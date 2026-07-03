// Command probe measures availability and latency of the VLESS/Reality path by
// making a periodic HTTP request through the local xray client's SOCKS proxy and
// exposing the result as Prometheus metrics on :9110/metrics.
package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/net/proxy"
)

const (
	canaryURL      = "http://cp.cloudflare.com/generate_204"
	expectedStatus = http.StatusNoContent // 204
	canaryInterval = 60 * time.Second
	requestTimeout = 15 * time.Second
	socksAddr      = "127.0.0.1:10808"
	metricsAddr    = ":9110"
)

type metrics struct {
	success       prometheus.Gauge
	duration      prometheus.Gauge
	statusCode    prometheus.Gauge
	connSecs      prometheus.Gauge
	firstByteSecs prometheus.Gauge
	failures      *prometheus.CounterVec
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		success: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_success",
			Help: "1 if the last probe completed with the expected status, else 0.",
		}),
		duration: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_duration_seconds",
			Help: "Total time for the last probe request.",
		}),
		statusCode: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_http_status_code",
			Help: fmt.Sprintf("HTTP status of the last probe (want %d; 0 = no response).", expectedStatus),
		}),
		connSecs: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_http_connect_seconds",
			Help: "Request start to connection ready (SOCKS dial + Reality tunnel).",
		}),
		firstByteSecs: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_http_ttfb_seconds",
			Help: "Request start to first response byte (full round trip).",
		}),
		failures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "probe_failures_total",
			Help: "Probe failures by reason.",
		}, []string{"reason"}),
	}
	reg.MustRegister(m.success, m.duration, m.statusCode, m.connSecs, m.firstByteSecs, m.failures)
	return m
}

// fail records a failed probe: success=0, no HTTP status, and the phase timings
// blanked to NaN (a gap on the graph rather than a stale value), then counts the
// reason. duration is set by the caller (time until the failure).
func (m *metrics) fail(reason string) {
	m.success.Set(0)
	m.statusCode.Set(0)
	m.connSecs.Set(math.NaN())
	m.firstByteSecs.Set(math.NaN())
	m.failures.WithLabelValues(reason).Inc()
}

func serveMetrics(gatherer prometheus.Gatherer) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{}))
	log.Fatal(http.ListenAndServe(metricsAddr, mux))
}

func newClient() (*http.Client, error) {
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	ctxDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("socks dialer does not implement ContextDialer")
	}
	return &http.Client{
		Timeout: requestTimeout, // bounds the whole request: dial + headers + body
		Transport: &http.Transport{
			DialContext:           ctxDialer.DialContext,
			MaxIdleConns:          2,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}, nil
}

// classify maps a request error to a stable, low-cardinality reason label.
func classify(err error) string {
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		return "timeout"
	}
	return "request"
}

func probe(client *http.Client, m *metrics) {
	start := time.Now()

	if c, err := net.DialTimeout("tcp", socksAddr, 2*time.Second); err != nil {
		m.duration.Set(time.Since(start).Seconds())
		m.fail("socks_down")
		log.Printf("probe: SOCKS %s unreachable: %v", socksAddr, err)
		return
	} else {
		_ = c.Close()
	}

	request, err := http.NewRequest(http.MethodGet, canaryURL, nil)
	if err != nil {
		m.duration.Set(time.Since(start).Seconds())
		m.fail("build_request")
		log.Printf("probe: build request: %v", err)
		return
	}
	trace := &httptrace.ClientTrace{
		GotConn:              func(httptrace.GotConnInfo) { m.connSecs.Set(time.Since(start).Seconds()) },
		GotFirstResponseByte: func() { m.firstByteSecs.Set(time.Since(start).Seconds()) },
	}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))

	response, err := client.Do(request)
	m.duration.Set(time.Since(start).Seconds())
	if err != nil {
		m.fail(classify(err))
		log.Printf("probe: request failed: %v", err)
		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}()

	m.statusCode.Set(float64(response.StatusCode))
	if response.StatusCode == expectedStatus {
		m.success.Set(1)
	} else {
		m.success.Set(0)
		m.failures.WithLabelValues("bad_status").Inc()
	}
}

func main() {
	registry := prometheus.NewRegistry()
	register := prometheus.WrapRegistererWith(
		prometheus.Labels{"service": "vless", "path": "reality"}, registry)

	m := newMetrics(register)
	go serveMetrics(registry)

	client, err := newClient()
	if err != nil {
		log.Fatalf("building client: %v", err)
	}

	ticker := time.NewTicker(canaryInterval)
	defer ticker.Stop()
	for {
		probe(client, m)
		<-ticker.C
	}
}
