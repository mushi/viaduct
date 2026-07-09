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
	metricsAddr    = "127.0.0.1:9110"
)

type metrics struct {
	total         prometheus.Counter
	success       prometheus.Gauge
	lastSuccess   prometheus.Gauge
	lastDuration  prometheus.Gauge
	durationHist  prometheus.Histogram
	statusCode    prometheus.Gauge
	connSecs      prometheus.Gauge
	firstByteSecs prometheus.Gauge
	failures      *prometheus.CounterVec
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		total: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "probe_attempts_total",
			Help: "Total number of probe attempts made.",
		}),
		success: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_success",
			Help: "1 if the last probe completed with the expected status, else 0.",
		}),
		lastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_last_success_timestamp_seconds",
			Help: "Unix timestamp (seconds) of the last successful probe.",
		}),
		lastDuration: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_duration_seconds",
			Help: "Total time for the last probe request.",
		}),
		durationHist: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "probe_request_duration_seconds", // distinct name — gauge keeps probe_duration_seconds
			Help:    "Histogram of successful probe request durations.",
			Buckets: []float64{0.015, 0.02, 0.025, 0.03, 0.035, 0.04, 0.045, 0.05, 0.06, 0.08, 0.1, 0.15, 0.25, 0.5, 1},
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
	reg.MustRegister(m.total, m.success, m.lastSuccess, m.lastDuration,
		m.durationHist, m.statusCode, m.connSecs, m.firstByteSecs, m.failures)

	for _, r := range []string{"socks_down", "timeout", "request", "bad_status", "build_request"} {
		m.failures.WithLabelValues(r) // creates the child at 0, exposed immediately
	}
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
	// nosemgrep: <use-tls> - loopback-only scrape, TLS buys nothing
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
		m.lastDuration.Set(time.Since(start).Seconds())
		m.fail("socks_down")
		log.Printf("probe: SOCKS %s unreachable: %v", socksAddr, err)
		return
	} else {
		_ = c.Close()
	}

	// nosemgrep: <http-customized-request> — intentional: canary rides inside the encrypted
	// Reality tunnel; empty 204 carries no sensitive data; plaintext avoids a
	// destination TLS handshake that would pollute the latency histogram.
	request, err := http.NewRequest(http.MethodGet, canaryURL, nil)
	if err != nil {
		m.lastDuration.Set(time.Since(start).Seconds())
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
	duration := time.Since(start).Seconds()
	m.lastDuration.Set(duration)
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
		m.durationHist.Observe(duration)
		m.lastSuccess.SetToCurrentTime()
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
		m.total.Inc()
		probe(client, m)
		<-ticker.C
	}
}
