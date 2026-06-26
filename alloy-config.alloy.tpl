// Rendered by Terraform from grafana_cloud_* variables and written to
// backups/alloy-config.alloy, then uploaded to /etc/alloy/config.alloy
// by the provisioner. Credentials never touch user_data / cloud-init.

// ── Scrape: Conduit metrics ───────────────────────────────────────────────
// Conduit exposes Prometheus metrics on 127.0.0.1:9090/metrics when started
// with --metrics-addr 127.0.0.1:9090 (set in the systemd unit).

prometheus.scrape "conduit" {
  targets = [{ "__address__" = "127.0.0.1:9090" }]
  forward_to = [prometheus.remote_write.grafana_cloud.receiver]
  job_name   = "conduit"
  scrape_interval = "30s"
}

// ── Scrape: Xray metrics via xray-exporter ────────────────────────────────
// xray-exporter listens on 127.0.0.1:9091 and exposes per-user traffic
// stats (uplink/downlink bytes), inbound stats, and runtime metrics.

prometheus.scrape "xray" {
  targets = [{ "__address__" = "127.0.0.1:9091" }]
  forward_to = [prometheus.remote_write.grafana_cloud.receiver]
  job_name   = "xray"
  scrape_interval = "30s"
  metrics_path   = "/scrape"
}

// ── Scrape: per-user traffic stats ───────────────────────────────────────
// xray-user-stats queries the xray Stats gRPC API directly and exposes
// cumulative per-user uplink/downlink bytes. xray-exporter intentionally
// omits user stats for cardinality reasons; this fills that gap.

prometheus.scrape "xray_user_stats" {
  targets = [{ "__address__" = "127.0.0.1:9092" }]
  forward_to = [prometheus.remote_write.grafana_cloud.receiver]
  job_name   = "xray_user_stats"
  scrape_interval = "30s"
}

// ── Scrape: node (system) metrics ─────────────────────────────────────────
// Alloy has a built-in node_exporter equivalent. Gives CPU, memory,
// network I/O, and disk — useful for correlating traffic with system load.

prometheus.exporter.unix "node" {}

prometheus.scrape "node" {
  targets    = prometheus.exporter.unix.node.targets
  forward_to = [prometheus.remote_write.grafana_cloud.receiver]
  job_name   = "node"
  scrape_interval = "60s"
}

// ── Remote write: Grafana Cloud ───────────────────────────────────────────

prometheus.remote_write "grafana_cloud" {
  // tag every series from this node so multi-node dashboards can break down by node
  external_labels = { node = "hetzner" }

  endpoint {
    url = "${grafana_cloud_url}"

    basic_auth {
      username = "${grafana_cloud_user}"
      password = "${grafana_cloud_password}"
    }

    queue_config {
      // Buffer up to 2 hours of metrics if Grafana Cloud is temporarily
      // unreachable. Capacity = (120 min * 60 s/min) / 30 s/scrape * ~20 series
      capacity           = 5000
      max_samples_per_send = 500
    }
  }
}
