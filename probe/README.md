# Xray Probe

This simple probe relies on an xray client running with a SOCKS5 inbound and a VLESS/Reality outbound
(to the server's public IP and Reality port (443)). The client is just the xray binary that is already deployed to the 
host, run via a systemd unit, and using configuration generated from a real, provisioned "probe" vless user's URI.
The probe dials the local SOCKS5 port every 60s, requests "http://cp.cloudflare.com/generate_204" and collects and 
serves `/metrics`.

Both the xray client and the probe run as unprivileged users.

### Metrics

| Name | Help                                                            | 
|------|-----------------------------------------------------------------|
`probe_attempts_total` | Total number of probe attempts made. |
`probe_success` | 1 if the last probe completed with the expected status, else 0. |
`probe_last_success_timestamp_seconds` | Unix timestamp (seconds) of the last successful probe. |
`probe_duration_seconds` | Total time for the last probe request.                          |
`probe_request_duration_seconds` | Histogram of successful probe request durations.                          |
`probe_http_status_code` | HTTP status of the last probe (want 204; 0 = no response).      |
`probe_http_connect_seconds` | Request start to connection ready (SOCKS dial + Reality tunnel). |
`probe_http_ttfb_seconds` | Request start to first response byte (full round trip). |
`probe_failures_total` | Probe failures by reason. |

### Use

`go run .` - run locally standalone and confirm a SOCKS unreachable error is emitted every 60s

`terraform apply` - this will provision the SOCKS5 systemd service dependency and the probe systemd unit,
compile and deploy the code, and start the services, scrape metrics and forward to the
configured grafana cloud account.