variable "hcloud_token" {
  description = "Hetzner Cloud API token. Generate at: https://console.hetzner.cloud → Security → API Tokens. Needs Read + Write permissions."
  type        = string
  sensitive   = true
}

variable "ssh_public_key" {
  description = "SSH public key contents (e.g. contents of ~/.ssh/id_ed25519.pub). Registered with Hetzner and installed on the server."
  type        = string
}

variable "ssh_private_key_path" {
  description = "Local filesystem path to the private SSH key matching ssh_public_key. Used by the Terraform provisioner script (never uploaded to the server). E.g. ~/.ssh/id_ed25519"
  type        = string
}

variable "admin_cidr" {
  description = "List of CIDR ranges allowed inbound SSH. Restrict to your own IP for security, e.g. [\"203.0.113.1/32\"]. Defaults to open — override this."
  type        = list(string)
  default     = ["0.0.0.0/0", "::/0"]
}

variable "location" {
  description = "Hetzner datacenter location. Options: nbg1 (Nuremberg), fsn1 (Falkenstein), hel1 (Helsinki), ash (Ashburn), sin (Singapore)."
  type        = string
  default     = "nbg1"
}

# ── Conduit ───────────────────────────────────────────────────────────────────

variable "conduit_version" {
  description = "Conduit CLI release tag. Check https://github.com/Psiphon-Inc/conduit/releases for the latest."
  type        = string
  default     = "release-cli-2.0.0"
}

variable "conduit_bandwidth" {
  description = "Per-peer bandwidth cap in Mbps (--bandwidth flag). 40 Mbps leaves headroom for many concurrent peers on a CX23."
  type        = number
  default     = 40
}

variable "conduit_max_clients" {
  description = "Maximum concurrent Conduit peers (--max-common-clients). 100 is a reasonable default for a dedicated CX23."
  type        = number
  default     = 100
}

variable "conduit_cpu_quota" {
  description = "systemd CPUQuota for the Conduit service. 100% = one full vCPU. 60% on a 2-vCPU CX23 leaves the remainder for Xray and Alloy."
  type        = string
  default     = "60%"
}

# ── Xray ─────────────────────────────────────────────────────────────────────

variable "xray_version" {
  description = "Xray-core release tag. Check https://github.com/XTLS/Xray-core/releases for the latest."
  type        = string
  default     = "v26.4.25"
}

variable "vless_sni" {
  description = "Domain that Reality impersonates (SNI). Must support TLS 1.3. microsoft.com is a widely-recommended default."
  type        = string
  default     = "microsoft.com"
}

variable "vless_domain" {
  description = "Public domain name proxied through Cloudflare (e.g. example.com). Used for the VLESS+WebSocket+TLS inbound that Iranian users connect to. Must be pointed at this server via a proxied Cloudflare DNS A record."
  type        = string
}

variable "vless_users" {
  description = "List of VLESS user names. Each gets a unique UUID and a URI file at /etc/xray/clients/<name>.txt. Add/remove names and re-apply — no server rebuild required."
  type        = list(string)
  default     = ["user1"]

  validation {
    condition     = length(var.vless_users) > 0
    error_message = "vless_users must contain at least one entry."
  }

  validation {
    condition     = alltrue([for u in var.vless_users : can(regex("^[a-zA-Z0-9_-]+$", u))])
    error_message = "User names may only contain letters, numbers, hyphens, and underscores (used as filenames)."
  }
}

variable "xray_exporter_version" {
  description = "xray-exporter release tag (compassvpn fork). Check https://github.com/compassvpn/xray-exporter/releases."
  type        = string
  default     = "v0.2.0"
}

variable "xray_exporter_sha256" {
  description = "SHA-256 of xray-exporter-linux-amd64 for the pinned xray_exporter_version. This release publishes no checksums file, so it is pinned here. Run scripts/get-checksums.sh to obtain."
  type        = string
}

# ── Grafana / Alloy ───────────────────────────────────────────────────────────

variable "alloy_version" {
  description = "Grafana Alloy release tag. Check https://github.com/grafana/alloy/releases for the latest."
  type        = string
  default     = "v1.8.3"
}

variable "grafana_cloud_prometheus_url" {
  description = "Grafana Cloud Prometheus remote-write endpoint. Find it at grafana.com → your stack → Prometheus → Details. Format: https://prometheus-xxx.grafana.net/api/prom/push"
  type        = string
  sensitive   = true
}

variable "grafana_cloud_prometheus_user" {
  description = "Grafana Cloud Prometheus username (numeric, e.g. 1234567). Shown alongside the remote-write URL in the Grafana Cloud console."
  type        = string
  sensitive   = true
}

variable "grafana_cloud_api_key" {
  description = "Grafana Cloud API key with MetricsPublisher role. Generate at grafana.com → your org → Access Policies."
  type        = string
  sensitive   = true
}

variable "cloudflare_api_token" {
  description = "Cloudflare API token for certbot DNS-01 challenge. Create at dash.cloudflare.com → My Profile → API Tokens with Zone:DNS:Edit permission for the vless_domain zone."
  type        = string
  sensitive   = true
}

# ── Binary checksums ──────────────────────────────────────────────────────────
# SHA-256 of each downloaded file, pinned per version.
# These must be updated whenever a *_version variable changes.
# Run scripts/get-checksums.sh to fetch the correct values for any version.
#
# Having checksums here (out-of-band from the download source) means a
# compromised GitHub release cannot silently substitute a malicious binary —
# cloud-init will abort with a checksum mismatch before executing anything.

variable "conduit_sha256" {
  description = "SHA-256 of conduit-linux-amd64 for the pinned conduit_version. Run scripts/get-checksums.sh to obtain."
  type        = string
}

variable "xray_zip_sha256" {
  description = "SHA-256 of Xray-linux-64.zip for the pinned xray_version. Run scripts/get-checksums.sh to obtain."
  type        = string
}

variable "alloy_zip_sha256" {
  description = "SHA-256 of alloy-linux-amd64.zip for the pinned alloy_version. Run scripts/get-checksums.sh to obtain."
  type        = string
}
