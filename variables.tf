variable "hcloud_token" {
  description = "Hetzner Cloud API token. Generate at: https://console.hetzner.cloud → Security → API Tokens. Needs Read + Write permissions."
  type        = string
  sensitive   = true
}

variable "ssh_public_key" {
  description = "SSH public key for the automation `deploy` user, used by the Terraform provisioner (e.g. contents of ~/.ssh/id_ed25519.pub). Registered with Hetzner and installed on the server."
  type        = string
}

variable "ssh_private_key_path" {
  description = "Local filesystem path to the private SSH key matching ssh_public_key. Used by the Terraform provisioner script (never uploaded to the server). E.g. ~/.ssh/id_ed25519"
  type        = string
}

variable "ops_ssh_public_key" {
  description = "SSH public key for the interactive `ops` admin user — a separate identity from the automation `deploy` key. Generate a dedicated keypair (e.g. `ssh-keygen -t ed25519 -f ~/.ssh/viaduct_ops`), put the .pub contents here, and keep the private key for `ssh ops@<ip>`."
  type        = string
}

variable "admin_cidr" {
  description = "List of CIDR ranges allowed inbound SSH. No default — you must supply your own IP /32 (fail closed), e.g. [\"203.0.113.1/32\"]. Set in terraform.tfvars or via TF_VAR_admin_cidr."
  type        = list(string)
}

variable "location" {
  description = "Hetzner datacenter location. Options: nbg1 (Nuremberg), fsn1 (Falkenstein), hel1 (Helsinki), ash (Ashburn), sin (Singapore)."
  type        = string
  default     = "nbg1"
}

# ── Conduit ───────────────────────────────────────────────────────────────────

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

variable "vless_sni" {
  description = "Domain that Reality impersonates (SNI). Must support TLS 1.3. microsoft.com is a widely-recommended default."
  type        = string
  default     = "microsoft.com"
}

variable "vless_domain" {
  description = "Public domain name for the VLESS+XHTTP+TLS inbound on port 8443 (e.g. example.com). Must be a DNS-only (grey cloud) Cloudflare A record pointing at this server; the zone's DNS is also used for the certbot DNS-01 challenge."
  type        = string

  # The provisioner passes it to certbot on a remote command line.
  validation {
    condition     = can(regex("^(?i)([a-z0-9]([a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,63}$", var.vless_domain))
    error_message = "vless_domain must be a plain hostname such as example.com."
  }
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

# ── Grafana / Alloy ───────────────────────────────────────────────────────────

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

  # Written as one line of certbot's credentials file; whitespace would split it.
  validation {
    condition     = can(regex("^\\S+$", var.cloudflare_api_token))
    error_message = "cloudflare_api_token must be a single token with no spaces or line breaks."
  }
}
