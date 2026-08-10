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

variable "ops_ssh_key_path" {
  description = "Local path to the `ops` private key matching ops_ssh_public_key. Used only to build copy-pasteable `ssh -i ...` hints in the outputs; never uploaded."
  type        = string
  default     = "~/.ssh/viaduct_ops"
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

# Grafana Cloud + Cloudflare secrets are NOT Terraform variables: the Hetzner node
# fetches them from GCP Vault (kv/hetzner/grafana, kv/hetzner/cloudflare) at boot via its
# SPIRE SVID, into tmpfs (see scripts/fetch-hetzner-secrets.sh). Seed them once in Vault;
# see docs/RUNBOOK.md. This keeps them off disk and out of Terraform state.

# ── Binary checksums ──────────────────────────────────────────────────────────
# SHA-256 of each downloaded file, pinned per version.
# These must be updated whenever a *_version variable changes.
# Run scripts/get-checksums.sh to fetch the correct values for any version.
#
# Checksums pinned here are out-of-band from the download. This is trust-on-first-use:
# it catches a release or CDN compromised AFTER you ran get-checksums.sh (cloud-init
# aborts on mismatch), and get-checksums.sh cross-checks Xray/Grafana against their
# own signed digest files (.dgst / SHA256SUMS). It does NOT catch a release that was
# already malicious when pinned — that needs upstream provenance (SLSA / cosign).

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

# ── SPIRE agent (multi-cloud lab) ─────────────────────────────────────────────
# This node runs a SPIRE agent that attests (via join_token) to the SPIRE
# server on the GCP control plane (the `gcp/` root). Set enable_spire = true to
# turn it on; the server IP, instance name, and zone are read from the gcp/ root's
# remote state (see main.tf), not copied into tfvars. Deploy gcp/ first.

variable "enable_spire" {
  description = "Enable the SPIRE agent on this node. When true, the agent's server address and the provisioner's IAP target are sourced from the gcp/ root's remote state, so gcp/ must be applied first. When false, all SPIRE steps are skipped."
  type        = bool
  default     = false
}

variable "spire_agent_version" {
  description = "SPIRE release version for the agent binary (e.g. 1.15.1)."
  type        = string
  default     = "1.15.1"
}

variable "spire_agent_sha256" {
  description = "SHA-256 of spire-<version>-linux-amd64-musl.tar.gz for the pinned spire_agent_version."
  type        = string
  default     = ""
}

variable "gcp_ssh_key_path" {
  description = "Local path to the SSH private key matching the GCP instance-metadata key. gcloud reuses it for the IAP tunnel when the provisioner mints a join token (--ssh-key-file)."
  type        = string
  default     = "~/.ssh/viaduct_lab"
}

variable "gcp_ssh_user" {
  description = "SSH user on the GCP SPIRE server (the instance-metadata key user; gcloud reuses it over the IAP tunnel)."
  type        = string
  default     = "viaduct"
}

variable "gcp_project" {
  description = "GCP project ID for the IAP tunnel. Empty uses gcloud's active project."
  type        = string
  default     = ""
}

variable "trust_domain" {
  description = "SPIFFE trust domain of the GCP SPIRE server this agent joins."
  type        = string
  default     = "viaduct.gcp"
}

variable "wg_port" {
  description = "WireGuard hub UDP port on the GCP control plane (must match the GCP root's wg_port). This spoke dials the hub at GCP_SERVER_IP:wg_port."
  type        = number
  default     = 51820
}

variable "wg_mesh_ip" {
  description = "This node's fixed address on the 10.99.0.0/24 WireGuard mesh (hub is 10.99.0.1)."
  type        = string
  default     = "10.99.0.2"
}

variable "wg_hub_ip" {
  description = "The GCP control plane's fixed address on the WireGuard mesh. The SPIRE agent dials the server here (over wg0), so cross-node control-plane traffic rides the mesh rather than the public IP. Must match the GCP hub's mesh address."
  type        = string
  default     = "10.99.0.1"
}

# ── Xray geo data ─────────────────────────────────────────────────────────────
# Pinned by release tag AND digest. Both are needed: the previous code tracked
# "latest", which no fixed digest can describe.

variable "geoip_version" {
  description = "Pinned v2fly/geoip release tag providing geoip.dat."
  type        = string
  default     = "202608050239"
}

variable "geoip_sha256" {
  description = "SHA-256 of geoip.dat from the pinned v2fly/geoip release."
  type        = string
  default     = "c67bd077eb102cec74fab759b73d17f99275f56af10a87c14d9fd983508f5ce1"
}

variable "geosite_version" {
  description = "Pinned v2fly/domain-list-community release tag providing dlc.dat (installed as geosite.dat)."
  type        = string
  default     = "20260807145230"
}

variable "geosite_sha256" {
  description = "SHA-256 of dlc.dat from the pinned v2fly/domain-list-community release."
  type        = string
  default     = "c383bc2487049f2bd49a54806c178098b990b08d4b1716140f9f9c86e7f15c71"
}
