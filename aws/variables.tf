variable "region" {
  description = "AWS region - t4g free-trial eligible."
  type        = string
  default     = "ap-south-1"
}

variable "vpc_cidr" {
  description = "CIDR for the dedicated VPC."
  type        = string
  default     = "10.20.0.0/24"
}

variable "instance_name" {
  description = "Name tag for the AWS node (SPIRE server + k3s + capped Conduit)."
  type        = string
  default     = "viaduct-aws-node"
}

variable "instance_type" {
  description = "EC2 instance type. t4g.small (ARM64/Graviton) is free-trial eligible through 2026-12-31."
  type        = string
  default     = "t4g.small"
}

variable "root_volume_gb" {
  description = "Root EBS volume size (GiB)."
  type        = number
  default     = 30
}


# ─── Federation (cross-cloud trust with viaduct.gcp) ─────────────────────────
variable "bundle_endpoint_port" {
  description = "HTTPS port for this server's SPIRE federation bundle endpoint, fetched by the GCP SPIRE server."
  type        = number
  default     = 8443
}

variable "trust_domain" {
  description = "SPIFFE trust domain for the AWS SPIRE server."
  type        = string
  default     = "viaduct.aws"
}

# ─── SPIRE server (consumed in Phase A2) ─────────────────────────────────────
variable "spire_version" {
  description = "SPIRE release version. Downloads the linux-arm64-musl tarball for Graviton (static; runs on Ubuntu)."
  type        = string
  default     = "1.15.1"
}

variable "spire_sha256" {
  description = "SHA-256 of spire-<version>-linux-arm64-musl.tar.gz (NOTE: arm64, not amd64)."
  type        = string
  default     = ""
}

# ─── Cross-cloud federation / provisioning (consumed by startup.sh.tpl) ────────
variable "gcp_control_plane_ip" {
  description = "GCP control-plane IP (Vault :8200 + SPIRE federation bundle endpoint :8443). Deploy gcp/ first to obtain it."
  type        = string
  default     = ""
}

# ── GCP access for federation bundle sync (over IAP) ──────────────────────────
# Used only by the federation-sync terraform_data to push this node's trust bundle
# to the GCP SPIRE server after a rebuild. Instance name + zone come from the gcp/
# root's remote state; these are the local key and user for the IAP tunnel.

variable "gcp_ssh_user" {
  description = "SSH user on the GCP control-plane instance (its metadata key user); gcloud reuses it over the IAP tunnel."
  type        = string
  default     = "viaduct"
}

variable "gcp_ssh_key_path" {
  description = "Local path to the private key matching the GCP instance-metadata key. Used only by the federation bundle sync to reach GCP over IAP. Never uploaded."
  type        = string
  default     = "~/.ssh/viaduct_lab"
}

variable "gcp_project" {
  description = "GCP project ID for the IAP tunnel. Empty uses gcloud's active project."
  type        = string
  default     = ""
}

# ── WireGuard mesh (this node is a spoke; the GCP control plane is the hub) ────

variable "wg_port" {
  description = "WireGuard hub UDP port on the GCP control plane (must match the GCP root's wg_port). This spoke dials the hub at gcp_control_plane_ip:wg_port."
  type        = number
  default     = 51820
}

variable "wg_mesh_ip" {
  description = "This node's fixed address on the 10.99.0.0/24 WireGuard mesh (hub is 10.99.0.1, Hetzner 10.99.0.2)."
  type        = string
  default     = "10.99.0.3"
}

variable "wg_hub_ip" {
  description = "The GCP control plane's fixed address on the WireGuard mesh. Cross-cloud control-plane traffic (SPIRE federation :8443, Vault :8200, Alloy) dials the hub here over wg0 rather than the public IP. The WG endpoint itself still dials gcp_control_plane_ip:wg_port (you cannot bootstrap the mesh over the mesh). Must match the GCP hub's mesh address."
  type        = string
  default     = "10.99.0.1"
}

variable "wg_psk_parameter" {
  description = "SSM Parameter Store name used to relay this spoke's WireGuard PSK from the provisioner to the box (SecureString; written then deleted per apply). Must begin with '/'."
  type        = string
  default     = "/viaduct/wg/aws-psk"
}

variable "gcp_trust_domain" {
  description = "Peer SPIFFE trust domain to federate with (the GCP control plane)."
  type        = string
  default     = "viaduct.gcp"
}

variable "k3s_version" {
  description = "Pinned k3s version (INSTALL_K3S_VERSION), e.g. v1.35.5+k3s1."
  type        = string
  default     = "v1.35.5+k3s1"
}

variable "k3s_installer_sha256" {
  description = <<-EOT
    SHA-256 of the https://get.k3s.io installer script, verified before it is
    executed as root. Upstream edits this script independently of k3s releases,
    so a boot that fails on a mismatch is the intended behaviour: re-run
    scripts/get-checksums.sh, read the diff, then update the pin.
  EOT
  type        = string
  default     = "ed01f89fd977bf20ac1516bbebf8370bf3ddbaa55dac8aba610956a4c78cc00b"
}

variable "awscli_version" {
  description = "Pinned aws-cli v2 version. The unversioned zip URL moves, so no digest can describe it."
  type        = string
  default     = "2.36.19"
}

variable "awscli_zip_sha256" {
  description = "SHA-256 of awscli-exe-linux-aarch64-<awscli_version>.zip, verified before it is unpacked and run as root."
  type        = string
  default     = "fb7a8cfd2a516a6b15560582fdc98c417fedffd39728d46fb6007b56b7c858d3"
}
