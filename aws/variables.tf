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

variable "ssh_user" {
  description = "Default login user baked into the Ubuntu AMI (ssh ubuntu@<eip>)."
  type        = string
  default     = "ubuntu"
}

variable "ssh_public_key" {
  description = "SSH public key content (not a path); registered as an EC2 key pair."
  type        = string
}

variable "admin_cidr" {
  description = "CIDR(s) allowed to SSH (port 22). Restrict to your own IP /32."
  type        = list(string)
}

# ─── Federation (cross-cloud trust with viaduct.gcp) ─────────────────────────
variable "bundle_endpoint_port" {
  description = "HTTPS port for this server's SPIRE federation bundle endpoint, fetched by the GCP SPIRE server."
  type        = number
  default     = 8443
}

variable "federation_cidrs" {
  description = "CIDR(s) allowed to reach the federation bundle endpoint: the GCP SPIRE server's IP /32. Empty disables the rule until known."
  type        = list(string)
  default     = []
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

variable "gcp_vault_fingerprint" {
  description = "SHA-256 fingerprint of GCP Vault's self-signed listener cert (colon-hex, e.g. AA:BB:...), pinned to verify the TOFU-fetched vault.crt. From: openssl x509 -in /opt/vault/tls/vault.crt -noout -fingerprint -sha256 on the GCP box."
  type        = string
  default     = ""
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
