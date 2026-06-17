variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "region" {
  description = "GCP region. Free-tier e2-micro is limited to us-west1, us-central1, us-east1."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone."
  type        = string
  default     = "us-central1-a"
}

variable "instance_name" {
  description = "Control-plane instance name (Vault + SPIRE server)."
  type        = string
  default     = "viaduct-controlplane"
}

variable "machine_type" {
  description = "Instance machine type. e2-micro is free-tier eligible (compute only; external IPv4 is billed)."
  type        = string
  default     = "e2-micro"
}

variable "boot_image" {
  description = "Boot disk image (project/family shorthand)."
  type        = string
  default     = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
}

variable "ssh_user" {
  description = "Admin username created via instance SSH-key metadata."
  type        = string
  default     = "viaduct"
}

variable "ssh_public_key" {
  description = "SSH public key content for admin access."
  type        = string
}

variable "admin_cidr" {
  description = "CIDR(s) allowed to SSH (port 22). Restrict to your own IP /32."
  type        = list(string)
}

variable "agent_cidrs" {
  description = "CIDR(s) allowed to reach Vault (8200) and SPIRE server (8081): the AWS and Hetzner node IPs. Empty until known."
  type        = list(string)
  default     = []
}

variable "snapshot_bucket_name" {
  description = "Globally-unique name for the Vault Raft snapshot bucket."
  type        = string
}

variable "vault_version" {
  description = "Vault apt package version to pin and hold (e.g. \"1.18.5-1\"). Verify the available version with `apt-cache madison vault` after adding the HashiCorp repo, or check HashiCorp releases."
  type        = string
}

variable "spire_version" {
  description = "SPIRE release version, e.g. \"1.15.1\" (downloads the linux-amd64-musl tarball; musl builds are static and run on Ubuntu)."
  type        = string
}

variable "spire_sha256" {
  description = "SHA-256 of spire-<version>-linux-amd64-musl.tar.gz, from the GitHub release."
  type        = string
}

variable "spire_approle_role_id" {
  description = "Vault AppRole role_id for the SPIRE server (non-secret). The secret_id is placed out-of-band in a 0600 EnvironmentFile on the node."
  type        = string
}

variable "trust_domain" {
  description = "SPIFFE trust domain for this SPIRE server."
  type        = string
  default     = "viaduct.gcp"
}

variable "snapshot_approle_role_id" {
  description = "Vault AppRole role_id for the weekly snapshot job (non-secret). The secret_id is placed out-of-band in /opt/vault-snapshot/secret-id (0600) on the node."
  type        = string
}
