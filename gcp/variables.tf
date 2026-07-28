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

variable "allow_stopping_for_update" {
  description = "Permit Terraform to stop and start the instance to apply changes that require it (machine_type, shielded/secure-boot config, service account). Default false so a stop is always a deliberate opt-in. The control-plane readiness gate confirms Vault and SPIRE come back after the restart."
  type        = bool
  default     = false
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

variable "ssh_private_key_path" {
  description = "Local path to the private key matching ssh_public_key. Used only by the control-plane readiness check to reach the instance over IAP (gcloud --ssh-key-file). Never uploaded to the instance."
  type        = string
  default     = "~/.ssh/viaduct_lab"
}

variable "agent_cidrs" {
  description = "CIDR(s) allowed to reach Vault (8200) and SPIRE server (8081): the AWS and Hetzner node IPs. Empty until known."
  type        = list(string)
  default     = []
}

variable "federation_cidrs" {
  description = "CIDR(s) allowed to reach the SPIRE federation bundle endpoint (8443): the AWS SPIRE server IP /32. Separate from agent_cidrs so federation does not also open Vault/8081. Empty disables the rule."
  type        = list(string)
  default     = []
}

variable "aws_spire_ip" {
  description = "AWS SPIRE server IP for cross-cloud federation (federates_with viaduct.aws). Empty omits the federation block from the generated SPIRE server config (standalone deploy)."
  type        = string
  default     = ""
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

variable "aws_certrole_approle_role_id" {
  description = "Vault AppRole role_id (non-secret) for refreshing the aws-vault-agent cert role after an AWS rebuild. Scoped to update only auth/cert/certs/aws-vault-agent. The secret_id is placed out-of-band in /opt/vault-certrole/secret-id (0600). Empty until the AppRole is created in BOOTSTRAP."
  type        = string
  default     = ""
}

# ── WireGuard private mesh (this node is the hub) ─────────────────────────────

variable "wg_port" {
  description = "WireGuard hub UDP listen port on the GCP node (the single public mesh port)."
  type        = number
  default     = 51820
}

variable "wg_ingress_cidrs" {
  description = "IPv4 CIDRs allowed to reach the WireGuard hub port. Default open: WireGuard silently drops any non-peer packet, so the crypto is the real gate. Tighten to the spoke public IPs (Hetzner /32, AWS EIP /32, your laptop /32) if you want an extra IP filter, accepting the IP-churn maintenance. IPv4 only: the hub endpoint is IPv4, and a GCP firewall rule cannot mix v4 and v6 source ranges."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}
