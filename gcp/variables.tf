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
