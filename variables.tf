variable "hcloud_token" {
  description = "Hetzner Cloud API token. Generate in the Hetzner Cloud Console under Security → API Tokens. Must have Read & Write permissions."
  type        = string
  sensitive   = true
}

variable "ssh_public_key" {
  description = "Your SSH public key (contents of ~/.ssh/id_ed25519.pub or similar). Used for admin access to the server."
  type        = string
}

variable "admin_cidr" {
  description = "List of CIDR ranges allowed to SSH into the server. Restrict this to your own IP(s) for security, e.g. [\"203.0.113.1/32\"]."
  type        = list(string)
  default     = ["0.0.0.0/0", "::/0"] # Open by default; override with your own IP
}

variable "location" {
  description = "Hetzner datacenter location. Options: nbg1 (Nuremberg), fsn1 (Falkenstein), hel1 (Helsinki), ash (Ashburn), sin (Singapore)."
  type        = string
  default     = "nbg1"
}

variable "conduit_version" {
  description = "Conduit CLI release tag to download from GitHub. Check https://github.com/Psiphon-Inc/conduit/releases for the latest."
  type        = string
  default     = "release-cli-2.0.0"
}

variable "conduit_bandwidth" {
  description = "Bandwidth limit per peer in Mbps. The CX23 has a 1 Gbit/s port; 40 Mbps leaves headroom for many simultaneous peers."
  type        = number
  default     = 40
}

variable "conduit_max_clients" {
  description = "Maximum number of concurrent Conduit clients (--max-common-clients). 100 is a reasonable default for a dedicated CX23."
  type        = number
  default     = 100
}
