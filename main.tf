terraform {
  required_version = ">= 1.3"

  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.49"
    }
  }
}

provider "hcloud" {
  token = var.hcloud_token
}

# ── SSH key ──────────────────────────────────────────────────────────────────

resource "hcloud_ssh_key" "conduit" {
  name       = "conduit-key"
  public_key = var.ssh_public_key
}

# ── Firewall ─────────────────────────────────────────────────────────────────
# Conduit uses outbound STUN/TURN and WebRTC — it does not require any inbound
# ports beyond SSH for administration. All Conduit traffic is initiated
# outbound by the node itself.

resource "hcloud_firewall" "conduit" {
  name = "conduit-firewall"

  # Allow inbound SSH from your admin IP only (set var.admin_cidr)
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = var.admin_cidr
  }

  # Allow all outbound traffic (Conduit connects out to Psiphon brokers)
  rule {
    direction       = "out"
    protocol        = "tcp"
    port            = "any"
    destination_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction       = "out"
    protocol        = "udp"
    port            = "any"
    destination_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction       = "out"
    protocol        = "icmp"
    destination_ips = ["0.0.0.0/0", "::/0"]
  }
}

# ── Server ───────────────────────────────────────────────────────────────────

resource "hcloud_server" "conduit" {
  name        = "conduit-station"
  server_type = "cx23"           # 2 vCPU, 4 GB RAM, 40 GB NVMe
  image       = "ubuntu-24.04"
  location    = var.location
  ssh_keys    = [hcloud_ssh_key.conduit.id]

  firewall_ids = [hcloud_firewall.conduit.id]

  # cloud-init user data installs Conduit and sets up the systemd service
  user_data = templatefile("${path.module}/cloud-init.yaml.tpl", {
    conduit_version      = var.conduit_version
    conduit_bandwidth    = var.conduit_bandwidth
    conduit_max_clients  = var.conduit_max_clients
  })

  labels = {
    role = "conduit"
  }
}
