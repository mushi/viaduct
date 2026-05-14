terraform {
  required_version = ">= 1.3"

  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.49"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}

provider "hcloud" {
  token = var.hcloud_token
}

# ── SSH key ───────────────────────────────────────────────────────────────────

resource "hcloud_ssh_key" "conduit" {
  name       = "conduit-key"
  public_key = var.ssh_public_key
}

# ── Firewall ──────────────────────────────────────────────────────────────────

resource "hcloud_firewall" "conduit" {
  name = "conduit-station-firewall"

  # SSH: restrict to your own IP via admin_cidr
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = var.admin_cidr
  }

  # Port 80: nginx static website. Defeats active probing (DPI sends HTTP GET
  # to suspected proxy IPs; a real page here looks like a legitimate server).
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "80"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  # Port 443: xray Reality inbound (direct connections). xray handles TLS
  # impersonation of vless_sni; no nginx involved on this port.
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "443"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  # Port 8443: nginx terminates TLS (Let's Encrypt cert) and proxies XHTTP
  # traffic to xray XHTTP inbound on localhost:10000. Use from Iran.
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "8443"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  # All outbound: Conduit connects out to Psiphon brokers; Xray connects out
  # on behalf of VLESS clients; Grafana Alloy remote-writes to Grafana Cloud.
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

# ── Server ────────────────────────────────────────────────────────────────────

resource "hcloud_server" "conduit" {
  name         = "conduit-station"
  server_type  = "cx23"
  image        = "ubuntu-24.04"
  location     = var.location
  ssh_keys     = [hcloud_ssh_key.conduit.id]
  firewall_ids = [hcloud_firewall.conduit.id]

  # vless_users is intentionally NOT in user_data.
  # It is managed via users.txt uploaded by the provisioner, so that adding
  # or removing users never forces a server rebuild.
  user_data = templatefile("${path.module}/cloud-init.yaml.tpl", {
    conduit_version       = var.conduit_version
    conduit_bandwidth     = var.conduit_bandwidth
    conduit_max_clients   = var.conduit_max_clients
    conduit_cpu_quota     = var.conduit_cpu_quota
    conduit_sha256        = var.conduit_sha256
    xray_version          = var.xray_version
    xray_zip_sha256       = var.xray_zip_sha256
    vless_sni             = var.vless_sni
    vless_domain          = var.vless_domain
    cloudflare_api_token  = var.cloudflare_api_token
    xray_exporter_version = var.xray_exporter_version
    alloy_version         = var.alloy_version
    alloy_zip_sha256      = var.alloy_zip_sha256
  })

  labels = { role = "conduit-station" }
}

# ── users.txt (local file, uploaded by provisioner) ───────────────────────────
# Generated from vless_users. Changing vless_users updates this file, which
# changes the users_hash trigger, causing the provisioner to re-run.

resource "local_file" "users_txt" {
  filename        = "${path.module}/backups/users.txt"
  content         = "${join("\n", var.vless_users)}\n"
  file_permission = "0600"
}

# ── alloy-config.yaml (local file, uploaded by provisioner) ──────────────────
# Grafana Alloy scrape + remote-write config. Generated here so the
# Grafana Cloud credentials stay in terraform.tfvars and are never
# baked into cloud-init / user_data.

resource "local_file" "alloy_config" {
  filename        = "${path.module}/backups/alloy-config.alloy"
  file_permission = "0600"
  content         = templatefile("${path.module}/alloy-config.alloy.tpl", {
    grafana_cloud_url      = var.grafana_cloud_prometheus_url
    grafana_cloud_user     = var.grafana_cloud_prometheus_user
    grafana_cloud_password = var.grafana_cloud_api_key
  })
}

# ── Provisioner ───────────────────────────────────────────────────────────────
# Runs on every apply where a trigger value changes:
#   server_id    — always re-runs after a server rebuild
#   users_hash   — re-runs when vless_users changes
#   alloy_hash   — re-runs when Grafana Cloud credentials change
#
# The script (scripts/provision.sh):
#   1. Waits for cloud-init to signal completion
#   2. Uploads backup files (conduit_key.json, keypair.env, *.uuid)
#   3. Uploads users.txt and alloy-config.alloy
#   4. Runs xray-setup.sh --regen
#   5. Installs the Alloy config and restarts Alloy
#   6. Starts / restarts conduit and xray
#   7. Downloads fresh backups locally

resource "null_resource" "provision" {
  triggers = {
    server_id  = hcloud_server.conduit.id
    users_hash = sha256(local_file.users_txt.content)
    alloy_hash = sha256(local_file.alloy_config.content)
  }

  provisioner "local-exec" {
    command     = "${path.module}/scripts/provision.sh"
    interpreter = ["/usr/bin/env", "bash"]
    environment = {
      SERVER_IP    = hcloud_server.conduit.ipv4_address
      SSH_KEY_PATH = var.ssh_private_key_path
      BACKUPS_DIR  = "${path.module}/backups"
      USERS_FILE   = local_file.users_txt.filename
      ALLOY_CONFIG = local_file.alloy_config.filename
    }
  }

  depends_on = [hcloud_server.conduit]
}
