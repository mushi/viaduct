terraform {
  required_version = ">= 1.4" # terraform_data (built-in) replaces the null provider

  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.49"
    }
    cloudinit = {
      source  = "hashicorp/cloudinit"
      version = "~> 2.3"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
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

# ── GCP control-plane coordinates (multi-cloud lab) ───────────────────────────
# When SPIRE is enabled, the agent's server address and the provisioner's IAP
# target (instance + zone) are read straight from the gcp/ root's state, so they
# are never hand-copied into tfvars and cannot drift. Apply gcp/ first; if its
# state is absent this read fails loudly rather than silently disabling SPIRE.
data "terraform_remote_state" "gcp" {
  count   = var.enable_spire ? 1 : 0
  backend = "local"
  config  = { path = "${path.module}/gcp/terraform.tfstate" }
}

locals {
  spire_server_ip = var.enable_spire ? data.terraform_remote_state.gcp[0].outputs.instance_external_ip : ""
  spire_instance  = var.enable_spire ? data.terraform_remote_state.gcp[0].outputs.instance_name : ""
  spire_zone      = var.enable_spire ? data.terraform_remote_state.gcp[0].outputs.zone : ""
}

# ── cloud-init (gzip-compressed) ──────────────────────────────────────────────
# The rendered cloud-config exceeds Hetzner's 32 KiB user_data limit, so we
# gzip it. Hetzner only accepts UTF-8 user_data, so gzip must be base64-wrapped
# (the cloudinit provider forces base64_encode=true whenever gzip=true). The box
# base64-decodes and gunzips it automatically at first boot.

data "cloudinit_config" "conduit" {
  gzip          = true
  base64_encode = true

  part {
    content_type = "text/cloud-config"
    content = templatefile("${path.module}/cloud-init.yaml.tpl", {
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
      xray_exporter_sha256  = var.xray_exporter_sha256
      alloy_version         = var.alloy_version
      alloy_zip_sha256      = var.alloy_zip_sha256
      spire_agent_version   = var.spire_agent_version
      spire_agent_sha256    = var.spire_agent_sha256
      spire_server_address  = var.wg_hub_ip
      trust_domain          = var.trust_domain
      ssh_public_key        = var.ssh_public_key
      ops_ssh_public_key    = var.ops_ssh_public_key
    })
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
  #
  # cloud-init is gzip+base64-compressed (see data.cloudinit_config.conduit
  # above) because the rendered YAML exceeds Hetzner's 32 KiB user_data limit.
  user_data = data.cloudinit_config.conduit.rendered

  labels = { role = "conduit-station" }

  # user_data (cloud-init) runs only at first boot; ongoing config is delivered by
  # the provisioner, so user_data drift must NOT rebuild the live station
  # Apply a cloud-init change deliberately with `-replace` when you truly intend a rebuild.
  lifecycle {
    ignore_changes = [user_data]
  }
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
  content = templatefile("${path.module}/alloy-config.alloy.tpl", {
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

resource "terraform_data" "provision" {
  triggers_replace = {
    server_id  = hcloud_server.conduit.id
    users_hash = sha256(local_file.users_txt.content)
    alloy_hash = sha256(local_file.alloy_config.content)
    # Re-provision (rebuild + redeploy the probe) when any file under probe/
    # changes. Covers *.go, go.mod, go.sum; also README, so a docs-only edit
    # triggers a (harmless) re-provision. Narrow the glob to "**/*.go" plus
    # go.mod/go.sum if you want to avoid that.
    probe_hash = sha256(join("", [for f in fileset("${path.module}/probe", "**") : filesha256("${path.module}/probe/${f}")]))
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
      PROBE_SRC    = "${path.module}/probe"

      # SPIRE agent: provisioner fetches the trust bundle + a join token from
      # the GCP SPIRE server. GCP must be deployed (SPIRE server running) first.
      GCP_SERVER_IP    = local.spire_server_ip
      GCP_SSH_KEY_PATH = var.gcp_ssh_key_path
      GCP_SSH_USER     = var.gcp_ssh_user
      GCP_INSTANCE     = local.spire_instance
      GCP_ZONE         = local.spire_zone
      GCP_PROJECT      = var.gcp_project
      TRUST_DOMAIN     = var.trust_domain

      # WireGuard mesh: this node registers with the GCP hub over IAP and dials
      # it at GCP_SERVER_IP:WG_PORT. WG_MESH_IP is this spoke's fixed mesh address.
      WG_PORT    = tostring(var.wg_port)
      WG_MESH_IP = var.wg_mesh_ip
    }
  }

  depends_on = [hcloud_server.conduit]

  lifecycle {
    precondition {
      condition     = !var.enable_spire || local.spire_server_ip != ""
      error_message = "enable_spire is true but no GCP SPIRE server IP was found. Apply the gcp/ root first; its state supplies the IP, instance name, and zone."
    }
  }
}
