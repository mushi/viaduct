# Viaduct — Conduit + VLESS Station on Hetzner Cloud (Terraform)

Deploys a Hetzner CX23 server (~€4/month) running:

| Service | Purpose |
|---|---|
| **Conduit** | Psiphon inproxy relay — censorship circumvention for users in restricted regions |
| **Xray** | VLESS + Reality proxy — personal proxy, v2ray-compatible |
| **xray-exporter** | Prometheus exporter for Xray per-user traffic stats |
| **Grafana Alloy** | Metrics agent — scrapes Conduit + Xray locally, remote-writes to Grafana Cloud |

All services run as unprivileged users under systemd. No extra ports beyond 22 and 443 are opened. Metrics are pushed outbound to Grafana Cloud — no inbound scrape port needed.

## Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/install) ≥ 1.3
- A [Hetzner Cloud](https://www.hetzner.com/cloud/) account
- A [Grafana Cloud](https://grafana.com/auth/sign-up) account (free tier is sufficient)
- An SSH key pair on your local machine

## First-time setup

### 1. Grafana Cloud

1. Sign up at grafana.com → create a stack
2. Navigate to your stack → **Prometheus** → **Details**
3. Note the **Remote Write Endpoint** URL and **Username**
4. Go to your org → **Access Policies** → create a token with the **MetricsPublisher** role
5. Import the Grafana dashboards (see [Dashboards](#dashboards) below)

### 2. Terraform

```sh
cp terraform.tfvars.example terraform.tfvars
# Fill in: hcloud_token, ssh keys, vless_users, grafana_cloud_* values

terraform init
terraform plan
terraform apply
```

After `apply`, the provisioner:
1. Waits for cloud-init to finish
2. Uploads any backup files (preserving identity/reputation/UUIDs)
3. Uploads `users.txt` and `alloy-config.alloy` (with Grafana credentials)
4. Runs `xray-setup.sh --regen`
5. Starts all four services
6. Downloads fresh backups to `backups/`

VLESS client URIs are saved locally to `backups/clients/<name>.txt`.

## Dashboards

| Dashboard | Source |
|---|---|
| **VLESS+Reality** | `dashboards/vless-xray-dashboard.json` (this repo) |
| **Conduit** | https://github.com/shayanb/MoaV/blob/main/configs/monitoring/grafana/provisioning/dashboards/conduit.json |
| **Node (system)** | Grafana dashboard ID **1860** (Node Exporter Full) — import by ID |

To import the VLESS dashboard: Grafana → Dashboards → New → Import → upload the JSON file, then select your Grafana Cloud Prometheus datasource.

The compassvpn xray-exporter exposes per-user traffic stats (`xray_traffic_uplink/downlink_bytes_total{dimension="user"}`). These only appear after a user has connected and sent traffic.

## Adding or revoking users

Edit `vless_users` in `terraform.tfvars`, then:

```sh
terraform apply
```

The provisioner detects the change (via `users_hash` trigger), uploads the new `users.txt`, calls `xray-setup.sh --regen`, and restarts Xray. No server rebuild. Existing users keep their UUIDs.

## What happens on terraform apply

### First apply (new server)
cloud-init installs binaries and registers systemd units. The provisioner then uploads backups (empty on first run), generates credentials, starts services, and downloads backups.

### Subsequent applies (users changed)
Server is not rebuilt. Provisioner re-runs due to `users_hash` trigger.

### Destroy + re-apply (full rebuild)
cloud-init runs fresh. The provisioner uploads `backups/conduit_key.json` (preserving broker reputation), `backups/keypair.env` (preserving Reality keypair — users keep their client configs), and `backups/clients/*.uuid` (preserving UUIDs). Everything continues working transparently.

> **Important:** `backups/keypair.env` must have all three fields populated (`PRIVATE_KEY`, `PUBLIC_KEY`, `SHORT_ID`) before a rebuild. If any are blank, xray-setup.sh will abort with an error. Verify with `cat backups/keypair.env` before running `terraform apply`.

## Metrics architecture

```
┌─────────────────────────────────────────────────────┐
│  CX23 server                                        │
│                                                     │
│  conduit   ──── :9090/metrics ──┐                  │
│  xray      ──── gRPC :8080 ─────┤                  │
│  xray-exporter ─ :9091/scrape ──┤                  │
│  alloy (node exporter built-in) ┘                  │
│       │                                             │
│       └── remote-write (HTTPS out) ──────────────► │
│                                                     │
└──────────────────────── Grafana Cloud ──────────────┘
                          (hosted Prometheus + Grafana)
```

Conduit exposes Prometheus metrics natively via `--metrics-addr` (added in v2.0.0).
Xray exposes a gRPC Stats API; `xray-exporter` translates this to Prometheus format and also parses `access.log` for per-user traffic breakdowns.
Grafana Alloy scrapes both endpoints locally and remote-writes over outbound HTTPS — no new inbound ports required.

## File layout

### Local (backups/ — secure these)

```
backups/
  conduit_key.json      # Conduit broker identity — loss means reputation reset
  keypair.env           # Reality private key + public key + short ID
  users.txt             # Generated from vless_users; uploaded each apply
  alloy-config.alloy    # Rendered Alloy config with Grafana credentials
  clients/
    alice.uuid           # Per-user UUID — preserved across rebuilds
    bob.uuid
    alice.txt            # Per-user vless:// URI
    bob.txt
```

### Server

| Path | Purpose |
|---|---|
| `/usr/local/bin/conduit` | Conduit binary |
| `/var/lib/conduit/data/conduit_key.json` | Conduit identity |
| `/usr/local/bin/xray` | Xray-core binary |
| `/etc/xray/config.json` | Xray config (root:xray 640) |
| `/etc/xray/keypair.env` | Reality keypair (root 600) |
| `/etc/xray/users.txt` | Current user list |
| `/etc/xray/clients/<name>.uuid` | Per-user UUID |
| `/etc/xray/clients/<name>.txt` | Per-user vless:// URI |
| `/usr/local/sbin/xray-setup.sh` | Generates xray config + per-user UUIDs and URIs from `/etc/xray/users.txt`. Run with `--regen` to regenerate after editing users. Restart xray after. |
| `/usr/local/bin/xray-exporter` | Xray → Prometheus bridge |
| `/usr/local/bin/alloy` | Grafana Alloy binary |
| `/etc/alloy/config.alloy` | Alloy scrape + remote-write config |

## Useful commands

```sh
# Service status
ssh root@<ip> 'systemctl status conduit xray xray-exporter alloy'

# Logs
ssh root@<ip> 'journalctl -u conduit -f'
ssh root@<ip> 'journalctl -u xray -f'
ssh root@<ip> 'journalctl -u alloy -f'

# Check metrics endpoints (from the server)
ssh root@<ip> 'curl -s http://127.0.0.1:9090/metrics | head -20'   # Conduit
ssh root@<ip> 'curl -s http://127.0.0.1:9091/scrape  | head -20'   # Xray

# Manually re-run provisioner without a full apply
# (e.g. after adding files to backups/)
terraform apply -replace=null_resource.provision
```

## Updating binaries

Change the relevant `*_version` variable in `terraform.tfvars`, then SSH in and update manually (cloud-init only runs on first boot), or destroy and recreate. On recreate, backups restore everything automatically.

## Optional: KhajuBridge (Iran traffic prioritisation)

[KhajuBridge](https://github.com/delejos/conduit-iran-khajubridge) is an optional nftables layer that restricts Conduit's UDP traffic to Iranian IP ranges, biasing the Psiphon broker toward routing Iranian clients to your instance. It does not affect Xray/VLESS or SSH.

```sh
cd /opt
git clone https://github.com/delejos/conduit-iran-khajubridge khajubridge
cd khajubridge
chmod +x scripts/*.sh install.sh
sudo bash install.sh
sudo /opt/khajubridge/scripts/update_region_cidrs.sh
sudo /opt/khajubridge/scripts/apply_firewall.sh
sudo cp systemd/khajubridge-cidr-refresh.service /etc/systemd/system/
sudo cp systemd/khajubridge-cidr-refresh.timer   /etc/systemd/system/
sudo cp -r systemd/conduit.service.d             /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now khajubridge-cidr-refresh.timer
```

To remove: `sudo nft delete table inet khajubridge && sudo systemctl disable --now khajubridge-cidr-refresh.timer`

Note: KhajuBridge is not managed by Terraform and must be reapplied manually after a server rebuild.

## Security notes

- `backups/` is gitignored. Store it in a password manager vault or encrypted drive.
- The Alloy config contains your Grafana Cloud API key — treat it like a password.
- The Reality keypair is equivalent to a TLS private key — back it up and keep it private.

## Teardown

```sh
terraform destroy
```
README