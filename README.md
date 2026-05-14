# Viaduct — Conduit + VLESS Station on Hetzner Cloud (Terraform)

Deploys a Hetzner CX23 server (~€4/month) running:

| Service | Purpose |
|---|---|
| **Conduit** | Psiphon inproxy relay — censorship circumvention for Psiphon clients |
| **Xray** | VLESS proxy — Reality (direct) + WebSocket via Cloudflare CDN |
| **nginx** | TLS reverse proxy — forwards Cloudflare WebSocket traffic to Xray |
| **xray-exporter** | Prometheus exporter for Xray inbound/system traffic stats |
| **xray-user-stats** | Sidecar exporter for per-user traffic bytes (from Xray Stats API) |
| **Grafana Alloy** | Metrics agent — scrapes all exporters, remote-writes to Grafana Cloud |

All services run as unprivileged users under systemd. Only ports 22, 443, and 8443 are open inbound. Metrics are pushed outbound to Grafana Cloud — no inbound scrape port needed.

## Architecture

```
┌─────────────────────────── Clients ───────────────────────────────┐
│                                                                   │
│  Iran / blocked regions          Direct (anywhere)                │
│  VLESS+WebSocket+TLS             VLESS+Reality+TCP                │
│  → example.com:443                 → server-ip:8443                 │
└──────────┬─────────────────────────────┬──────────────────────────┘
           │                             │
           ▼                             │
   ┌───────────────┐                     │
   │  Cloudflare   │  (hides server IP)  │
   │  CDN / Proxy  │                     │
   └───────┬───────┘                     │
           │ HTTPS → HTTP (TLS strip)    │
           ▼                             ▼
┌──────────────────────────────────────────────────────────────────┐
│  CX23 server (203.0.113.10)                                   │
│                                                                  │
│  nginx :443 (TLS, self-signed)                                   │
│    └── /vless WebSocket ──► xray WS inbound  :10000 (lo)         │
│                                                                  │
│  xray Reality inbound :8443 ◄──────────────────────────────────  │
│                                                                  │
│  conduit        ── :9090/metrics ──┐                             │
│  xray-exporter  ── :9091/scrape  ──┤                             │
│  xray-user-stats── :9092/metrics ──┤                             │
│  alloy (node exporter built-in)    │                             │
│       └── remote-write (HTTPS) ────┘──────────────────────────►  │
│                                                                  │
└─────────────────────────── Grafana Cloud ────────────────────────┘
                             (hosted Prometheus + Grafana)
```

Each user gets **two client URIs**:
- **WebSocket URI** (`*-ws`) — connects via `example.com:443` through Cloudflare. Use from Iran and other regions where the server IP is blocked.
- **Reality URI** (`*-reality`) — connects directly to `server-ip:8443`. Lower latency, use outside Iran.

## Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/install) ≥ 1.3
- A [Hetzner Cloud](https://www.hetzner.com/cloud/) account
- A [Cloudflare](https://cloudflare.com) account (free tier)
- A domain name pointed to Cloudflare (e.g. `example.com`)
- A [Grafana Cloud](https://grafana.com/auth/sign-up) account (free tier)
- An SSH key pair on your local machine

## First-time setup

### 1. Cloudflare

1. Register a domain (Namecheap, Porkbun, or Cloudflare Registrar — all include free WHOIS privacy)
2. Add the domain to Cloudflare → note the two nameservers → set them in your registrar
3. In Cloudflare DNS, add an **A record**: name `@`, value = your Hetzner server IP, **Proxied** (orange cloud)
4. In Cloudflare **SSL/TLS → Overview**, set encryption mode to **Full** (not Flexible, not Full strict)

### 2. Grafana Cloud

1. Sign up at grafana.com → create a stack
2. Navigate to your stack → **Prometheus** → **Details**
3. Note the **Remote Write Endpoint** URL and **Username**
4. Go to your org → **Access Policies** → create a token with the **MetricsPublisher** role
5. Import the Grafana dashboards (see [Dashboards](#dashboards) below)

### 3. Terraform

```sh
cp terraform.tfvars.example terraform.tfvars
# Fill in: hcloud_token, ssh keys, vless_domain, vless_users, grafana_cloud_* values, 
# binary versions (and checksums, from separately running get-checksums.sh

terraform init
terraform plan
terraform apply
```

After `apply`, the provisioner:
1. Waits for cloud-init to finish
2. Uploads any backup files (preserving Conduit identity, Reality keypair, UUIDs)
3. Uploads `users.txt` and `alloy-config.alloy` (with Grafana credentials)
4. Runs `xray-setup.sh --regen`
5. Starts all six services
6. Downloads fresh backups to `backups/`

Both Reality and WebSocket client URIs are saved locally to `backups/clients/<name>.txt`.

## Dashboards

| Dashboard | Source |
|---|---|
| **VLESS+Reality** | `dashboards/vless-xray-dashboard.json` (this repo) |
| **Conduit** | https://github.com/shayanb/MoaV/blob/main/configs/monitoring/grafana/provisioning/dashboards/conduit.json |
| **Node (system)** | Grafana dashboard ID **1860** (Node Exporter Full) — import by ID |

To import the VLESS dashboard: Grafana → Dashboards → New → Import → upload the JSON file, then select your Grafana Cloud Prometheus datasource.

The dashboard shows:
- Service status and uptime
- Bandwidth by inbound (`vless_ws_in` = WebSocket/Cloudflare, `vless_in` = Reality/direct)
- Per-user uplink/downlink rates and totals (from `xray-user-stats`)
- Active users in the last 24 hours

## Adding or revoking users

Edit `vless_users` in `terraform.tfvars`, then:

```sh
terraform apply
```

The provisioner detects the change (via `users_hash` trigger), uploads the new `users.txt`, calls `xray-setup.sh --regen`, and restarts Xray. No server rebuild. Existing users keep their UUIDs.

## What happens on terraform apply

### First apply (new server)
cloud-init installs binaries, nginx, and registers systemd units. The provisioner then uploads backups, generates credentials, starts services, and downloads backups.

### Subsequent applies (users changed)
Server is not rebuilt. Provisioner re-runs due to `users_hash` trigger.

### Destroy + re-apply (full rebuild)
cloud-init runs fresh. The provisioner uploads:
- `backups/conduit_key.json` — preserves Conduit broker reputation
- `backups/keypair.env` — preserves Reality keypair (users keep their client configs)
- `backups/clients/*.uuid` — preserves UUIDs

> **Important:** `backups/keypair.env` must have all three fields populated (`PRIVATE_KEY`, `PUBLIC_KEY`, `SHORT_ID`) before a rebuild. If any are blank, xray-setup.sh will abort with an error. Verify with `cat backups/keypair.env` before running `terraform apply`.

## Metrics architecture

```
┌─────────────────────────────────────────────────────┐
│  CX23 server                                        │
│                                                     │
│  conduit        ──── :9090/metrics ──┐              │
│  xray-exporter  ──── :9091/scrape  ──┤              │
│  xray-user-stats──── :9092/metrics ──┤              │
│  alloy (node exporter built-in)      │              │
│       └── remote-write (HTTPS out) ──┴───────────►  │
│                                                     │
└──────────────────────── Grafana Cloud ──────────────┘
                          (hosted Prometheus + Grafana)
```

**xray-exporter** (compassvpn fork) scrapes Xray's gRPC Stats API and access log:
- `xray_up`, `xray_uptime_seconds` — service health
- `xray_traffic_uplink/downlink_bytes_total{dimension="inbound"}` — per-inbound bandwidth
- `xray_unique_users` — users active in the last 24 hours (access log window)
- `xray_countries_total`, `xray_cities_total`, `xray_asns_total` — connection geography

**xray-user-stats** (custom sidecar) queries the Xray Stats API directly:
- `xray_user_uplink_bytes_total{user="..."}` — cumulative uplink per user
- `xray_user_downlink_bytes_total{user="..."}` — cumulative downlink per user

These are true Prometheus counters, so Grafana `rate()` and `increase()` queries work correctly across any time range.

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
    alice.txt            # Per-user URIs (Reality + WebSocket)
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
| `/etc/xray/clients/<name>.txt` | Per-user URIs (Reality + WebSocket) |
| `/usr/local/sbin/xray-setup.sh` | Generates xray config + per-user UUIDs and URIs from `/etc/xray/users.txt`. Run with `--regen` to regenerate after editing users. Restart xray after. |
| `/usr/local/bin/xray-exporter` | Xray inbound stats → Prometheus |
| `/usr/local/bin/xray-user-stats.py` | Xray per-user stats → Prometheus (port 9092) |
| `/etc/nginx/conf.d/vless-ws.conf` | nginx WebSocket proxy config |
| `/etc/nginx/ssl/origin.{crt,key}` | Self-signed TLS cert for nginx (Cloudflare Full mode) |
| `/usr/local/bin/alloy` | Grafana Alloy binary |
| `/etc/alloy/config.alloy` | Alloy scrape + remote-write config |

## Useful commands

```sh
# Service status
ssh root@<ip> 'systemctl status conduit xray xray-exporter xray-user-stats alloy nginx'

# Logs
ssh root@<ip> 'journalctl -u conduit -f'
ssh root@<ip> 'journalctl -u xray -f'
ssh root@<ip> 'journalctl -u alloy -f'

# Check metrics endpoints (from the server)
ssh root@<ip> 'curl -s http://127.0.0.1:9090/metrics | head -20'   # Conduit
ssh root@<ip> 'curl -s http://127.0.0.1:9091/scrape  | head -20'   # xray-exporter
ssh root@<ip> 'curl -s http://127.0.0.1:9092/metrics'              # xray-user-stats

# Query xray Stats API directly
ssh root@<ip> '/usr/local/bin/xray api statsquery --server=127.0.0.1:8080 --pattern=user'

# Confirm  Cloudflare is proxying your domain
ssh root@<ip> dig +short your.url

# Manually re-run provisioner without a full apply
terraform apply -replace=null_resource.provision
```

## Updating binaries

Change the relevant `*_version` variable in `terraform.tfvars`. Then run `get-checksums.sh` and paste the new checksums into `terraform.tfvars`.
Then SSH in and update manually (cloud-init only runs on first boot), or destroy and recreate. On recreate, backups restore everything automatically.

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
- nginx uses a self-signed certificate. Cloudflare SSL mode must be set to **Full** (not Flexible, not Full strict) — Flexible would send traffic to the server unencrypted; Full strict would reject the self-signed cert.

## Teardown

```sh
terraform destroy
```
