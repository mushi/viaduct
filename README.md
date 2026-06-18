# Viaduct - Conduit + VLESS Station on Multiple Clouds (Terraform)

## What
A lab that extends the main branch into a multi-cloud SPIFFE/SPIRE + Vault
deployment. It adds no user-facing capability over main; its purpose is to exercise
cross-cloud workload identity and secrets management. \
Three nodes, each a separate Terraform root:
1. **Hetzner** — the production node from main: VLESS+Reality proxy
   ([Xray-core](https://github.com/XTLS/Xray-core)) + Psiphon Conduit relay
   ([Psiphon Conduit](https://github.com/Psiphon-Inc/conduit)), unchanged.
2. **AWS** — a k3s (Kubernetes) node running a SPIRE agent and a bandwidth-capped
   Conduit pod, for Kubernetes-based workload attestation.
3. **GCP** — the control plane: Vault (secrets management) and the SPIRE server
   (workload attestation) that the other two nodes authenticate to.
### VLESS
End users connect with a client app - e.g. V2RayNG (Android), v2rayN (Windows), or Nekoray - that routes their device's traffic through the server. It works like a VPN for the user, though the underlying protocol is a proxy. This project generates connection URIs per user.

### Conduit
Conduit serves bandwidth to users through Psiphon's broker even when the server's IP is blocked; the direct VLESS paths require the IP to be reachable.

_Older tags (v0.1.0–v0.3.0) provide alternative deployable configurations._

### Deployment
Deploys a Hetzner CX23 server (~€4/month) running:

| Service | Purpose |
|---|---|
| **Conduit** | Psiphon inproxy relay — censorship circumvention for Psiphon clients |
| **Xray** | VLESS proxy — Reality (direct, port 443) + XHTTP+TLS via Let's Encrypt (port 8443) |
| **nginx** | Port 80: static website (active probing defence). Port 8443: terminates Let's Encrypt TLS, proxies XHTTP to Xray |
| **xray-exporter** | Prometheus exporter for Xray inbound/system traffic stats |
| **xray-user-stats** | Sidecar exporter for per-user traffic bytes (from Xray Stats API) |
| **Grafana Alloy** | Metrics agent — scrapes all exporters, remote-writes to Grafana Cloud |

All services run as unprivileged users under systemd. Ports 22, 80, 443, and 8443 are open inbound. Metrics are pushed outbound to Grafana Cloud — no inbound scrape port needed.

## Architecture

```
┌──────────────────────────────── Clients ─────────────────────────────────┐
│                                                                          │
│  Direct (anywhere)                       Iran / blocked regions          │
│  VLESS+XHTTP+TLS                         VLESS+Reality+TCP               │
│  → example.com:8443                        → server-ip:443               │
└────────────────────────────────────┬──────────────────┬──────────────────┘
                                     │                  │
                                     ▼                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  CX23 server (203.0.113.10)                                             │
│                                                                         │
│  nginx :80  (static site — active probing defence)                      │
│                                                                         │
│  nginx :8443 (Let's Encrypt TLS for example.com, HTTP/2)                │
│    └── /api ──► xray XHTTP inbound :10000 (lo)                          │
│                                                                         │
│  xray Reality inbound :443 ◄────────────────────────────────────────    │
│    (TLS impersonation of google.com — direct connections)               │
│                                                                         │
│  conduit        ── :9090/metrics ──┐                                    │
│  xray-exporter  ── :9091/scrape  ──┤                                    │
│  xray-user-stats── :9092/metrics ──┤                                    │
│  alloy (node exporter built-in)    │                                    │
│       └── remote-write (HTTPS) ────┴───────────────────────────────►    │
│                                                                         │
└──────────────────────────── Grafana Cloud ──────────────────────────────┘
                              (hosted Prometheus + Grafana)
```

Each user gets **two client URIs** (saved to `backups/clients/<name>.txt`):
- **XHTTP URI** (`*-xhttp`) — connects to `example.com:8443` via Let's Encrypt TLS + HTTP/2. Use where the server IP is blocked but TLS to the domain on port 8443 is reachable.
- **Reality URI** (`*-reality`) — connects directly to `server-ip:443`. Lower latency; use from anywhere the server IP is reachable.

> **DNS note:** for this version, `example.com` must be DNS-only (grey cloud) in Cloudflare, never proxied. XHTTP connects directly to the server's own TLS, so Cloudflare must stay out of the path. \
> For regions where Cloudflare is reachable and you want to use Cloudflare proxying, see tag v0.2.0 (VLESS over Cloudflare + WebSocket).
 
## Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/install) ≥ 1.3
- A [Hetzner Cloud](https://www.hetzner.com/cloud/) account
- A domain name with [Cloudflare](https://cloudflare.com) as the DNS provider (free tier sufficient — used only for DNS-01 certificate issuance, not CDN proxying)
- A [Grafana Cloud](https://grafana.com/auth/sign-up) account (free tier)
- An SSH key pair on your local machine

## First-time setup

### 1. Cloudflare

1. Register a domain (Namecheap, Porkbun, or Cloudflare Registrar — all include free WHOIS privacy)
2. Add the domain to Cloudflare → note the two nameservers → set them in your registrar
3. In Cloudflare DNS, add an **A record**: name `@`, value = your Hetzner server IP, **DNS-only** (grey cloud — do not proxy)
4. Create a Cloudflare API token: **My Profile → API Tokens → Create Token**
   - Permission: `Zone:DNS:Edit` scoped to your domain zone
   - This token is used only by certbot for DNS-01 certificate issuance

### 2. Grafana Cloud

1. Sign up at grafana.com → create a stack
2. Navigate to your stack → **Prometheus** → **Details**
3. Note the **Remote Write Endpoint** URL and **Username**
4. Go to your org → **Access Policies** → create an access policy scoped to **`metrics:write`**, then generate a token under it
5. Import the Grafana dashboards (see [Dashboards](#dashboards) below)

### 3. Terraform

```sh
cp terraform.tfvars.example terraform.tfvars
# Fill in: hcloud_token, ssh keys, vless_domain, vless_users,
# cloudflare_api_token, grafana_cloud_* values,
# binary versions and checksums (run scripts/get-checksums.sh)

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

## Dashboards

| Dashboard | Source |
|---|---|
| **VLESS+Reality** | `dashboards/vless-xray-dashboard.json` (this repo) |
| **Conduit** | https://github.com/shayanb/MoaV/blob/main/configs/monitoring/grafana/provisioning/dashboards/conduit.json |
| **Node (system)** | Grafana dashboard ID **1860** (Node Exporter Full) — import by ID |

To import the VLESS dashboard: Grafana → Dashboards → New → Import → upload the JSON file, then select your Grafana Cloud Prometheus datasource.

The dashboard shows:
- Service status and uptime
- Bandwidth by inbound (`vless_xhttp_in` = XHTTP/TLS, `vless_in` = Reality/direct)
- Per-user uplink/downlink rates and totals (from `xray-user-stats`)
- Active users in the selected time range (from `xray-user-stats`)

## Adding or revoking users

Edit `vless_users` in `terraform.tfvars`, then:

```sh
terraform apply
```

The provisioner detects the change (via `users_hash` trigger), uploads the new `users.txt`, calls `xray-setup.sh --regen`, and restarts Xray. No server rebuild. Existing users keep their UUIDs.

## What happens on terraform apply

### First apply (new server)
cloud-init installs binaries, nginx, certbot, and registers systemd units. Let's Encrypt issues a certificate via DNS-01 challenge. The provisioner then uploads backups, generates credentials, starts services, and downloads backups.

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

**xray-exporter** (compassvpn fork) reads Xray's gRPC Stats API:
- `xray_up`, `xray_uptime_seconds` — service health
- `xray_traffic_uplink/downlink_bytes_total{dimension="inbound"}` — per-inbound bandwidth

> The exporter can also derive access-log metrics (`xray_unique_users`, `xray_countries_total`, `xray_cities_total`, `xray_asns_total`). They are **unavailable in this configuration**: the Xray access log is set to `none` so the server does not record client destinations (see [Security notes](#security-notes)). The two metrics above come from the Stats API and are unaffected.

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
    alice.txt            # Per-user URIs (Reality + XHTTP)
```

### Server

| Path | Purpose |
|---|---|
| `/usr/local/bin/conduit` | Conduit binary |
| `/var/lib/conduit/data/conduit_key.json` | Conduit identity |
| `/usr/local/bin/xray` | Xray-core binary |
| `/usr/local/bin/geoip.dat` | IP geolocation data (v2fly) — used for `geoip:ir` routing rules |
| `/usr/local/bin/geosite.dat` | Domain category data (v2fly) — used for `geosite:category-ir` routing rules |
| `/etc/xray/config.json` | Xray config (root:xray 640) |
| `/etc/xray/keypair.env` | Reality keypair (root 600) |
| `/etc/xray/users.txt` | Current user list |
| `/etc/xray/clients/<name>.uuid` | Per-user UUID |
| `/etc/xray/clients/<name>.txt` | Per-user URIs (Reality + XHTTP) |
| `/usr/local/sbin/xray-setup.sh` | Generates xray config + per-user UUIDs and URIs from `/etc/xray/users.txt`. Run with `--regen` to regenerate after editing users. Restart xray after. |
| `/usr/local/bin/xray-exporter` | Xray inbound stats → Prometheus |
| `/usr/local/bin/xray-user-stats.py` | Xray per-user stats → Prometheus (port 9092) |
| `/etc/nginx/conf.d/site.conf` | nginx config: port 80 static site + port 8443 XHTTP proxy |
| `/etc/letsencrypt/live/<vless_domain>/fullchain.pem` | Let's Encrypt TLS certificate (auto-renews via systemd timer) |
| `/etc/letsencrypt/live/<vless_domain>/privkey.pem` | Let's Encrypt private key |
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

# Check Let's Encrypt certificate expiry
ssh root@<ip> 'certbot certificates'

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
sudo sed -i '/^define IRAN_UDP_RATE/d' /opt/khajubridge/nftables/conduit-region.nft
sudo sed -i \
  's/limit rate \$IRAN_UDP_RATE burst \$IRAN_UDP_BURST packets/limit rate 100000\/second burst 200000 packets/g' \
  /opt/khajubridge/nftables/conduit-region.nft
sudo /opt/khajubridge/scripts/apply_firewall.sh
sudo cp /opt/khajubridge/systemd/khajubridge-cidr-refresh.service /etc/systemd/system/
sudo cp /opt/khajubridge/systemd/khajubridge-cidr-refresh.timer   /etc/systemd/system/
sudo cp -r /opt/khajubridge/systemd/conduit.service.d             /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now khajubridge-cidr-refresh.timer
```

The two `sed` commands work around a syntax error in the nftables template (rate expressions are not valid in `define` statements on Ubuntu 24.04's nftables).

To remove: `sudo nft delete table inet khajubridge && sudo systemctl disable --now khajubridge-cidr-refresh.timer`

Note: KhajuBridge is not managed by Terraform and must be reapplied manually after a server rebuild.

## Security notes

- `backups/` is gitignored. Store it in a password manager vault or encrypted drive.
- The Alloy config contains your Grafana Cloud access-policy token — treat it like a password.
- The Reality keypair is equivalent to a TLS private key — back it up and keep it private.
- The Cloudflare API token only needs `Zone:DNS:Edit` permission. It is used solely by certbot for DNS-01 certificate renewal and is never exposed to client traffic.
- Port 80 serves a static website intentionally — this defeats active probing (DPI systems that send HTTP GET requests to suspected proxy IPs will receive a legitimate-looking response).
- Iranian IP ranges and domains are routed to a `block` outbound in Xray (`geoip:ir`, `geosite:category-ir`), preventing the server from proxying traffic back to Iranian infrastructure. This removes a potential fingerprinting signal.
- The Xray access log is disabled (`"access": "none"`), so the server does not record which destinations users connect to. Per-user byte totals are unaffected — they come from the Stats API, not the access log.

## Teardown

```sh
terraform destroy
```

## License

Released under the [MIT License](LICENSE).

## Acknowledgements

Built on these open-source projects:

- [Xray-core](https://github.com/XTLS/Xray-core) — VLESS / Reality / XHTTP proxy core
- [Psiphon Conduit](https://github.com/Psiphon-Inc/conduit) — in-proxy relay for Psiphon clients
- [Grafana Alloy](https://github.com/grafana/alloy) — metrics collection agent
- [v2fly/geoip](https://github.com/v2fly/geoip) and [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) — geo-routing data

Configuration, scripts and documentation co-authored with [Claude](https://claude.ai) (Anthropic).

## Disclaimer

This repository contains personal infrastructure-as-code for deploying a
censorship-circumvention node. It is published for educational and transparency
purposes. It is not an operated service — this repository provides no
infrastructure, access, or credentials. Anyone who deploys their own instance is
solely responsible for complying with all applicable laws and regulations.
