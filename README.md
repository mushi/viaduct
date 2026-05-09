# Viaduct — Conduit Station on Hetzner Cloud (Terraform)

Deploys a single Psiphon Conduit relay node on a Hetzner CX23 server
(2 vCPU, 4 GB RAM, 40 GB NVMe, ~€4/month as of 2026).

## Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/install) ≥ 1.3
- A [Hetzner Cloud](https://www.hetzner.com/cloud/) account and project
- An SSH key pair (`ssh-keygen -t ed25519 -C "conduit"` if you need one)

## Setup

```sh
# 1. Clone / place this directory somewhere
cd conduit-hetzner

# 2. Create your variables file
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars — at minimum fill in hcloud_token and ssh_public_key

# 3. Initialise Terraform
terraform init

# 4. Preview the plan
terraform plan

# 5. Apply
terraform apply
```

Terraform will output the server IP and convenience SSH/log commands.

## What it creates

| Resource | Details |
|---|---|
| `hcloud_ssh_key.conduit` | Your public key, registered with Hetzner |
| `hcloud_firewall.conduit` | Allows SSH in (from `admin_cidr`), all traffic out |
| `hcloud_server.conduit` | CX23, Ubuntu 24.04, with cloud-init |

### On the server (via cloud-init)

- Dedicated `conduit` system user (no login shell, no home directory)
- `/var/lib/conduit/data/` — persistent data directory, owned by `conduit`
- `/usr/local/bin/conduit` — official binary from Psiphon's GitHub releases
- `/etc/systemd/system/conduit.service` — hardened systemd unit
- Automatic security updates via `unattended-upgrades`

## Key files on the server

| Path | Purpose |
|---|---|
| `/var/lib/conduit/data/conduit_key.json` | **Node identity/reputation key — back this up!** |
| `/var/lib/conduit/data/traffic_state.json` | Traffic usage tracking |
| `/usr/local/bin/conduit` | Conduit binary |
| `/etc/systemd/system/conduit.service` | systemd unit |

> **Important:** The `conduit_key.json` file is how Psiphon's broker tracks
> your node's reputation. A new key starts with zero reputation and will
> receive fewer client connections until it builds history. If you rebuild
> the server, copy this file to the new instance first.

## Useful commands

```sh
# Check service status
ssh root@<ip> 'systemctl status conduit'

# Tail live logs
ssh root@<ip> 'journalctl -u conduit -f'

# Restart the service
ssh root@<ip> 'systemctl restart conduit'

# Back up the identity key
scp root@<ip>:/var/lib/conduit/data/conduit_key.json ./conduit_key.backup.json
```

## Updating Conduit

Change `conduit_version` in `terraform.tfvars` and run `terraform apply`.
The cloud-init script only runs on first boot, so to update an existing server:

```sh
# SSH in and update manually
ssh root@<ip>
systemctl stop conduit
curl -fsSL "https://github.com/Psiphon-Inc/conduit/releases/download/release-cli-X.Y.Z/conduit-linux-amd64" \
  -o /usr/local/bin/conduit
chmod +x /usr/local/bin/conduit
systemctl start conduit
```

Or destroy and recreate the server with `terraform destroy && terraform apply`
(remember to restore `conduit_key.json` afterwards if you care about reputation).

## Teardown

```sh
terraform destroy
```
