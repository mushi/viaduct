# Viaduct: multi-cloud SPIFFE/SPIRE + Vault lab (Terraform)

[![VulnHunter Regression Tests](https://github.com/mushi/viaduct/actions/workflows/python-app.yml/badge.svg)](https://github.com/mushi/viaduct/actions/workflows/python-app.yml)

> This branch, `lab-multicloud-spire`, is a **three-cloud deployment** running a
> bandwidth-donation data plane (VLESS+Reality and Psiphon Conduit) with cross-cloud
> **workload identity** (federated SPIRE) and **centralized secrets** (Vault). It extends
> the single-node `main` station with a second cloud node (an egress-capped Conduit) and a
> control plane, to exercise cross-cloud identity and secrets management. **It adds nothing
> for users** beyond a small Psiphon bandwidth bump; it is a control-plane lab. For the
> simpler single-node deployment, see **`main`**.


The total cost for all resources across the three clouds is ≈ $15/month USD *before end of 2026* (using an AWS t4g free trial). 
Do reconfirm the costs before running it (use the [resources breakdown](#cloud-cost-breakdown) below)!

Deployment is **low-touch**, but not no-touch. Terraform does most of it; the few manual
steps are: `terraform apply` the roots **in order (GCP → Hetzner → AWS)**; one-time Vault
setup on the GCP box (`vault operator init`, store the recovery keys offline, then run
`bootstrap-vault.sh`); supply your secret values; and point your domain at the Hetzner IP,
**DNS-only** (grey cloud in Cloudflare).

The full step-by-step is in **[docs/RUNBOOK.md](docs/RUNBOOK.md)**.

## What

Three nodes, each its **own Terraform root** (independent, isolated state):

| Node | Cloud          | Trust domain | Runs |
|---|----------------|---|---|
| **Control plane** | GCP e2-micro   | `viaduct.gcp` | Vault (secrets) + SPIRE server |
| **Data plane** | Hetzner CX23   | `viaduct.gcp` (agent) | Xray VLESS + Conduit + SPIRE agent + Vault secrets via SVID |
| **k8s node** | AWS t4g.small  | `viaduct.aws` | k3s + SPIRE server + agent + capped Conduit |

**VLESS** (Xray-core): users connect with a client app (e.g. V2RayNG, v2rayN, Nekoray) that
proxies their device's traffic. **Conduit** (Psiphon in-proxy): relays for Psiphon
clients via Psiphon's brokers, works even when the node IP is blocked.

## Architecture

```
                          ┌────────────────────────────────┐
                          │ Operator · wg 10.99.0.4        │
                          └───┬──────────┬────────────┬────┘
                     IAP SSH  │     SSM  │      wg0   │ Vault/SPIRE,
                     (GCP)    │    (AWS) │            │ Hetzner SSH
                              ▼          │            │
   ╔═══════════════ GCP · control plane · viaduct.gcp ═══════════════╗
   ║ Vault (PKI root · KMS unseal · snapshots) + SPIRE server        ║
   ║ WireGuard HUB · 10.99.0.1 · :51820  (the only public port)      ║
   ║ Vault :8200 · SPIRE :8081 · federation :8443  →  wg0-only       ║
   ╚═══▲═══════════════════════════════════════════════════▲═════════╝
       │ wg0: agent :8081 + Vault           wg0: federation :8443     
       │                                         + Vault (Alloy)      
       │                                                   │
 ┌─────┴──────────────────────┐              ┌─────────────┴──────────────┐
 │ Hetzner · 10.99.0.2        │              │ AWS · 10.99.0.3            │
 │ viaduct.gcp, SPIRE agent   │              │ viaduct.aws, SPIRE server  │
 │ SVID → Vault → secrets     │              │ k3s + SPIFFE CSI + Alloy   │
 │ Xray VLESS + Conduit       │              │ Conduit pod (capped)       │
 │ admin over wg0; :22 break  │              │ SSM only · no inbound      │
 └───┬───────────────┬────────┘              └─────────────┬──────────────┘
     │ VLESS         │ Conduit                             │ Conduit (capped)
     │ :443  Reality │ in-proxy, no inbound                │ in-proxy, no inbound
     │ :8443 XHTTP   │ (dials out to brokers)              │ (dials out to brokers)
     ▼               ▼                                     ▼
  end users (direct)  ◄──── Psiphon brokers ────►       end users
                          │ (all nodes' Alloy)
                          ▼
                  Grafana Cloud (metrics + dashboards)
```

**Data plane (public ingress).** Only the Hetzner node accepts inbound user traffic, all
over TCP: `:443` VLESS+Reality (XTLS-Vision, direct connections, no real cert; impersonates
`vless_sni`), `:8443` VLESS+XHTTP over real TLS (nginx terminates a Let's Encrypt cert, for
where the IP is blocked but the domain resolves), and `:80` a static nginx decoy site that
defeats active HTTP probing. Conduit has **no inbound port** on either node: the Psiphon
in-proxy dials out to Psiphon's brokers, which pair it with clients, so it relays even when
the node IP is blocked. AWS's node is otherwise closed (SSM only, no inbound).

**Mesh + lockdown.** WireGuard is the fabric for all cross-cloud control-plane traffic and
operator admin: Vault `:8200`, SPIRE `:8081`, and federation `:8443` are reachable only over
`wg0`. The sole public control-plane port is the hub's WireGuard UDP (`:51820`); WireGuard
drops any non-peer packet, so the crypto is the gate. The operator reaches GCP over IAP, AWS
over SSM, and Vault/SPIRE/Hetzner-SSH as a mesh peer (`10.99.0.4`).

**Wireguard** is lovely. It's small, elegant, does one thing reliably. Big respect to Jason Donenfeld. 

**Runtime identity → secrets flow:** each SPIRE agent attests its node (Hetzner
`join_token` → GCP server; AWS `aws_iid` → its own server) and receives an agent SVID; the
agent issues short-lived SVIDs to local workloads over the Workload API; a workload presents
its SVID to Vault (cert auth, matched on the SVID's SPIFFE URI SAN) and gets scoped secrets.
The AWS workload reaches GCP Vault **cross-cloud**, trust for which is established by SPIRE
**federation**. (Deploy order is the reverse dependency: GCP → Hetzner → AWS; see
[docs/RUNBOOK.md](docs/RUNBOOK.md).)

## Identity & secrets

- **Two independently-rooted trust domains.** `viaduct.gcp`'s SPIRE CA chains to Vault's
  PKI root; `viaduct.aws`'s is self-signed with its key in **AWS KMS**. **Neither root
  private key ever leaves its home** (Vault / KMS): a node compromise yields transient
  signing at most, never key theft.
- **Federation.** The two SPIRE servers exchange trust bundles over `https_spiffe`
  endpoints (:8443), so a workload in one domain can authenticate one in the other.
- **Secrets.** Workloads get short-lived X.509 **SVIDs** from SPIRE, then authenticate
  to Vault (cert auth, bound to the SVID's SPIFFE URI SAN) for scoped KV secrets. The
  AWS node authenticates **cross-cloud** to GCP's Vault this way. Both spokes render their
  secrets to **tmpfs** (Hetzner fetches its Grafana + Cloudflare secrets from Vault via its
  SPIRE SVID at boot; AWS its Alloy secret at pod start), never to persistent disk.

## Cloud cost breakdown

All-in estimate (USD/month, 24/7, excludes exceeding the AWS egress cap). The only
thing that changes at the cliff is the AWS instance leaving its free trial; GCP's
e2-micro is *always*-free (indefinite), and every other line is billed in both periods.

| Line item | Before 2026-12-31 | After | Notes                                                                                                                    |
|---|---|---|--------------------------------------------------------------------------------------------------------------------------|
| Hetzner CX23 | ~4.3 | ~4.3 | €4; the always-on station, incl. 20 TB egress                                                                            |
| GCP e2-micro compute | 0 | 0 | always-free tier (us-central1), indefinite                                                                               |
| GCP external IPv4 | ~3.6 | ~3.6 | billed even on free-tier VMs                                                                                             |
| GCP KMS + GCS snapshots | ~0.1 | ~0.1 | unseal key + small Vault + SPIRE snapshots                                                                                 |
| AWS t4g.small compute | 0 | ~13 | **free trial → 2026-12-31**, then on-demand 24/7                                                                         |
| AWS EIP (public IPv4) | ~3.6 | ~3.6 | billed in-use                                                                                                            |
| AWS EBS gp3 root | ~1.8 | ~1.8 | ~30 GB, encrypted                                                                                                        |
| AWS KMS (SPIRE CA) | ~2.0 | ~2.0 | 2 keys, the X.509 CA A/B rotation slots (JWT signing is disabled); **survive `terraform destroy`** |
| **Total** | **≈ 15** | **≈ 28** |                                                                                                                          |

Figures are approximate and region/FX-dependent; the AWS instance assumes on-demand 24/7
(a 1-yr Savings Plan roughly halves it). AWS egress is the cost risk: **100 GB/mo is free**
(account-global, not per-region or trial-scoped), then ~**$0.11/GB** in ap-south-1. The
Conduit relay is bandwidth-capped and a host timer **throttles egress at 70% of the cap and stops the instance near 90 GB/mo**.
**Lifecycle:** Hetzner is persistent (the live station); GCP + AWS are the lab, torn down
once they've served their purpose.

## Deploy & operate

The full operator runbook, first deploy and rebuild, apply order, recovery, and teardown,
is in **[docs/RUNBOOK.md](docs/RUNBOOK.md)**. It is a linear, copy-paste sequence; start
there. This README covers the what and why; the runbook covers the how.

## Data plane (the service)

Hetzner runs the full VLESS station; AWS runs an egress-capped Conduit relay. Each VLESS
user gets **two client URIs** in `backups/clients/<name>.txt`:

- **Reality** (`*-reality`): direct to `server-ip:443`, TLS-impersonates `google.com`. Lower latency where the IP is reachable.
- **XHTTP/TLS** (`*-xhttp`): to `example.com:8443` via Let's Encrypt + HTTP/2. For regions where the IP is blocked but the domain on :8443 is reachable.

Add/revoke users by editing `vless_users` in `terraform.tfvars` and re-running
`terraform apply` (no rebuild). Optional Iran traffic prioritisation via
[KhajuBridge](https://github.com/delejos/conduit-iran-khajubridge) (nftables; not
Terraform-managed, reapply after a rebuild).

## Observability

Every node's **Grafana Alloy** scrapes local exporters and remote-writes to Grafana
Cloud, labelled by node: Conduit usage → the [MoaV dashboard](https://github.com/shayanb/MoaV/blob/main/configs/monitoring/grafana/provisioning/dashboards/conduit.json), VLESS per-user stats →
`dashboards/vless-xray-dashboard.json`, node metrics → Node Exporter (1860). A blackbox
**availability probe** exercises the VLESS/Reality path each minute and exposes SLIs on
`:9110`; a dead-man's-switch alert fires if a node stops reporting. AWS egress headroom
ships as `aws_mtd_egress_bytes` / `aws_egress_cap_bytes`. Vault / SPIRE / k3s telemetry is
planned on a separate dashboard.

## Security notes

- **Control plane is mesh-only.** Vault (`:8200`), the SPIRE server API (`:8081`), and federation (`:8443`) have no public ingress: cross-cloud traffic reaches them only over the WireGuard mesh, and re-exposing any of them requires adding a firewall rule (a reviewable code change), not flipping a variable. The only world-facing control-plane port is the hub's WireGuard UDP (`:51820`).
- Hetzner SSH is key-only, with no root login. Two OS identities on separate keypairs: `deploy` (automation, broad sudo) and `ops` (interactive, sudo scoped to service lifecycle + logs), IP-restricted via `admin_cidr`; day-to-day admin is over the mesh. GCP admin is via IAP, AWS via SSM Session Manager, with no public SSH on either.
- AWS IAM separates two least-privilege identities: a _deployment_ identity for running `terraform apply` (scoped to the resources it manages, explicitly denied KMS key deletion) and an MFA-enforced _operator_ identity for interactive admin. SPIRE creates KMS keys dynamically, so the deployment identity holds kms:Sign on * with destructive KMS actions withheld to bound the blast radius.
- Root CA keys are non-exportable from Vault PKI (`viaduct.gcp`) and AWS KMS (`viaduct.aws`).
- Secrets are delivered to workloads from Vault into tmpfs via each node's SPIRE SVID (cert auth), never persistent disk: Hetzner fetches `kv/hetzner/*` at boot, AWS fetches `kv/aws/grafana` at pod start. Per-node secret sets are disjoint.
- `backups/` and all `terraform.tfvars` (live keys/tokens) are gitignored.
- Xray access log is `none`, to preserve user privacy; `geoip:ir` / `geosite:category-ir` are routed to `block` (no proxying back into Iran, removing a fingerprint signal); port 80 serves a decoy static site (anti-active-probing).

## License

Released under the [MIT License](LICENSE).

## Acknowledgements

- [SPIFFE/SPIRE](https://spiffe.io): workload identity & attestation
- [HashiCorp Vault](https://www.vaultproject.io): secrets & PKI
- [k3s](https://k3s.io): lightweight Kubernetes · [SPIFFE CSI Driver](https://github.com/spiffe/spiffe-csi)
- [Xray-core](https://github.com/XTLS/Xray-core): VLESS / Reality / XHTTP proxy
- [Psiphon Conduit](https://github.com/Psiphon-Inc/conduit): in-proxy relay
- [Grafana Alloy](https://github.com/grafana/alloy): metrics agent · [v2fly](https://github.com/v2fly) geo-routing data

Configuration, scripts and documentation co-authored with [Claude](https://claude.ai) (Anthropic).

## Disclaimer
Personal infrastructure-as-code for censorship-circumvention nodes, published for
educational and transparency purposes. This is not an operated service: the repository
provides no infrastructure, access, or credentials. Anyone who deploys their own instance
is solely responsible for complying with all applicable laws.
