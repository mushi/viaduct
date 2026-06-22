# Viaduct — multi-cloud SPIFFE/SPIRE + Vault lab (Terraform)

> This branch, `lab-multicloud-spire`, is a **three-cloud deployment** that runs a
> bandwidth donation data plane (VLESS+Reality and Psiphon Conduit) with cross-cloud
> **workload identity** (federated SPIRE) and **centralized secrets** (Vault). The data
> plane is the same service the `main` branch provides single-node; this branch adds 
> a second cloud node (running an egress-constrained Conduit, no VLESS) and a control plane to exercise cross-cloud identity and secrets
> management. This adds nothing for users. It is useful if you want to see SPIFFE/SPIRE
> and Vault in action. For the simpler single-node station deployment, see **`main`**.


The total cost for all resources across the three clouds is ≈ $14/month USD *before end of 2026* (using an AWS t4g free trial). 
Do reconfirm the costs before running it (use the [resources breakdown](#cloud-cost-breakdown) below)!

Deployment is **low-touch**, but not no-touch. Most of the work is done by terraform, but you'll need prerequisites and a handful of manual steps, mainly:
1. Fill values in `terraform.tfvars` files and `terraform apply` the roots **in order: GCP → Hetzner → AWS**.
2. **GCP Vault bootstrap** (one-time, root token): `vault operator init`, store recovery keys offline, enable PKI / cert-auth / AppRoles — [gcp/BOOTSTRAP.md](gcp/BOOTSTRAP.md).
3. **AWS (k8s) cross-cloud Vault role** after federation — [aws/k8s/README.md](aws/k8s/README.md).
4. **DNS:** point your domain at the Hetzner IP, **DNS-only** (grey cloud in Cloudflare).

See the [runbooks](#runbooks) section for complete details.

## What

Three nodes, each its **own Terraform root** (independent state, blast-radius isolation):

| Node | Cloud          | Trust domain | Runs |
|---|----------------|---|---|
| **Control plane** | GCP e2-micro   | `viaduct.gcp` | Vault (secrets) + SPIRE server |
| **Data plane** | Hetzner CX23   | `viaduct.gcp` (agent) | Xray VLESS + Conduit + SPIRE agent + Vault Agent |
| **k8s node** | AWS t4g.small  | `viaduct.aws` | k3s + SPIRE server + agent + capped Conduit |

**VLESS** (Xray-core): users connect with a client app (V2RayNG, v2rayN, Nekoray) that
proxies their device's traffic. **Conduit** (Psiphon in-proxy): relays for Psiphon
clients via Psiphon's brokers — works even when the node IP is blocked.

## Architecture

```
                 ┌──────────── GCP — control plane (viaduct.gcp) ────────────┐
                 │   Vault  (PKI root CA · KMS auto-unseal · Raft snapshots) │
                 │   SPIRE server                                            │
                 └───▲──────────────────▲────────────────────────▲───────────┘
[3] SVID cert-auth → │ [1] SPIRE agent  │ SPIRE federation       │cross-cloud → GCP
    Vault (:8200)    │     API (:8081)  │ (https_spiffe, :8443)  │Vault (:8200)
                     │                  │                        │
 ┌───────────────────┴──────┐      ┌────┴────────────────────────┴───────────┐
 │ Hetzner CX23             │      │ AWS t4g.small                           │
 │ (member of viaduct.gcp)  │      │  SPIRE server — root CA in AWS KMS      │
 │  SPIRE agent (join_token)│      │  k3s + SPIFFE CSI driver                │
 │ [2] Vault Agent → secrets│      │  SPIRE agent (aws_iid)                  │
 │  Xray VLESS + Conduit    │◀════▶│  Conduit pod (capped) + Alloy           │
 │  Alloy → Grafana Cloud   │ fed. │  egress guardrail (auto-stop ≈90 GB/mo) │
 └──────────┬───────────────┘      └────────────────┬────────────────────────┘
            │ VLESS + Conduit                       │ Conduit relay (capped)
            ▼                                       ▼
        end users  ◀──── Psiphon brokers / direct VLESS ────▶  end users
                              │ (all nodes' Alloy)
                              ▼
                        Grafana Cloud (Prometheus + dashboards)
```

**Runtime identity → secrets flow:** **[1]** each SPIRE agent attests its node (Hetzner
`join_token` → GCP server; AWS `aws_iid` → its own server) and receives an agent SVID;
**[2]** the agent issues short-lived SVIDs to local workloads over the Workload API;
**[3]** a workload presents its SVID to Vault (cert auth, matched on the SVID's SPIFFE
URI SAN) and gets scoped secrets — the AWS workload reaches GCP Vault **cross-cloud**,
trust for which is established by SPIRE **federation** (:8443). (Deploy order is the
reverse dependency: GCP → Hetzner → AWS; see [Runbooks](#runbooks).)

## Identity & secrets

- **Two independently-rooted trust domains.** `viaduct.gcp`'s SPIRE CA chains to Vault's
  PKI root; `viaduct.aws`'s is self-signed with its key in **AWS KMS**. **Neither root
  private key ever leaves its home** (Vault / KMS) — a node compromise yields transient
  signing at most, never key theft.
- **Federation.** The two SPIRE servers exchange trust bundles over `https_spiffe`
  endpoints (:8443), so a workload in one domain can authenticate one in the other.
- **Secrets.** Workloads get short-lived X.509 **SVIDs** from SPIRE, then authenticate
  to Vault (cert auth, bound to the SVID's SPIFFE URI SAN) for scoped KV secrets. The
  AWS node authenticates **cross-cloud** to GCP's Vault this way. Secrets are rendered
  to **tmpfs / RAM**, never to persistent disk and never committed.

## Cloud cost breakdown

All-in estimate (USD/month, 24/7, excludes exceeding the AWS egress cap). The only
thing that changes at the cliff is the AWS instance leaving its free trial; GCP's
e2-micro is *always*-free (indefinite), and every other line is billed in both periods.

| Line item | Before 2026-12-31 | After | Notes |
|---|---|---|---|
| Hetzner CX23 | ~4.3 | ~4.3 | €4; the always-on station, incl. 20 TB egress |
| GCP e2-micro compute | 0 | 0 | always-free tier (us-central1), indefinite |
| GCP external IPv4 | ~3.6 | ~3.6 | billed even on free-tier VMs |
| GCP KMS + GCS snapshots | ~0.1 | ~0.1 | unseal key + small weekly Raft snapshots |
| AWS t4g.small compute | 0 | ~13 | **free trial → 2026-12-31**, then on-demand 24/7 |
| AWS EIP (public IPv4) | ~3.6 | ~3.6 | billed in-use |
| AWS EBS gp3 root | ~1.8 | ~1.8 | ~20 GB, encrypted |
| AWS KMS (SPIRE CA) | ~1.0 | ~1.0 | 1 customer key; **survives `terraform destroy`** |
| **Total** | **≈ 14** | **≈ 27** | |

Figures are approximate and region/FX-dependent; the AWS instance assumes on-demand 24/7
(a 1-yr Savings Plan roughly halves it). AWS egress is the cost risk (100 GB/mo free, then
~$0.09/GB) — the Conduit relay is **bandwidth-capped** and a host timer guardrail **auto-stops the
instance near 90 GB/month**. **Lifecycle:** Hetzner is persistent (the live station); GCP + AWS
are the lab and can be torn once they've served their educational purpose.

## Runbooks

### Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/install) ≥ 1.3
- Accounts on [Hetzner Cloud](https://www.hetzner.com/cloud/), [AWS](https://signin.aws.amazon.com/signup?request_type=register) and [GCP](https://docs.cloud.google.com/docs/get-started/)
- A domain name with [Cloudflare](https://cloudflare.com) as the DNS provider (free tier sufficient — used only for DNS-01 certificate issuance, not CDN proxying)
- A [Grafana Cloud](https://grafana.com/auth/sign-up) account (free tier)
- An SSH key pair on your local machine

### First-time setup

#### 1. Cloudflare

1. Register a domain (Namecheap, Porkbun, or Cloudflare Registrar — all include free WHOIS privacy)
2. Add the domain to Cloudflare → note the two nameservers → set them in your registrar
3. In Cloudflare DNS, add an **A record**: name `@`, value = your Hetzner server IP, **DNS-only** (grey cloud — do not proxy)
4. Create a Cloudflare API token: **My Profile → API Tokens → Create Token**
  - Permission: `Zone:DNS:Edit` scoped to your domain zone
  - This token is used only by certbot for DNS-01 certificate issuance

#### 2. Grafana Cloud

1. Sign up at grafana.com → create a stack
2. Navigate to your stack → **Prometheus** → **Details**
3. Note the **Remote Write Endpoint** URL and **Username**
4. Go to your org → **Access Policies** → create an access policy scoped to **`metrics:write`**, then generate a token under it
5. Import the Grafana dashboards 

#### 3. Terraform

Each root is independent (local state). **Order matters: bring up the GCP control plane
first** — the other nodes authenticate to its Vault/SPIRE; then Hetzner and AWS.

1. **Shared SSH source.** Export your admin IP once (used by all three roots):
   `export TF_VAR_admin_cidr='["x.x.x.x/32"]'`
2. **GCP control plane.** `cd gcp && cp terraform.tfvars.example terraform.tfvars`,
   fill it in, then `terraform init && terraform apply`.
   Vault comes up **sealed + uninitialised**.
3. **GCP Vault bootstrap** (one-time, manual) — follow [GCP boostrap](gcp/BOOTSTRAP.md):
   `vault operator init` → store recovery keys + root token **offline**; enable
   KV/PKI/cert-auth/AppRoles; put the two AppRole **role-ids** into `gcp/terraform.tfvars`
   and `terraform apply` again; place the **secret-ids** on the host; seed secrets;
   `vault token revoke -self`.
4. **Hetzner data plane.** From the repo root:
   `cp terraform.tfvars.example terraform.tfvars && ./scripts/get-checksums.sh`,
   then `terraform init && terraform apply`.
5. **AWS node.** `cd aws && cp terraform.tfvars.example terraform.tfvars`,
   set `gcp_control_plane_ip` + `gcp_vault_fingerprint` (and `gcp_trust_domain`),
   then `terraform init && terraform apply`.
6. **AWS cross-cloud Vault role** (one-time, manual) — follow [K8s Readme](aws/k8s/README.md#vault-cert-auth-bootstrap): create the `aws-vault-agent` cert role on GCP Vault and
   seed `kv/aws/grafana`.
7. **Complete federation.** Set `aws_spire_ip` and `federation_cidrs` in
   `gcp/terraform.tfvars`, then `cd gcp && terraform apply` to open `:8443` and emit the
   federation block (AWS already federates toward GCP from step 5). Then bootstrap the
   trust bundle on the GCP box (initial TOFU — the AWS side imports GCP's automatically via
   `crosscloud-bootstrap`, but GCP's import of the AWS bundle is manual):
   `curl -sk https://<aws-ip>:8443 | sudo spire-server bundle set -format spiffe -id spiffe://viaduct.aws`
8. **Verify.** SVIDs issuing (`spire-server entry show`), Vault Agent rendering secrets,
   metrics arriving in Grafana Cloud (all three `node` labels).

### Recovery 
See [Recovery runbook](gcp/RESTORE.md)

### Teardown

Tear the data plane nodes down first, control plane last:

```sh
cd aws && terraform destroy      # then delete the SPIRE CA in AWS KMS (see note)
terraform destroy                # Hetzner (repo root)
cd gcp && terraform destroy      # stops short of the prevent_destroy unseal key + bucket (see note)
```

> - **AWS KMS (SPIRE CA):** not Terraform-managed — after `aws destroy`, run
>   `aws kms schedule-key-deletion` for it or it lingers (~$1/mo).
> - **GCP KMS unseal key + snapshot bucket:** marked `prevent_destroy`, so `terraform destroy`
>   leaves them by design (the GCP destroy won't complete until they're gone). To remove them —
>   which makes any Vault snapshot **permanently unrecoverable** — drop the `lifecycle` blocks
>   or delete them manually via `gcloud`.
>
> Tear the GCP + AWS roots down **before 2026-12-31** to fall back to ~$4.3/mo (Hetzner only).

## Data plane (the service)

Hetzner runs the full VLESS station; AWS runs an egress-capped Conduit relay. Each VLESS user gets **two client URIs** in
`backups/clients/<name>.txt`:

- **Reality** (`*-reality`) — direct to `server-ip:443`, TLS-impersonates `google.com`. Lower latency where the IP is reachable.
- **XHTTP/TLS** (`*-xhttp`) — to `example.com:8443` via Let's Encrypt + HTTP/2. For regions where the IP is blocked but the domain on :8443 is reachable.

Add/revoke users by editing `vless_users` in `terraform.tfvars` and re-running
`terraform apply` (no rebuild — existing users keep their UUIDs). Optional Iran traffic
prioritisation via [KhajuBridge](https://github.com/delejos/conduit-iran-khajubridge)
(nftables; not Terraform-managed — reapply after a rebuild).

## Observability

Every node's **Grafana Alloy** scrapes local exporters and remote-writes to Grafana
Cloud, labelled by node. Conduit usage → the [MoaV dashboard](https://github.com/shayanb/MoaV/blob/main/configs/monitoring/grafana/provisioning/dashboards/conduit.json); VLESS per-user stats →
`dashboards/vless-xray-dashboard.json`; node metrics → Node Exporter (ID 1860). The AWS
egress headroom is sent as `aws_mtd_egress_bytes` / `aws_egress_cap_bytes`. Vault /
SPIRE / k8s telemetry will be monitored on a **separate** dashboard (planned).

## Security notes

- Root CA keys never leave home: Vault PKI (`viaduct.gcp`) and AWS KMS (`viaduct.aws`).
- Secrets reach workloads at runtime via Vault Agent → **tmpfs**, not persistent disk; per-node disjoint secret sets cap lateral reach.
- `backups/` and all `terraform.tfvars` are gitignored — they hold live keys/tokens.
- Xray access log is `none` (no record of user destinations); `geoip:ir` / `geosite:category-ir` are routed to `block` (no proxying back into Iran — removes a fingerprint signal). Port 80 serves a decoy static site (anti-active-probing).

## License

Released under the [MIT License](LICENSE).

## Acknowledgements

- [SPIFFE/SPIRE](https://spiffe.io) — workload identity & attestation
- [HashiCorp Vault](https://www.vaultproject.io) — secrets & PKI
- [k3s](https://k3s.io) — lightweight Kubernetes · [SPIFFE CSI Driver](https://github.com/spiffe/spiffe-csi)
- [Xray-core](https://github.com/XTLS/Xray-core) — VLESS / Reality / XHTTP proxy
- [Psiphon Conduit](https://github.com/Psiphon-Inc/conduit) — in-proxy relay
- [Grafana Alloy](https://github.com/grafana/alloy) — metrics agent · [v2fly](https://github.com/v2fly) geo-routing data

Configuration, scripts and documentation co-authored with [Claude](https://claude.ai) (Anthropic).

## Disclaimer
This repository contains personal infrastructure-as-code for deploy
nodes that could be used to circumvent censorship. Personal infrastructure-as-code, published for
educational and transparency purposes. This is not an operated service — the repository
provides no infrastructure, access, or credentials. Anyone who deploys their own instance
is solely responsible for complying with all applicable laws and regulations.
