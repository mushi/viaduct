# Viaduct operator runbook

Deploy and operate the three-node lab. Architecture and rationale live in the
[README](../README.md); this is the executable sequence. Every step says where it runs and
mints the token it needs before using it. Follow it top to bottom.

## Apply order (read first)

**First deploy:** GCP control plane → bootstrap Vault → Hetzner → AWS → federation. GCP must
be up and its readiness gate returned before the spokes, which authenticate into it.

**Rebuild one node.** A boot-script edit never rebuilds on a plain apply (GCP's startup
script is in instance metadata; Hetzner and AWS keep `user_data` under `ignore_changes`).
Rebuild explicitly:

| Node | Command |
|---|---|
| GCP control plane | `cd gcp && terraform apply -replace=google_compute_instance.controlplane` |
| Hetzner data plane | `terraform apply -replace=hcloud_server.conduit` (repo root) |
| AWS node | `cd aws && terraform apply -replace=aws_instance.spire` |

A GCP rebuild needs no follow-up on the spokes: each fetches GCP Vault's (rotated) cert
fresh over the mesh when it next needs it (Hetzner at boot, AWS at Alloy pod start), so a
cert rotation self-heals. GCP's SPIRE CA is stable across a rebuild (restored from the Vault
snapshot), so federation needs no re-import either.

In-place changes apply normally: add/remove VLESS users or rotate Grafana creds with a
repo-root `terraform apply` (re-runs `scripts/provision.sh`, a few-second service blip, no
rebuild); a GCP change needing an instance stop (`machine_type`, shielded config) adds
`-var 'allow_stopping_for_update=true'`.

## Prerequisites

- Terraform ≥ 1.4; `gcloud` (authed, with `iap.tunnelResourceAccessor`); the `aws` CLI;
  `wg`/`wg-quick`; `uuidgen` and `jq`.
- Accounts: Hetzner, AWS, GCP; a Cloudflare-managed domain; a Grafana Cloud stack.
- Two SSH keypairs (a `deploy` and an `ops` key for Hetzner).

### Account setup

- **Cloudflare:** register a domain, add it to Cloudflare, set its nameservers at your
  registrar. Add an A record `@` → your Hetzner IP, **DNS-only** (grey cloud, not proxied).
  Create an API token (**My Profile → API Tokens**) with `Zone:DNS:Edit` on your zone;
  certbot uses it for DNS-01 issuance.
- **Grafana Cloud:** create a stack; from **Prometheus → Details** note the Remote Write
  endpoint + Username; under **Access Policies** create one scoped to `metrics:write` and
  generate a token; import the dashboards.

## First deploy

### 1. GCP control plane

```sh
cd gcp
cp terraform.tfvars.example terraform.tfvars
# Fill it in. Generate the three AppRole role_ids with:  uuidgen
terraform init && terraform apply
```

Vault comes up sealed and uninitialised; step 2 initialises it. The readiness gate holds the
apply until Vault and SPIRE are up (SPIRE stays down until step 2 configures its Vault role).

### 2. Bootstrap Vault (one-time)

Reach the box over IAP (no public SSH):

```sh
gcloud compute ssh viaduct-controlplane --zone <zone> --project <project> --tunnel-through-iap
```

On the box:

```sh
# Skip-verify is correct here: this is loopback to the co-located Vault (no MITM), and the
# self-signed cert is root-owned so a non-root operator cannot read it. Remote clients verify.
unset VAULT_CACERT   # vault loads it even with skip-verify; clear any lingering value
export VAULT_ADDR=https://127.0.0.1:8200 VAULT_SKIP_VERIFY=true
vault operator init          # STORE the recovery keys AND the root token OFFLINE (e.g. a password manager)
export VAULT_TOKEN=<root-token-from-init>
sudo -E /usr/local/bin/bootstrap-vault.sh
```

`bootstrap-vault.sh` configures KV, the PKI root, the SPIRE/snapshot/cert-refresh AppRoles
(with the role_ids from your tfvars) and their out-of-band secret-ids, cert auth, the
gcp-auth admin/restore/wireguard roles, brings SPIRE and the WireGuard hub up, and revokes
the root token. It is idempotent and safe to re-run.

Then take your standing login and seed the workload secrets. Each node fetches its own set
from Vault via its SPIRE SVID (AWS Alloy, and Hetzner's Grafana + Cloudflare):

```sh
vault login -method=gcp role=admin type=gce      # your login from here on; there is no standing root token
# Scope of this login, and the risks deliberately accepted around it:
# see docs/ACCEPTED-RISKS.md
# This login can seed kv/aws/* and kv/hetzner/*, clear a stale peer registration,
# and read policies — it deliberately cannot create policies, auth roles or mounts.
# Re-provisioning Vault needs a fresh root token: `vault operator generate-root`
# with the recovery keys, which is an explicit and auditable act.
vault kv put kv/aws/grafana        prometheus_url=<url> prometheus_user=<user> api_key=<metrics:write-token>
vault kv put kv/hetzner/grafana    prometheus_url=<url> prometheus_user=<user> api_key=<metrics:write-token>
vault kv put kv/hetzner/cloudflare  api_token=<cloudflare-zone-dns-edit-token>
```

### 3. Hetzner data plane

```sh
cd ..            # repo root
cp terraform.tfvars.example terraform.tfvars
# Fill it in: admin_cidr (your IP /32) and VLESS users. Grafana + Cloudflare secrets are
# NOT here: they come from Vault (step 2), fetched via the node's SVID into tmpfs.
./scripts/get-checksums.sh     # paste its output into terraform.tfvars
terraform init && terraform apply
```

The provisioner attests the SPIRE agent to GCP, then joins the node to the WireGuard mesh
(both over IAP), then starts the data-plane services.

### 4. AWS node

```sh
cd aws
cp terraform.tfvars.example terraform.tfvars    # set gcp_control_plane_ip (+ gcp_project)
terraform init && terraform apply
```

The provisioners join AWS to the mesh and sync GCP Vault's cert fingerprint live over IAP +
SSM (no pinned fingerprint to maintain). The `aws-vault-agent` cert role on GCP Vault is
created automatically by `federation-sync`.

> **Deployment-identity IAM.** The AWS mesh-join provisioner (`aws/wireguard.tf`) runs SSM
> Run Command on the box and relays the peer PSK through an SSM SecureString. So the identity
> running `aws/` apply needs, beyond resource CRUD: `ssm:SendCommand` +
> `ssm:GetCommandInvocation`; and for the PSK only, `ssm:PutParameter`/`DeleteParameter`
> (scoped to `wg_psk_parameter`, default `/viaduct/wg/aws-psk`) plus `kms:Encrypt`/
> `GenerateDataKey` conditioned on `kms:ViaService = ssm.<region>.amazonaws.com`. The
> instance's own PSK read-back is Terraform-managed; only this deploy-identity half is a
> manual one-time attach.

### 5. Complete federation

Set `aws_spire_ip = "10.99.0.3"` (the AWS node's mesh address) in `gcp/terraform.tfvars`,
then:

```sh
cd gcp && terraform apply
```

Both directions import automatically over the mesh (`:8443`): AWS imports GCP's bundle via
`crosscloud-bootstrap`, and `federation-sync` re-pushes the AWS bundle to GCP on every AWS
(re)build.

### 6. (Optional) Join the mesh from your operator computer

Gives you Vault, SPIRE, and Hetzner admin over `wg0` instead of public paths.

1. Generate a keypair and register the public key with the hub over IAP. The register
   command prints the hub public key and a PSK:

   ```sh
   umask 077; wg genkey | tee operator.key | wg pubkey > operator.pub
   gcloud compute ssh viaduct-controlplane --zone <zone> --project <project> --tunnel-through-iap \
     --command "sudo /usr/local/bin/wg-register-peer.sh operator $(cat operator.pub) 10.99.0.4"
   # prints:  hub_public_key <HUB_PUB>
   #          psk            <PSK>
   ```

2. Create `/etc/wireguard/wg0.conf` locally, filling in your private key (the contents of
   `operator.key`) and the `<HUB_PUB>` / `<PSK>` from that output:

   ```ini
   [Interface]
   Address = 10.99.0.4/32
   PrivateKey = <contents of operator.key>

   [Peer]
   PublicKey = <HUB_PUB>
   PresharedKey = <PSK>
   Endpoint = <GCP public IP>:51820
   AllowedIPs = 10.99.0.0/24
   PersistentKeepalive = 25
   ```

3. Bring it up: `sudo wg-quick up wg0` (tear down with `sudo wg-quick down wg0`). The peer
   registration persists in Vault, so it survives a hub rebuild.

### 7. Verify

- SVIDs issuing: on GCP, `sudo spire-server entry show`.
- Federation: `sudo spire-server bundle list | grep viaduct.aws`.
- AWS Alloy healthy: over SSM, `sudo k3s kubectl -n viaduct get pods` (Alloy `Running`).
- Metrics arriving in Grafana Cloud under all three `node` labels.
- Vault reachable + verified over the mesh. The listener cert is self-signed and
  **regenerated on every GCP rebuild**, so pull the current one first, then verify (no
  `-k`):
  ```sh
  gcloud compute ssh viaduct@viaduct-controlplane --zone <zone> --project <project> \
    --tunnel-through-iap --ssh-key-file=~/.ssh/viaduct_lab \
    --command 'sudo cat /opt/vault/tls/vault.crt' > ~/vault.crt
  curl --cacert ~/vault.crt https://10.99.0.1:8200/v1/sys/health   # sealed:false, initialized:true
  ```

## Recovery

**Automatic.** A GCP `-replace` restores Vault and SPIRE from the latest GCS snapshot on
first boot; a fresh backup is taken just before the old instance is destroyed, and the
readiness gate holds the apply until Vault is unsealed and SPIRE is active. No manual steps.

A rebuild regenerates the Vault listener cert (new key, same SANs), so any locally cached
`~/vault.crt` goes stale: re-pull it (see step 7) for local verification, and run the
refresh-AWS-after-a-GCP-rebuild apply from the [apply-order](#apply-order-read-first) rules
so the AWS side re-syncs the new fingerprint.

`vault-snapshot.service` writes `vault.snap` (Vault Raft) and `spire-data.tar.gz` (SPIRE
datastore + `keys.json`) to the bucket, weekly on a timer and once more just before every
replace. The bucket keeps the last 3 versions of each object.

**Break-glass (only if the automatic restore fails).** Reach the box over IAP and run the
same sequence as the [restore block in `startup.sh`](../gcp/scripts/startup.sh#L136)
(the `6a. Restore` section), authenticating after the restore with your **offline** recovery
keys (the temporary init token is invalidated by the restore). Do not run
`vault operator init` and stop there: that forks a new empty Vault instead of restoring.

## Teardown

Tear the data-plane nodes down first, control plane last:

```sh
cd aws && terraform destroy      # then delete the SPIRE CA in AWS KMS (see note)
terraform destroy                # Hetzner (repo root)
cd gcp && terraform destroy      # stops short of the prevent_destroy unseal key + bucket (see note)
```

- **AWS KMS (SPIRE CA):** not Terraform-managed. After `aws destroy`, run
  `aws kms schedule-key-deletion` or it lingers (~$1/mo).
- **GCP KMS unseal key + snapshot bucket:** `prevent_destroy`, so `terraform destroy` leaves
  them by design (the destroy will not complete until they are gone). Removing them makes any
  Vault snapshot **permanently unrecoverable**: drop the `lifecycle` blocks or delete via
  `gcloud`.
- Tear the GCP + AWS roots down **before 2026-12-31** to fall back to ~$4.3/mo (Hetzner only; main branch).
