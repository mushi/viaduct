# GCP control plane — manual first-time Vault + SPIRE bootstrap

One-time manual operator setup, run **after the first `terraform apply`** of the `gcp/` root.
`startup.sh` installs and configures Vault (Raft + GCP KMS auto-unseal) and SPIRE
server, but Vault comes up **sealed + uninitialised** and SPIRE can't reach its
UpstreamAuthority until the steps below exist. For *rebuild* recovery (Vault already
initialised once), use [`RESTORE.md`](RESTORE.md) instead.

All commands run on the GCP box over SSH (`viaduct@<ip>`).

## 1. Initialise Vault → recovery keys offline

```sh
export VAULT_ADDR=https://127.0.0.1:8200 VAULT_SKIP_VERIFY=true
vault operator init
```

With KMS auto-unseal, `init` emits **recovery keys** (not Shamir unseal keys) and an
**initial root token**. Store *all* of them offline (e.g. in a password manager) — the recovery keys are
the only way to `operator generate-root` or rekey later; there is no other copy.
Vault auto-unseals via KMS from here on; you never enter an unseal key at boot.

Authenticate for the rest of this runbook (kept out of shell history):

```sh
read -rsp 'VAULT_TOKEN: ' VAULT_TOKEN; export VAULT_TOKEN; echo   # the init root token
```

## 2. KV v2 (secrets store)

```sh
vault secrets enable -path=kv kv-v2
```

## 3. PKI root (SPIRE's UpstreamAuthority)

SPIRE's CA chains to this Vault PKI root, so `viaduct.gcp` SVIDs are Vault-rooted.

```sh
vault secrets enable -max-lease-ttl=87600h pki
vault write -field=certificate pki/root/generate/internal \
  common_name="Viaduct Root CA" issuer_name="viaduct-root" ttl=87600h > /dev/null
```

## 4. AppRoles (SPIRE server + snapshot job)

Both consumers auth to Vault by AppRole. `startup.sh` reads each **role-id** from
instance metadata (Terraform vars) and each **secret-id** from a `0600` file placed
out-of-band — secret-ids never go in tfvars/metadata.

> Why AppRole and not GCP IAM auth (which would need no secret-id on a GCE box)? SPIRE's
> Vault UpstreamAuthority plugin only supports **token / cert / AppRole / k8s** auth — not
> `gcp`. AppRole is the closest fit for a non-k8s host.

```sh
vault auth enable approle

# SPIRE server — may sign its intermediate against the PKI root.
# Bound to localhost (SPIRE server shares this box with Vault); periodic token auto-renews.
vault policy write spire-upstream - <<'EOF'
path "pki/root/sign-intermediate" { capabilities = ["update"] }
EOF
vault write auth/approle/role/spire-server \
  token_policies=spire-upstream token_period=20m \
  secret_id_bound_cidrs=127.0.0.1/32 token_bound_cidrs=127.0.0.1/32

# snapshot job — read-only access to take a Raft snapshot
vault policy write snapshot - <<'EOF'
path "sys/storage/raft/snapshot" { capabilities = ["read"] }
EOF
vault write auth/approle/role/snapshot-saver \
  token_policies=snapshot token_period=20m \
  secret_id_bound_cidrs=127.0.0.1/32 token_bound_cidrs=127.0.0.1/32

# role-ids → back into Terraform; secret-ids → onto disk (this boot only)
vault read -field=role_id auth/approle/role/spire-server/role-id      # -> tfvars spire_approle_role_id
vault read -field=role_id auth/approle/role/snapshot-saver/role-id    # -> tfvars snapshot_approle_role_id
```

Put the two **role-ids** in `gcp/terraform.tfvars` (`spire_approle_role_id`,
`snapshot_approle_role_id`) and `terraform apply` again so they reach instance metadata.
Then mint and place the **secret-ids** (these live only on the host, not in Terraform):

```sh
# SPIRE server secret-id -> /opt/spire/conf/server/spire.env (0600 spire)
SID=$(vault write -f -field=secret_id auth/approle/role/spire-server/secret-id)
sudo install -o spire -g spire -m 0600 /dev/null /opt/spire/conf/server/spire.env
echo "VAULT_APPROLE_SECRET_ID=$SID" | sudo tee /opt/spire/conf/server/spire.env > /dev/null

# snapshot secret-id -> /opt/vault-snapshot/secret-id (raw value, 0600 root)
vault write -f -field=secret_id auth/approle/role/snapshot-saver/secret-id \
  | sudo tee /opt/vault-snapshot/secret-id > /dev/null
sudo chmod 0600 /opt/vault-snapshot/secret-id
unset SID
```

> **Refresh `server.conf`.** `startup.sh` bakes the SPIRE `approle_id` into
> `/opt/spire/conf/server/server.conf` from instance metadata, but only **on boot** — the
> metadata change above plus a `systemctl restart` will *not* pick up the new role-id. Re-run
> the startup script so `server.conf` is regenerated (this also restarts `spire-server`):
>
> ```sh
> sudo google_metadata_script_runner startup
> ```
>
> A reboot does the same — `startup.sh` is idempotent and Vault auto-unseals via KMS.

## 5. cert auth (workloads, by SVID)

The Hetzner Vault Agent authenticates with its SPIRE SVID, scoped by the SPIFFE URI SAN.
The trust anchor is the `viaduct.gcp` SPIRE bundle.

```sh
sudo /usr/local/bin/spire-server bundle show -format pem > /tmp/gcp-root.pem
vault auth enable cert
vault policy write hetzner-vault-agent - <<'EOF'
path "kv/data/hetzner/*" { capabilities = ["read"] }
EOF
vault write auth/cert/certs/hetzner-vault-agent \
  display_name=hetzner-vault-agent policies=hetzner-vault-agent \
  certificate=@/tmp/gcp-root.pem \
  allowed_uri_sans="spiffe://viaduct.gcp/hetzner/vault-agent" \
  token_ttl=20m token_max_ttl=1h
rm -f /tmp/gcp-root.pem
```

> The **AWS** node's cross-cloud cert role (`aws-vault-agent`, trusting the federated
> `viaduct.aws` root) is created after federation — see
> [`../aws/k8s/README.md`](../aws/k8s/README.md).

## 6. Seed secrets + verify

```sh
vault kv put kv/hetzner/grafana \
  prometheus_url='<grafana_cloud_prometheus_url>' \
  prometheus_user='<grafana_cloud_prometheus_user>' \
  api_key='<grafana_cloud_metrics:write_token>'

# Cloudflare API token for certbot DNS-01 issuance (Hetzner reads it via Vault Agent)
vault kv put kv/hetzner/cloudflare api_token='<cloudflare_zone_dns_edit_token>'

# spire-server was already restarted by the startup re-run in §4; confirm it's healthy
sudo /usr/local/bin/spire-server healthcheck
sudo systemctl start vault-snapshot.service   # verify the first snapshot lands in GCS
```

## 7. Operator admin via GCP auth, then revoke the root token

Replace the standing root token with a short-lived **admin** token the operator gets from
the box's own GCE instance identity — nothing to store. (Vault's `gcp` auth works fine for
this even though SPIRE's UpstreamAuthority can't use it — that limit is SPIRE-plugin-specific,
see §4.)

Prereq (all in `gcp/main.tf`, applied by your admin/Terraform identity — not the box SA):
the `compute`, `iam`, and `cloudresourcemanager` APIs enabled (`google_project_service.required`),
and the instance SA granted **`roles/compute.viewer`** (`compute.instances.get`) +
**`roles/iam.serviceAccountViewer`** (`iam.serviceAccounts.get`) so Vault's `gcp` backend can
read the calling instance and resolve its service account.

```sh
# near-root admin policy (true root is regenerable from recovery keys if ever needed)
vault policy write admin - <<'EOF'
path "sys/*"  { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }
path "auth/*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }
path "kv/*"   { capabilities = ["create", "read", "update", "delete", "list"] }
path "pki/*"  { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }
EOF

# operator logs in by the box's GCE instance identity (no key/secret on disk)
vault auth enable gcp 2>/dev/null || true
vault write auth/gcp/role/admin type=gce \
  project_id=<project-id> \
  bound_zones=<zone> \
  bound_service_accounts=<controlplane-sa-email> \
  policies=admin token_ttl=20m token_max_ttl=2h
```

Test from a **fresh shell** (don't lean on the cached root token), and confirm the admin
token can do real work **before** revoking root:

```sh
vault login -method=gcp role=admin type=gce
vault policy list && vault secrets list && vault auth list
```

Then revoke the standing root token (the one from §1):

```sh
vault token revoke <init-root-token>
```

Root tokens have no TTL — don't keep one standing. Break-glass: `vault operator generate-root`
with the offline recovery keys.

> Binding `admin` to the instance SA means anyone with **root on the box** can obtain Vault
> admin — not a new escalation (box-root already controls Vault's memory/unseal). For a
> separate operator principal, bind to your gcloud user via the `iam` type instead.
