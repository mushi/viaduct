#!/usr/bin/env bash
# bootstrap-vault.sh, one-time Vault + SPIRE operator setup, automated.
#
# Run ONCE on the GCP box after `vault operator init`, with VAULT_TOKEN set to the
# init root token. It reproduces the whole manual Vault setup: KV, PKI root, the
# SPIRE/snapshot/cert-refresh AppRoles (with the role_ids you chose in tfvars),
# their out-of-band secret-ids, cert auth, the gcp-auth admin/restore/wireguard
# roles, and finally revokes the root token. Idempotent and safe to re-run.
#
# The only operator steps left around it: `vault operator init` (store the recovery keys
# offline) before, and seeding the workload secrets after (kv/aws/grafana,
# kv/hetzner/grafana, kv/hetzner/cloudflare), which the nodes fetch via their SVIDs.
set -euo pipefail
export PATH="/snap/bin:$PATH"

md() { curl -sf -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/$1"; }
log() { echo "[bootstrap-vault] $*"; }

# Loopback to the co-located Vault. Skip TLS verification: on 127.0.0.1 there is no MITM
# to defend against, and the self-signed cert is root-owned (not readable by a non-root
# operator running this). Remote clients (agents, cross-cloud) still verify the cert.
# Unset any inherited VAULT_CACERT: vault tries to load it even with skip-verify set.
unset VAULT_CACERT
export VAULT_ADDR="https://127.0.0.1:8200" VAULT_SKIP_VERIFY="true"
: "${VAULT_TOKEN:?export VAULT_TOKEN (the init root token) first}"
command -v jq >/dev/null || { echo "jq required"; exit 1; }

PROJECT="$(md project/project-id)"
ZONE="$(md instance/zone | sed 's|.*/||')"
SA_EMAIL="$(md instance/service-accounts/default/email)"
TRUST_DOMAIN="$(md instance/attributes/trust-domain)"
SPIRE_ROLE_ID="$(md instance/attributes/spire-approle-role-id)"
SNAPSHOT_ROLE_ID="$(md instance/attributes/snapshot-approle-role-id)"
CERTROLE_ROLE_ID="$(md instance/attributes/aws-certrole-approle-role-id)"
: "${SPIRE_ROLE_ID:?spire_approle_role_id must be set in tfvars (generate with uuidgen)}"
: "${SNAPSHOT_ROLE_ID:?snapshot_approle_role_id must be set in tfvars (generate with uuidgen)}"

has() { vault "$1" list -format=json 2>/dev/null | jq -e --arg k "$2" 'has($k)' >/dev/null 2>&1; }

# ── Audit devices ─────────────────────────────────────────────────────────────
# Enabled FIRST, so everything this script then does is on the record — including
# the root-token operations and the revoke at the end.
#
# Two devices, deliberately. Vault fails a request only when EVERY enabled device
# fails to write, so a single file device turns a full /var/log into a Vault
# outage. With syslog alongside it, a disk problem degrades to "one device is
# failing" instead of "Vault refuses requests". The file device is the one to read
# for forensics; syslog is the availability backstop (and reaches journald, so it
# survives the disk filling).
#
# `has audit` keys on the device path, which is "file/" and "syslog/".
has audit "file/"   || vault audit enable file file_path=/var/log/vault/audit.log
has audit "syslog/" || vault audit enable syslog tag=vault facility=AUTH
log "audit devices ready (file + syslog)"

# ── KV v2 ─────────────────────────────────────────────────────────────────────
has secrets "kv/" || vault secrets enable -path=kv kv-v2
log "KV ready"

# ── PKI root (GUARD: never regenerate an existing root, it would invalidate
#    every issued SVID) ──────────────────────────────────────────────────────────
has secrets "pki/" || vault secrets enable -max-lease-ttl=87600h pki
if vault read pki/cert/ca >/dev/null 2>&1 && [ -n "$(vault read -field=certificate pki/cert/ca 2>/dev/null)" ]; then
  log "PKI root already present, not regenerating"
else
  vault write -field=certificate pki/root/generate/internal \
    common_name="Viaduct Root CA" issuer_name="viaduct-root" ttl=87600h >/dev/null
  log "PKI root generated"
fi

# ── AppRoles + policies + custom role_ids (set from tfvars, no read-back) ──────
has auth "approle/" || vault auth enable approle

vault policy write spire-upstream - <<'EOF'
path "pki/root/sign-intermediate" { capabilities = ["update"] }
EOF
vault write auth/approle/role/spire-server \
  token_policies=spire-upstream token_period=20m \
  secret_id_bound_cidrs=127.0.0.1/32 token_bound_cidrs=127.0.0.1/32
vault write auth/approle/role/spire-server/role-id role_id="$SPIRE_ROLE_ID" >/dev/null

vault policy write snapshot - <<'EOF'
path "sys/storage/raft/snapshot" { capabilities = ["read"] }
EOF
vault write auth/approle/role/snapshot-saver \
  token_policies=snapshot token_period=20m \
  secret_id_bound_cidrs=127.0.0.1/32 token_bound_cidrs=127.0.0.1/32
vault write auth/approle/role/snapshot-saver/role-id role_id="$SNAPSHOT_ROLE_ID" >/dev/null

vault policy write aws-certrole-refresh - <<'EOF'
path "auth/cert/certs/aws-vault-agent" { capabilities = ["create", "update"] }
EOF
vault write auth/approle/role/aws-certrole-refresh \
  token_policies=aws-certrole-refresh token_ttl=5m token_max_ttl=30m \
  secret_id_bound_cidrs=127.0.0.1/32 token_bound_cidrs=127.0.0.1/32
[ -n "$CERTROLE_ROLE_ID" ] && vault write auth/approle/role/aws-certrole-refresh/role-id role_id="$CERTROLE_ROLE_ID" >/dev/null
log "AppRoles + role_ids set"

# ── Secret-ids → 0600 files (GUARD: only mint if absent, so re-runs are no-ops) ─
if [ ! -s /opt/spire/conf/server/spire.env ]; then
  SID="$(vault write -f -field=secret_id auth/approle/role/spire-server/secret-id)"
  install -o spire -g spire -m 0600 /dev/null /opt/spire/conf/server/spire.env
  echo "VAULT_APPROLE_SECRET_ID=$SID" > /opt/spire/conf/server/spire.env
  unset SID
  log "spire-server secret-id placed"
fi
mkdir -p /opt/vault-snapshot /opt/vault-certrole
chmod 0700 /opt/vault-snapshot /opt/vault-certrole
[ -s /opt/vault-snapshot/secret-id ] || {
  vault write -f -field=secret_id auth/approle/role/snapshot-saver/secret-id > /opt/vault-snapshot/secret-id
  chmod 0600 /opt/vault-snapshot/secret-id; }
[ -s /opt/vault-certrole/secret-id ] || {
  vault write -f -field=secret_id auth/approle/role/aws-certrole-refresh/secret-id > /opt/vault-certrole/secret-id
  chmod 0600 /opt/vault-certrole/secret-id; }
log "secret-ids in place"

# ── cert auth + policies (aws-workload is referenced by the auto-managed
#    aws-vault-agent cert role that federation-sync creates) ─────────────────────
has auth "cert/" || vault auth enable cert
vault policy write hetzner-vault-agent - <<'EOF'
path "kv/data/hetzner/*" { capabilities = ["read"] }
EOF
vault policy write aws-workload - <<'EOF'
path "kv/data/aws/*" { capabilities = ["read"] }
EOF
log "cert-auth policies ready"

# ── gcp auth: operator admin + restore-agent + wireguard-hub roles ────────────
has auth "gcp/" || vault auth enable gcp

# The role below is bound to the instance's own service account, and any local uid on
# the hub can reach the GCE metadata server — so this token is obtainable by anything
# running on the box. Narrowing does not change who can obtain it; it changes what it
# can do, and that only helps if the surviving grants cannot rebuild the lost ones.
#
# An earlier narrowing left `sys/policies/acl/*` create/update and `auth/gcp/role/*`
# create/update in place. Together those are a complete escalation: write an
# unrestricted policy, bind a new gcp role to this same service account, log in
# again. The narrowing was therefore cosmetic. Neither is needed at steady state —
# every mount, auth method, policy, role and the PKI root is provisioned above under
# the init root token, before it is revoked. Re-provisioning needs a deliberately
# generated root token (`vault operator generate-root`), which is the point: it is an
# explicit, auditable act rather than something any local uid can mint from metadata.
#
# What is left is the operator surface RUNBOOK.md actually documents: seeding the
# workload secrets, clearing a stale peer registration, and read-only introspection.
vault policy write admin - <<'EOF'
# Seeding and rotating the workload secrets (RUNBOOK.md "Vault bootstrap").
path "kv/data/aws/*"             { capabilities = ["create", "read", "update", "delete"] }
path "kv/data/hetzner/*"         { capabilities = ["create", "read", "update", "delete"] }
path "kv/metadata/aws/*"         { capabilities = ["read", "list", "delete"] }
path "kv/metadata/hetzner/*"     { capabilities = ["read", "list", "delete"] }

# Clearing a stale peer registration is the documented recovery for a rebuilt spoke
# whose key changed. kv/data/wireguard/hub is deliberately absent: that is the hub's
# own WireGuard private key, and only the hub's role has any business reading it.
path "kv/data/wireguard/peers/*"     { capabilities = ["read", "delete"] }
path "kv/metadata/wireguard/peers/*" { capabilities = ["read", "list", "delete"] }
path "kv/metadata/wireguard"         { capabilities = ["list"] }

# Read-only introspection: see what is mounted and which policies exist, change
# neither. A `read` on sys/policies/acl/* is what makes an audit possible; the
# create/update that made it an escalation is gone.
path "sys/mounts"            { capabilities = ["read", "list"] }
path "sys/auth"              { capabilities = ["read", "list"] }
path "sys/policies/acl"      { capabilities = ["list"] }
path "sys/policies/acl/*"    { capabilities = ["read"] }
path "auth/approle/role"     { capabilities = ["list"] }
path "auth/cert/certs"       { capabilities = ["list"] }
path "auth/gcp/role"         { capabilities = ["list"] }

# PKI: inspect the issued chain. Root generation stays with the root token.
path "pki/cert/*"            { capabilities = ["read", "list"] }
EOF
vault write auth/gcp/role/admin type=gce project_id="$PROJECT" bound_zones="$ZONE" \
  bound_service_accounts="$SA_EMAIL" policies=admin token_ttl=20m token_max_ttl=2h >/dev/null

vault policy write restore-secret-ids - <<'EOF'
path "auth/approle/role/spire-server/secret-id"         { capabilities = ["create", "update"] }
path "auth/approle/role/snapshot-saver/secret-id"       { capabilities = ["create", "update"] }
path "auth/approle/role/aws-certrole-refresh/secret-id" { capabilities = ["create", "update"] }
EOF
vault write auth/gcp/role/restore-agent type=gce project_id="$PROJECT" bound_zones="$ZONE" \
  bound_service_accounts="$SA_EMAIL" policies=restore-secret-ids token_ttl=5m token_max_ttl=10m >/dev/null

# Split the peer registry from the hub's own key. A blanket kv/data/wireguard/* grant
# let a token from this role replace kv/wireguard/hub — the hub's WireGuard private key —
# and take over the mesh, rather than merely registering spokes. startup.sh:400 notes the
# hub key is generated once then only fetched, and the write at :477 runs only when it is
# absent, so create+read is sufficient there.
vault policy write wireguard-hub - <<'EOF'
path "kv/data/wireguard/peers/*"     { capabilities = ["create", "read", "update"] }
path "kv/data/wireguard/hub"         { capabilities = ["create", "read"] }
path "kv/metadata/wireguard/*"       { capabilities = ["read", "list"] }
EOF
vault write auth/gcp/role/wireguard-hub type=gce project_id="$PROJECT" bound_zones="$ZONE" \
  bound_service_accounts="$SA_EMAIL" policies=wireguard-hub token_ttl=5m token_max_ttl=10m >/dev/null
log "gcp-auth roles ready"

# ── Converge the box now that Vault is configured. On a FIRST bootstrap the mesh
#    is down (startup §8 deferred wg0 while the wireguard-hub role was absent) and
#    spire-server is crash-looping without its secret-id, so re-run startup: it
#    brings up wg0 and restarts spire-server, and skips the restore path because
#    Vault is now initialised. On a re-run (mesh already up) skip it, nothing to
#    converge, and we avoid needlessly restarting Vault/SPIRE. ─────────────────────
if ! wg show wg0 >/dev/null 2>&1; then
  log "First bootstrap: re-running startup to bring up SPIRE + the WireGuard hub..."
  google_metadata_script_runner startup
fi

# ── cert role for the Hetzner Vault Agent (needs the SPIRE bundle; spire-server is
#    healthy after the startup re-run above) ─────────────────────────────────────
for _ in $(seq 1 30); do /usr/local/bin/spire-server healthcheck >/dev/null 2>&1 && break; sleep 2; done
/usr/local/bin/spire-server healthcheck >/dev/null 2>&1 || { log "ERROR: spire-server not healthy"; exit 1; }
# Same class as the fixed /tmp paths removed from startup.sh: the bundle itself is
# public, so there is nothing to disclose, but a fixed name written by root in a
# world-writable directory can be pre-created as a symlink and redirect the write.
GCP_ROOT_PEM="$(umask 077; mktemp /tmp/gcp-root.XXXXXXXX)"
/usr/local/bin/spire-server bundle show -format pem > "$GCP_ROOT_PEM"
vault write auth/cert/certs/hetzner-vault-agent \
  display_name=hetzner-vault-agent policies=hetzner-vault-agent \
  certificate=@"$GCP_ROOT_PEM" \
  allowed_uri_sans="spiffe://${TRUST_DOMAIN}/hetzner/vault-agent" \
  token_ttl=20m token_max_ttl=1h >/dev/null
rm -f "$GCP_ROOT_PEM"
log "hetzner-vault-agent cert role ready"

log "Bootstrap complete. Seed the workload secrets (this script revoked root and cleared"
log "its Vault env, so log in fresh):"
log ""
log "  unset VAULT_CACERT   # vault loads it even with skip-verify; clear any lingering value"
log "  export VAULT_ADDR=https://127.0.0.1:8200 VAULT_SKIP_VERIFY=true"
log "  vault login -method=gcp role=admin type=gce"
log "  vault kv put kv/aws/grafana        prometheus_url=<url> prometheus_user=<user> api_key=<metrics:write-token>"
log "  vault kv put kv/hetzner/grafana    prometheus_url=<url> prometheus_user=<user> api_key=<metrics:write-token>"
log "  vault kv put kv/hetzner/cloudflare  api_token=<cloudflare-zone-dns-edit-token>"

# ── Revoke the init root token, only when running AS root, and only after the
#    admin gcp-auth login is proven to work (so you are never locked out). ────────
if vault token lookup -format=json 2>/dev/null | jq -e '.data.policies | index("root")' >/dev/null 2>&1; then
  if vault login -method=gcp -token-only role=admin type=gce >/dev/null 2>&1; then
    vault token revoke -self
    log "Root token revoked. Log in from now on with: vault login -method=gcp role=admin type=gce"
  else
    log "WARNING: admin gcp-auth login did not verify, leaving the root token intact. Investigate before revoking."
  fi
fi
