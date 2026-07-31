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

vault policy write admin - <<'EOF'
path "sys/*"  { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }
path "auth/*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }
path "kv/*"   { capabilities = ["create", "read", "update", "delete", "list"] }
path "pki/*"  { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }
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

vault policy write wireguard-hub - <<'EOF'
path "kv/data/wireguard/*"     { capabilities = ["create", "read", "update"] }
path "kv/metadata/wireguard/*" { capabilities = ["read", "list"] }
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
/usr/local/bin/spire-server bundle show -format pem > /tmp/gcp-root.pem
vault write auth/cert/certs/hetzner-vault-agent \
  display_name=hetzner-vault-agent policies=hetzner-vault-agent \
  certificate=@/tmp/gcp-root.pem \
  allowed_uri_sans="spiffe://${TRUST_DOMAIN}/hetzner/vault-agent" \
  token_ttl=20m token_max_ttl=1h >/dev/null
rm -f /tmp/gcp-root.pem
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
