#!/usr/bin/env bash
# Fetch Hetzner's Grafana + Cloudflare secrets from GCP Vault into tmpfs, using this
# node's SPIRE SVID (cert auth) over the WireGuard mesh. One-shot: run at boot before
# Alloy and certbot, and re-run to pick up rotated secrets. Mirrors the AWS Alloy
# startup fetch. No secret ever touches persistent disk.
#
# Runs as the dedicated `viaduct-secrets` user, so the SPIRE Workload API attests it by
# unix:uid and issues only the spiffe://viaduct.gcp/hetzner/vault-agent SVID. That SVID
# cert-auths to Vault as hetzner-vault-agent, scoped to kv/hetzner/*.
set -euo pipefail

# Mesh preconditions for the trust-on-first-use fetch below. See the comments in the
# library: After=wg-quick@wg0.service orders unit start, not peer authentication.
# shellcheck source=scripts/lib/mesh-trust.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/mesh-trust.sh"

SPIRE_SOCK="/run/spire-agent/public/api.sock"
HUB_MESH_IP="10.99.0.1"                 # GCP hub over wg0
VAULT_ADDR="https://${HUB_MESH_IP}:8200"
RUN="/run/hetzner-secrets"              # tmpfs (RAM), group-readable by alloy
SVID="$RUN/svid"
CACERT="$RUN/vault-ca.crt"

umask 077
mkdir -p "$SVID"

# 1. SVID from the SPIRE agent Workload API (attested by this process's uid). Retry:
#    after a reboot the agent may still be attesting to the server when this fires,
#    returning "Unavailable"; wait for it (up to ~60s) so reboots self-heal.
for attempt in $(seq 1 12); do
  /usr/local/bin/spire-agent api fetch x509 -socketPath "$SPIRE_SOCK" -write "$SVID" >/dev/null 2>&1 && break
  [ "$attempt" = 12 ] && { echo "ERROR: SVID fetch failed after retries (spire-agent not ready / mesh down?)"; exit 1; }
  sleep 5
done

# 2. GCP Vault's CURRENT listener cert, fetched over the mesh. WireGuard authenticates
#    that ${HUB_MESH_IP} is the GCP hub, so this trust-on-first-use is sound and always
#    reflects the current cert (which rotates on a GCP rebuild) — but only once a peer
#    handshake has actually happened. systemd's After=wg-quick@wg0.service does not
#    guarantee that, so wait for it explicitly, then fail closed on a certificate that
#    cannot be the hub's.
vh_wait_for_mesh_handshake "$HUB_MESH_IP" wg0 60 || exit 1
openssl s_client -connect "${HUB_MESH_IP}:8200" </dev/null 2>/dev/null | openssl x509 > "$CACERT"
vh_verify_cert_san "$CACERT" "$HUB_MESH_IP" || exit 1

# 3. Cert-auth to Vault with the SVID (role hetzner-vault-agent, scoped to kv/hetzner/*).
#    Uses the Vault HTTP API via curl + jq, so the data-plane box needs no Vault binary.
vapi() { curl -sf --cacert "$CACERT" "$@"; }
TOKEN="$(vapi --cert "$SVID/svid.0.pem" --key "$SVID/svid.0.key" \
  --request POST --data '{"name":"hetzner-vault-agent"}' \
  "$VAULT_ADDR/v1/auth/cert/login" | jq -r '.auth.client_token')"
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || { echo "ERROR: Vault cert-auth failed"; exit 1; }

kv() { vapi -H "X-Vault-Token: $TOKEN" "$VAULT_ADDR/v1/kv/data/hetzner/$1" | jq -r ".data.data.$2"; }

# 4. Render Grafana creds (Alloy EnvironmentFile) and the Cloudflare token (certbot ini).
#    Group alloy is inherited from the setgid dir; alloy reads grafana.env, root reads the ini.
#
#    These four values go unescaped into two config-file sinks. grafana.env is a
#    systemd EnvironmentFile, so a newline in a value declares a further variable;
#    cloudflare.ini is parsed the same way by certbot. Validate before rendering and
#    refuse rather than write something unintended — the AWS side of this same data
#    is guarded identically in aws/k8s/20-alloy.yaml.
vh_reject() {
  echo "ERROR: $1 from Vault is empty or carries characters that would add a" >&2
  echo "       directive to the rendered file; refusing to render." >&2
  exit 1
}
vh_check() {  # name value extended-regex
  [ -n "$2" ] || vh_reject "$1"
  # grep is line-oriented, so a multi-line value could satisfy it line by line
  # while still injecting. Reject those before the pattern is applied at all.
  [ "$(printf '%s' "$2" | wc -l)" -eq 0 ] || vh_reject "$1"
  printf '%s' "$2" | grep -qE "$3" || vh_reject "$1"
}

GRAFANA_URL_V="$(kv grafana prometheus_url)"
GRAFANA_USER_V="$(kv grafana prometheus_user)"
GRAFANA_KEY_V="$(kv grafana api_key)"
CF_TOKEN_V="$(kv cloudflare api_token)"

vh_check prometheus_url  "$GRAFANA_URL_V"  '^https://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+$'
vh_check prometheus_user "$GRAFANA_USER_V" '^[A-Za-z0-9._@-]+$'
vh_check api_key         "$GRAFANA_KEY_V"  '^[A-Za-z0-9._=+/-]+$'
vh_check cf_api_token    "$CF_TOKEN_V"     '^[A-Za-z0-9._-]+$'

{
  printf 'GRAFANA_URL=%s\n'  "$GRAFANA_URL_V"
  printf 'GRAFANA_USER=%s\n' "$GRAFANA_USER_V"
  printf 'GRAFANA_KEY=%s\n'  "$GRAFANA_KEY_V"
} > "$RUN/grafana.env"

printf 'dns_cloudflare_api_token = %s\n' "$CF_TOKEN_V" > "$RUN/cloudflare.ini"

# Alloy reads grafana.env, so that one keeps the group. certbot runs as root and is
# the only consumer of the Cloudflare token — a token that can create DNS records
# for the zone, so the alloy group has no business holding it.
chmod 0640 "$RUN/grafana.env"
chmod 0600 "$RUN/cloudflare.ini"

# 5. Do not leave the SVID key or the fetched cert lying in tmpfs after use.
unset TOKEN
rm -rf "$SVID" "$CACERT"
echo "[fetch-hetzner-secrets] rendered grafana.env + cloudflare.ini in $RUN"
