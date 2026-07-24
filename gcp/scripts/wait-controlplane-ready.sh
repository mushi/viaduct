#!/usr/bin/env bash
# Poll the GCP control-plane instance over IAP until Vault is unsealed and the
# SPIRE server is active, then print a confirmation. Invoked by
# null_resource.controlplane_ready so `terraform apply` blocks until the control
# plane is genuinely ready, rather than returning when the instance resource is
# merely created/modified. Read-only: it never changes the instance.
#
# Behaviour:
#   - Vault up but not initialised (first deploy): report and exit 0, since the
#     operator must run `vault operator init` manually before it can unseal.
#   - Vault unsealed + SPIRE server active: print the ready line and exit 0.
#   - Neither, until the timeout: exit 1 with what was last seen.
set -euo pipefail

: "${GCP_INSTANCE:?}"
: "${GCP_ZONE:?}"
: "${GCP_SSH_USER:?}"
: "${GCP_SSH_KEY_PATH:?}"

command -v gcloud >/dev/null || { echo "ERROR: gcloud not found; required to reach the IAP-only control plane." >&2; exit 1; }
command -v jq     >/dev/null || { echo "ERROR: jq not found; required to parse Vault status." >&2; exit 1; }

GCP_KEY="${GCP_SSH_KEY_PATH/#\~/$HOME}"
TIMEOUT="${TIMEOUT:-600}"   # seconds; generous for first-boot cloud-init
INTERVAL="${INTERVAL:-10}"

# One IAP SSH per poll: emit the SPIRE unit state, then Vault's status JSON.
# Single-quoted --command so the $(...) runs on the instance, not locally.
probe() {
  gcloud compute ssh "${GCP_SSH_USER}@${GCP_INSTANCE}" \
    --zone "${GCP_ZONE}" ${GCP_PROJECT:+--project "${GCP_PROJECT}"} \
    --tunnel-through-iap --ssh-key-file="${GCP_KEY}" \
    --ssh-flag="-o StrictHostKeyChecking=accept-new" \
    --ssh-flag="-o ConnectTimeout=15" \
    --command 'echo "SPIRE=$(systemctl is-active spire-server 2>/dev/null)"; echo "---VAULT---"; sudo env VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT=/opt/vault/tls/vault.crt vault status -format=json 2>/dev/null || true' \
    2>/dev/null
}

echo "Waiting for GCP control plane (Vault unsealed + SPIRE server active); timeout ${TIMEOUT}s..."
deadline=$(( $(date +%s) + TIMEOUT ))
last=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  out="$(probe || true)"
  spire="$(printf '%s\n' "$out" | sed -n 's/^SPIRE=//p' | head -1)"
  vjson="$(printf '%s\n' "$out" | sed -n '/^---VAULT---$/,$p' | grep -v '^---VAULT---$' || true)"
  # Parse the booleans directly. jq's // treats boolean false as "absent", so it
  # cannot be used here (an unsealed Vault reports sealed=false). Normalise only
  # an empty result (jq failed / no JSON) or a null (missing key) to "unknown".
  initialized="$(printf '%s' "$vjson" | jq -r '.initialized' 2>/dev/null || true)"
  sealed="$(printf '%s' "$vjson" | jq -r '.sealed' 2>/dev/null || true)"
  case "$initialized" in ""|null) initialized="unknown" ;; esac
  case "$sealed" in ""|null) sealed="unknown" ;; esac

  if [ "$initialized" = "false" ]; then
    echo
    echo "Vault is up but NOT initialised. Run 'vault operator init' on the control plane,"
    echo "then re-run this apply to confirm readiness."
    exit 0
  fi

  if [ "$spire" = "active" ] && [ "$sealed" = "false" ] && [ "$initialized" = "true" ]; then
    echo
    echo "GCP control plane ready: Vault unsealed, SPIRE server active."
    exit 0
  fi

  status="spire=${spire:-unreachable} vault_initialized=${initialized} vault_sealed=${sealed}"
  if [ "$status" != "$last" ]; then printf '  not ready yet: %s\n' "$status"; last="$status"; fi
  sleep "$INTERVAL"
done

echo >&2
echo "ERROR: control plane not ready after ${TIMEOUT}s (last seen: ${last:-unreachable})." >&2
echo "Check Vault auto-unseal / KMS access, and 'systemctl status spire-server' on the instance." >&2
exit 1
