#!/usr/bin/env bash
# Poll the GCP control-plane instance over IAP until Vault is unsealed and the
# SPIRE server is active, then print a confirmation. Invoked by
# terraform_data.controlplane_ready so `terraform apply` blocks until the control
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
# A rebuild auto-initialises Vault via the startup-script restore within a few
# minutes, so a brief uninitialised window is transient. Only after Vault stays
# uninitialised for this long do we treat it as a genuine first-ever deploy that
# needs a manual `vault operator init`.
FIRST_DEPLOY_GRACE="${FIRST_DEPLOY_GRACE:-300}"

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
uninit_since=""
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

  # Readiness always wins, even after passing through a transient uninit window.
  if [ "$spire" = "active" ] && [ "$sealed" = "false" ] && [ "$initialized" = "true" ]; then
    echo
    echo "GCP control plane ready: Vault unsealed, SPIRE server active."
    exit 0
  fi

  # Vault reachable but uninitialised. On a rebuild the restore auto-initialises
  # shortly, so keep waiting; only conclude "first deploy, needs manual init" if
  # it persists past the grace period. Running `vault operator init` during a
  # rebuild would fork a NEW Vault instead of restoring, so we never advise it
  # while a restore might still be in progress.
  if [ "$initialized" = "false" ]; then
    now="$(date +%s)"
    [ -z "$uninit_since" ] && uninit_since="$now"
    if [ $(( now - uninit_since )) -ge "$FIRST_DEPLOY_GRACE" ]; then
      echo
      echo "Vault is up but still uninitialised after ${FIRST_DEPLOY_GRACE}s (no restore took"
      echo "effect). If this is a first-ever deploy, run 'vault operator init' on the control"
      echo "plane, then re-run this apply. Do NOT run init during a rebuild."
      exit 0
    fi
  else
    uninit_since=""
  fi

  status="spire=${spire:-unreachable} vault_initialized=${initialized} vault_sealed=${sealed}"
  if [ "$status" != "$last" ]; then printf '  not ready yet: %s\n' "$status"; last="$status"; fi
  sleep "$INTERVAL"
done

echo >&2
echo "ERROR: control plane not ready after ${TIMEOUT}s (last seen: ${last:-unreachable})." >&2
echo "Check Vault auto-unseal / KMS access, and 'systemctl status spire-server' on the instance." >&2
exit 1
