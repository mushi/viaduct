#!/usr/bin/env bash
# Destroy-time hook: before the control-plane instance is replaced or destroyed,
# capture a FRESH Vault + SPIRE snapshot to GCS so the rebuilt instance restores
# the latest state rather than the last weekly snapshot. Reuses the on-box
# vault-snapshot.service (Type=oneshot), so `systemctl start` blocks until the
# backup finishes and returns its exit status.
#
# Best-effort by design: if the instance is already unreachable (for example it
# died, which may be WHY it is being rebuilt), warn loudly and let the rebuild
# proceed from the most recent EXISTING snapshot rather than deadlocking recovery.
# To make it fail-closed instead (block the replace unless a fresh backup
# succeeds), change the else branch below to `exit 1`.
set -euo pipefail

: "${GCP_INSTANCE:?}"
: "${GCP_ZONE:?}"
: "${GCP_SSH_USER:?}"
: "${GCP_SSH_KEY_PATH:?}"

command -v gcloud >/dev/null || { echo "ERROR: gcloud not found; needed to reach the IAP-only control plane." >&2; exit 1; }

KEY="${GCP_SSH_KEY_PATH/#\~/$HOME}"

echo "Pre-replace backup: refreshing Vault + SPIRE snapshot on ${GCP_INSTANCE} before it is destroyed..."
if gcloud compute ssh "${GCP_SSH_USER}@${GCP_INSTANCE}" \
     --zone "${GCP_ZONE}" ${GCP_PROJECT:+--project "${GCP_PROJECT}"} \
     --tunnel-through-iap --ssh-key-file="${KEY}" \
     --ssh-flag="-o StrictHostKeyChecking=accept-new" \
     --ssh-flag="-o ConnectTimeout=15" \
     --command 'sudo systemctl start vault-snapshot.service'; then
  echo "Pre-replace backup complete: vault.snap + spire-data.tar.gz refreshed in the snapshot bucket."
else
  echo "WARNING: pre-replace backup did NOT complete (instance unreachable or the snapshot job failed)." >&2
  echo "         The rebuilt instance will restore from the most recent EXISTING snapshot in the bucket." >&2
  echo "         If the box is reachable and you need the very latest state, run" >&2
  echo "         'sudo systemctl start vault-snapshot.service' on it, then replace." >&2
fi
