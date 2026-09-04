#!/usr/bin/env bash
# Re-run the control plane's startup script in place, over IAP.
#
# WHY THIS EXISTS. GCE reads `startup-script` metadata only at boot; there is no
# mechanism to re-execute it when the metadata changes. So `terraform apply`
# converges the instance's NEXT BOOT, not the running box, and reports success
# while the machine is still executing the previous script. That is not a
# theoretical gap: a corrected Alloy config sat in metadata for hours on
# 2026-09-04 while the box kept shipping with the broken one, and the apply that
# delivered it exited 0.
#
# startup.sh is idempotent and runs on every boot anyway, so re-running it here is
# the same operation the instance performs for itself — just at apply time. It
# takes an flock, so this is safe even while a boot-time run is still in flight.
#
# It is NOT free: startup.sh rewrites /etc/vault.d/vault.hcl and restarts Vault,
# so an apply that changes the script briefly interrupts the control plane. Vault
# auto-unseals via KMS, and terraform_data.controlplane_ready then blocks until it
# is back. That is the deliberate trade for `terraform apply` meaning what it says.
#
# Invoked by terraform_data.controlplane_converge (gcp/converge.tf).
set -euo pipefail

: "${GCP_INSTANCE:?}"
: "${GCP_ZONE:?}"
: "${GCP_SSH_USER:?}"
: "${GCP_SSH_KEY_PATH:?}"

command -v gcloud >/dev/null || { echo "ERROR: gcloud not found; required to reach the IAP-only control plane." >&2; exit 1; }

GCP_KEY="${GCP_SSH_KEY_PATH/#\~/$HOME}"
# Generous: a run that installs Alloy pulls a ~100 MB zip, and the flock may hold
# this behind a boot-time run that is still working through apt.
REMOTE_TIMEOUT="${REMOTE_TIMEOUT:-1200}"
TAIL_LINES="${TAIL_LINES:-40}"

echo "Converging ${GCP_INSTANCE}: re-running its startup script over IAP (timeout ${REMOTE_TIMEOUT}s)..."

# `|| true` so a non-zero exit does not abort before the output is inspected: the
# runner's own exit status is not a reliable signal (it has been observed exiting 0
# for a script that aborted), so the authoritative check is the status line it
# prints, asserted below.
set +e
OUT="$(gcloud compute ssh "${GCP_SSH_USER}@${GCP_INSTANCE}" \
  --zone "${GCP_ZONE}" ${GCP_PROJECT:+--project "${GCP_PROJECT}"} \
  --tunnel-through-iap --ssh-key-file="${GCP_KEY}" \
  --ssh-flag="-o StrictHostKeyChecking=accept-new" \
  --ssh-flag="-o ConnectTimeout=15" \
  --command "sudo timeout ${REMOTE_TIMEOUT} google_metadata_script_runner startup 2>&1" 2>/dev/null)"
SSH_RC=$?
set -e

printf '%s\n' "$OUT" | tail -n "$TAIL_LINES" | sed 's/^/  | /'

# The guest agent prints exactly this on success. Assert on it rather than on the
# exit code, and fail the apply if it is absent — an apply that leaves the box on
# the old script must not look like a success.
if printf '%s' "$OUT" | grep -q 'startup-script exit status 0'; then
  echo "Converged: ${GCP_INSTANCE} is running the startup script from current metadata."
  exit 0
fi

echo "ERROR: the startup script did not complete successfully on ${GCP_INSTANCE}." >&2
echo "       ssh exit=${SSH_RC}; no 'startup-script exit status 0' in its output (tail above)." >&2
echo "       The instance is still running its PREVIOUS configuration. Fix the cause and" >&2
echo "       re-apply, or investigate with:" >&2
echo "         gcloud compute ssh ${GCP_INSTANCE} --zone ${GCP_ZONE} --tunnel-through-iap \\" >&2
echo "           --command 'sudo google_metadata_script_runner startup'" >&2
exit 1
