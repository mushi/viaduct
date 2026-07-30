#!/usr/bin/env bash
# aws/scripts/crosscloud-refresh.sh
#
# Runs locally via Terraform (terraform_data.crosscloud_refresh) on every aws/ apply.
# Keeps the AWS node's view of GCP Vault's listener cert current WITHOUT a hardcoded
# fingerprint and WITHOUT rebuilding the instance:
#   1. read GCP's CURRENT vault.crt fingerprint from the GCP box over IAP (trusted,
#      operator-authenticated — not the untrusted network);
#   2. write it (with GCP_IP + trust domain) into crosscloud.env on the AWS box over SSM;
#   3. run crosscloud-bootstrap there, which re-fetches vault.crt, verifies it against
#      that fingerprint, and refreshes the Vault-Agent CA ConfigMap.
# The fingerprint is public (a cert hash), so it can ride the SSM command in clear.
# So a GCP rebuild (which rotates the cert) is followed by a plain `terraform apply`
# here — a refresh, no AWS instance rebuild.
set -euo pipefail

: "${AWS_REGION:?}"
: "${AWS_INSTANCE_ID:?}"
: "${GCP_MESH_IP:?}"
: "${GCP_TRUST_DOMAIN:?}"
: "${GCP_INSTANCE:?}"
: "${GCP_ZONE:?}"

command -v aws    >/dev/null || { echo "ERROR: aws CLI not found."   >&2; exit 1; }
command -v gcloud >/dev/null || { echo "ERROR: gcloud not found."    >&2; exit 1; }
command -v jq     >/dev/null || { echo "ERROR: jq not found."        >&2; exit 1; }

GCP_KEY="${GCP_SSH_KEY_PATH/#\~/$HOME}"
log() { echo "[crosscloud-refresh] $*"; }

# Run one shell command on the AWS box via SSM (as root); print stdout, non-zero if failed.
ssm_run() {
  local cid status out
  cid="$(aws ssm send-command --region "$AWS_REGION" --instance-ids "$AWS_INSTANCE_ID" \
    --document-name AWS-RunShellScript \
    --parameters "$(jq -Rn --arg c "$1" '{commands:[$c]}')" \
    --query 'Command.CommandId' --output text)" || return 1
  aws ssm wait command-executed --region "$AWS_REGION" \
    --command-id "$cid" --instance-id "$AWS_INSTANCE_ID" 2>/dev/null || true
  status="$(aws ssm get-command-invocation --region "$AWS_REGION" \
    --command-id "$cid" --instance-id "$AWS_INSTANCE_ID" --query 'Status' --output text)"
  out="$(aws ssm get-command-invocation --region "$AWS_REGION" \
    --command-id "$cid" --instance-id "$AWS_INSTANCE_ID" --query 'StandardOutputContent' --output text)"
  printf '%s' "$out"
  [ "$status" = "Success" ]
}

gcp_ssh() {
  gcloud compute ssh "${GCP_SSH_USER}@${GCP_INSTANCE}" \
    --zone "${GCP_ZONE}" ${GCP_PROJECT:+--project "${GCP_PROJECT}"} \
    --tunnel-through-iap --ssh-key-file="${GCP_KEY}" \
    --ssh-flag="-o StrictHostKeyChecking=accept-new" \
    --ssh-flag="-o ConnectTimeout=30" \
    --command "$1"
}

# Wait until the AWS box is SSM-ready, k3s is Ready, and the bootstrap script is in
# place (user_data reached §10). A failed send-command or empty result = not ready.
log "Waiting for the AWS box to be ready (SSM + k3s Ready + crosscloud script)..."
st=""
for _ in $(seq 1 60); do
  st="$(ssm_run 'test -x /opt/viaduct/crosscloud-bootstrap.sh && k3s kubectl get node --no-headers 2>/dev/null | grep -qw Ready && echo READY || true' 2>/dev/null | tr -d "[:space:]" || true)"
  [ "$st" = "READY" ] && break
  sleep 15
done
[ "$st" = "READY" ] || { log "ERROR: AWS box not ready (SSM/k3s/crosscloud) after ~15min."; exit 1; }

log "Reading GCP Vault cert fingerprint from ${GCP_INSTANCE} over IAP..."
GCP_FP="$(gcp_ssh "sudo openssl x509 -in /opt/vault/tls/vault.crt -noout -fingerprint -sha256 | cut -d= -f2" | tr -d '[:space:]')"
case "$GCP_FP" in
  *:*:*) : ;;   # looks like a colon-hex fingerprint
  *) log "ERROR: could not read a valid fingerprint from GCP (got: '$GCP_FP')."; exit 1 ;;
esac

log "Writing crosscloud.env and running the bootstrap over SSM..."
REMOTE="$(cat <<REOF
set -e
cat > /opt/viaduct/crosscloud.env <<CCENV
GCP_IP=${GCP_MESH_IP}
GCP_FP=${GCP_FP}
GCP_TRUST_DOMAIN=${GCP_TRUST_DOMAIN}
CCENV
/opt/viaduct/crosscloud-bootstrap.sh
REOF
)"
B64="$(printf '%s' "$REMOTE" | base64 | tr -d '\n')"
if out="$(ssm_run "echo ${B64} | base64 -d | bash")"; then
  log "cross-cloud refresh complete (fingerprint ${GCP_FP})."
  printf '%s\n' "$out" | tail -1
else
  log "ERROR: crosscloud-bootstrap failed on the box. Last output:"
  printf '%s\n' "$out" | tail -5 >&2
  exit 1
fi
