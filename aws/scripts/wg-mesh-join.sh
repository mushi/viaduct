#!/usr/bin/env bash
# aws/scripts/wg-mesh-join.sh
#
# Runs locally via Terraform (terraform_data.wg_mesh_join) after an AWS rebuild.
# Joins the AWS node to the WireGuard mesh, mirroring the Hetzner provisioner but
# over the AWS-native channels: SSM to reach the box, IAP to reach the GCP hub.
#
# Flow:
#   1. read the AWS node's wg0.pub over SSM (cloud-init generated the key);
#   2. register with the hub over IAP (reuses wg-register-peer.sh on the GCP box),
#      receiving the hub public key + endpoint + the shared PSK;
#   3. relay the PSK through an SSM SecureString parameter, since SSM send-command
#      parameters are logged and must not carry the secret in the clear;
#   4. over SSM, write wg0.conf (the box reads the PSK by name, never echoing it)
#      and start wg-quick; then delete the parameter.
set -euo pipefail

: "${AWS_REGION:?}"
: "${AWS_INSTANCE_ID:?}"
: "${GCP_HUB_IP:?}"
: "${WG_PORT:?}"
: "${WG_MESH_IP:?}"
: "${PSK_PARAM:?}"
: "${GCP_INSTANCE:?}"
: "${GCP_ZONE:?}"

command -v aws    >/dev/null || { echo "ERROR: aws CLI not found."   >&2; exit 1; }
command -v gcloud >/dev/null || { echo "ERROR: gcloud not found."    >&2; exit 1; }
command -v jq     >/dev/null || { echo "ERROR: jq not found."        >&2; exit 1; }

GCP_KEY="${GCP_SSH_KEY_PATH/#\~/$HOME}"
log() { echo "[wg-mesh-join] $*"; }

# Run one shell command on the AWS box via SSM Run Command (executes as root),
# print its stdout, and return non-zero if it did not succeed. The command is
# JSON-encoded with jq so arbitrary text is safe.
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

# A freshly rebuilt instance needs ~a minute for the SSM agent to register (until
# then SendCommand returns InvalidInstanceId), and user_data must reach §11 to
# write wg0.pub. Poll until both hold: a failed send-command OR an empty result
# just means "not ready yet". ~15 min budget.
log "Waiting for the AWS box to be SSM-ready and for cloud-init to write wg0.pub..."
AWS_PUB=""
for _ in $(seq 1 60); do
  AWS_PUB="$(ssm_run 'cat /etc/wireguard/wg0.pub 2>/dev/null || true' 2>/dev/null | tr -d '[:space:]' || true)"
  [ -n "$AWS_PUB" ] && break
  sleep 15
done
[ -n "$AWS_PUB" ] || { log "ERROR: AWS box not SSM-ready or wg0.pub absent after ~15min. Check the SSM agent registration and user_data (§11)."; exit 1; }
log "AWS node ready; public key retrieved."

log "Registering with the hub ${GCP_INSTANCE} over IAP..."
REG_OUT="$(gcp_ssh "sudo /usr/local/bin/wg-register-peer.sh aws ${AWS_PUB} ${WG_MESH_IP}")"
HUB_PUB="$(printf '%s\n' "$REG_OUT" | awk '/^hub_public_key /{print $2}')"
WG_PSK="$(printf  '%s\n' "$REG_OUT" | awk '/^psk /{print $2}')"
[ -n "$HUB_PUB" ] && [ -n "$WG_PSK" ] || { log "ERROR: hub returned no key/psk (is GCP on the current startup.sh?)."; exit 1; }

log "Staging the PSK in SSM Parameter Store (SecureString)..."
aws ssm put-parameter --region "$AWS_REGION" --name "$PSK_PARAM" \
  --type SecureString --value "$WG_PSK" --overwrite >/dev/null
trap 'aws ssm delete-parameter --region "$AWS_REGION" --name "$PSK_PARAM" >/dev/null 2>&1 || true' EXIT

# Remote script: fetch the PSK by name (never echoed), write wg0.conf, start the
# tunnel. Operator-side vars are already expanded; \${psk} and %i stay literal for
# the box / wg-quick. Base64 so the multi-line script needs no JSON gymnastics.
REMOTE="$(cat <<REOF
set -e
psk="\$(aws ssm get-parameter --region ${AWS_REGION} --name ${PSK_PARAM} --with-decryption --query Parameter.Value --output text)"
install -d -m 0700 /etc/wireguard
umask 077
cat > /etc/wireguard/wg0.conf <<CONF
[Interface]
Address = ${WG_MESH_IP}/24
PostUp = wg set %i private-key /etc/wireguard/wg0.key

[Peer]
PublicKey = ${HUB_PUB}
PresharedKey = \${psk}
Endpoint = ${GCP_HUB_IP}:${WG_PORT}
AllowedIPs = 10.99.0.0/24
PersistentKeepalive = 25
CONF
unset psk
systemctl daemon-reload
systemctl enable wg-quick@wg0
systemctl restart wg-quick@wg0
REOF
)"
B64="$(printf '%s' "$REMOTE" | base64 | tr -d '\n')"

log "Writing wg0.conf and starting the tunnel over SSM..."
ssm_run "echo ${B64} | base64 -d | bash" >/dev/null

sleep 2
if ssm_run 'wg show wg0' | grep -q 'peer:'; then
  log "WireGuard mesh: wg0 up (hub 10.99.0.1, self ${WG_MESH_IP})."
else
  log "WARNING: wg0 has no peer yet. Check on the box: journalctl -u wg-quick@wg0"
fi
