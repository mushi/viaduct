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

# Shared allowlists, also used by scripts/provision.sh. Both provisioners feed
# node-authored values into root command strings executed on another host, so the
# validation lives in one place rather than being restated (and drifting) per script.
# shellcheck source=../../scripts/lib/provision-guards.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../scripts/lib" && pwd)/provision-guards.sh"

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

# The `tr -d '[:space:]'` above normalizes the SSM stdout; it is NOT a security
# control. It deletes literal whitespace but leaves ';', '&', '|', backticks and
# command substitution intact, and ${IFS} — which contains no literal whitespace —
# expands back to a space in the hub's shell. AWS_PUB is about to be interpolated
# into a string that runs as root on the hub, so admit only the exact key shape.
vh_require vh_is_wg_key  "AWS wg0.pub (AWS_PUB)" "$AWS_PUB"    || exit 1
vh_require vh_is_mesh_ip "mesh IP (WG_MESH_IP)"  "$WG_MESH_IP" || exit 1
log "AWS node ready; public key retrieved."

# terraform_data.wg_mesh_join fires only when aws_instance.spire.id changes (a
# recreate), so the box always presents a fresh key here. Clear any stale registry
# entry first so the hub does not refuse the re-register; a harmless no-op on a first
# deploy. Authorised by that instance-id trigger — the same unforgeable rebuild signal
# Hetzner gates on. Tolerant: an un-updated hub without the script falls back to the refusal.
log "Clearing any stale 'aws' mesh registry entry (this step runs only on a rebuild)..."
gcp_ssh "sudo /usr/local/bin/wg-deregister-peer.sh aws" >/dev/null 2>&1 \
  || log "  (deregister skipped: hub lacks wg-deregister-peer.sh or it failed; register will print the manual step if the key differs)"

log "Registering with the hub ${GCP_INSTANCE} over IAP..."
REG_OUT="$(gcp_ssh "sudo /usr/local/bin/wg-register-peer.sh aws '${AWS_PUB}' '${WG_MESH_IP}'")"
HUB_PUB="$(printf '%s\n' "$REG_OUT" | awk '/^hub_public_key /{print $2}')"
WG_PSK="$(printf  '%s\n' "$REG_OUT" | awk '/^psk /{print $2}')"
[ -n "$HUB_PUB" ] && [ -n "$WG_PSK" ] || { log "ERROR: hub returned no key/psk (is GCP on the current startup.sh?)."; exit 1; }

# HUB_PUB is interpolated into the REMOTE heredoc below, which is base64'd and run
# through `base64 -d | bash` as root on the box. A reply carrying a newline plus
# "CONF" closes the inner config heredoc and everything after it becomes root shell
# commands on the spoke. WG_PSK goes to SSM Parameter Store on the same reply.
vh_require vh_is_wg_key "hub public key (HUB_PUB)"   "$HUB_PUB" || exit 1
vh_require vh_is_wg_key "mesh preshared key (WG_PSK)" "$WG_PSK"  || exit 1

log "Staging the PSK in SSM Parameter Store (SecureString)..."
# Reap any residue from a previous run before staging. The EXIT trap below already fires
# on SIGTERM, SIGINT and SIGHUP — bash runs EXIT traps for all of those — so the only way
# a parameter survives is SIGKILL, which cannot be trapped by definition. Clearing it here
# bounds that residue to the interval between the kill and the next run, rather than
# leaving the mesh preshared key resident indefinitely.
aws ssm delete-parameter --region "$AWS_REGION" --name "$PSK_PARAM" >/dev/null 2>&1 || true
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
