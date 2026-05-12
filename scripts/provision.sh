#!/usr/bin/env bash
# scripts/provision.sh
#
# Executed locally by Terraform's null_resource.provision via local-exec.
# Environment variables set by Terraform:
#   SERVER_IP    — public IPv4 of the server
#   SSH_KEY_PATH — local path to the SSH private key
#   BACKUPS_DIR  — local path to the backups/ directory
#   USERS_FILE   — local path to the generated users.txt
#   ALLOY_CONFIG — local path to the rendered alloy-config.alloy
#
# Uses SSH ControlMaster multiplexing so that all SSH and SCP operations
# share a single underlying TCP connection. This avoids triggering the
# SSH daemon's MaxStartups limit (which causes "Connection timed out"
# errors when many sequential connections are opened rapidly) and is
# significantly faster overall.

set -euo pipefail

: "${SERVER_IP:?}"
: "${SSH_KEY_PATH:?}"
: "${BACKUPS_DIR:?}"
: "${USERS_FILE:?}"
: "${ALLOY_CONFIG:?}"

# Expand ~ in SSH_KEY_PATH (Terraform passes it literally if set in tfvars)
SSH_KEY_PATH="${SSH_KEY_PATH/#\~/$HOME}"

# ── SSH ControlMaster setup ───────────────────────────────────────────────────
# A temp socket file is used as the ControlPath. All subsequent ssh/scp calls
# reference this socket and reuse the single authenticated connection.

CONTROL_DIR=$(mktemp -d)
CONTROL_SOCKET="${CONTROL_DIR}/ssh-ctl.sock"
trap 'ssh -o ControlPath="${CONTROL_SOCKET}" -O exit root@${SERVER_IP} 2>/dev/null; rm -rf "${CONTROL_DIR}"' EXIT

BASE_OPTS=(
  -i "${SSH_KEY_PATH}"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o BatchMode=yes
  -o ConnectTimeout=30
  -o ControlMaster=auto
  -o ControlPath="${CONTROL_SOCKET}"
  -o ControlPersist=60
  -o ServerAliveInterval=15
  -o ServerAliveCountMax=4
  -o LogLevel=ERROR
)

SSH="ssh ${BASE_OPTS[*]} root@${SERVER_IP}"
# SCP also supports ControlPath — it reuses the master connection
SCP="scp -q ${BASE_OPTS[*]}"

log()    { echo "[provision] $*"; }
remote() { $SSH -- "$@"; }

upload() {
  local src="$1" dst="$2" perms="${3:-}"
  $SCP "$src" "root@${SERVER_IP}:${dst}"
  if [[ -n "$perms" ]]; then
    remote chmod "$perms" "$dst"
  fi
  log "Uploaded $(basename "$src") → $dst"
}

download() {
  local src="$1" dst="$2"
  $SCP "root@${SERVER_IP}:${src}" "$dst"
  chmod 600 "$dst"
}

# ── 1. Wait for cloud-init, establishing the master connection ────────────────
# The first SSH call establishes the ControlMaster. We use a longer timeout
# here since the server may still be booting.

log "Waiting for cloud-init to finish (up to 10 min)..."
for i in $(seq 1 60); do
  if $SSH -o ConnectTimeout=30 -- "test -f /var/lib/cloud-init-done" 2>/dev/null; then
    # Sentinel found — but runcmd continues past failures by default, so the
    # sentinel can exist even when an earlier step errored. Check status too.
    CI_STATUS=$($SSH -- "cloud-init status 2>/dev/null" 2>/dev/null || true)
    if echo "$CI_STATUS" | grep -q "error"; then
      log "ERROR: cloud-init finished with errors — a runcmd step failed."
      log "  ssh root@${SERVER_IP} 'journalctl -u cloud-init --no-pager -n 100'"
      exit 1
    fi
    log "cloud-init complete."
    break
  fi

  # Detect cloud-init failure early — if it has finished but never wrote
  # the sentinel, it means a runcmd step failed (e.g. bad checksum or 404).
  # 'cloud-init status' exits 2 when cloud-init finished with errors.
  CLOUD_STATUS=$($SSH -o ConnectTimeout=30 -- "cloud-init status 2>/dev/null; echo exit:$?" 2>/dev/null || true)
  if echo "$CLOUD_STATUS" | grep -q "exit:0" && echo "$CLOUD_STATUS" | grep -q "error\|Error"; then
    log "ERROR: cloud-init reported an error. Check logs on the server:"
    log "  ssh root@${SERVER_IP} 'journalctl -u cloud-init --no-pager -n 50'"
    exit 1
  fi
  if echo "$CLOUD_STATUS" | grep -q "status: error"; then
    log "ERROR: cloud-init status is 'error'. Check logs on the server:"
    log "  ssh root@${SERVER_IP} 'journalctl -u cloud-init --no-pager -n 50'"
    exit 1
  fi

  [[ $i -eq 60 ]] && { log "ERROR: timed out waiting for cloud-init."; exit 1; }
  log "  waiting... ($i/60)"
  sleep 10
done

# ── 2. Upload conduit_key.json ────────────────────────────────────────────────

KEY="$BACKUPS_DIR/conduit_key.json"
if [[ -f "$KEY" ]]; then
  upload "$KEY" "/var/lib/conduit/data/conduit_key.json" "600"
  remote chown conduit:conduit /var/lib/conduit/data/conduit_key.json
  log "Conduit identity key restored — broker reputation preserved."
else
  log "No conduit_key.json in backups/ — a fresh key will be generated on first start."
fi

# ── 3. Upload Reality keypair ─────────────────────────────────────────────────

KEYPAIR="$BACKUPS_DIR/keypair.env"
if [[ -f "$KEYPAIR" ]]; then
  upload "$KEYPAIR" "/etc/xray/keypair.env" "600"
  log "Reality keypair restored — existing client configs remain valid."
else
  log "No keypair.env in backups/ — a fresh keypair will be generated."
  log "  All users will need updated client configs after this apply."
fi

# ── 4. Upload per-user UUID files ─────────────────────────────────────────────

UUID_DIR="$BACKUPS_DIR/clients"
if [[ -d "$UUID_DIR" ]]; then
  shopt -s nullglob
  UUID_FILES=("$UUID_DIR"/*.uuid)
  shopt -u nullglob
  if [[ ${#UUID_FILES[@]} -gt 0 ]]; then
    log "Uploading ${#UUID_FILES[@]} UUID file(s)..."
    for f in "${UUID_FILES[@]}"; do
      upload "$f" "/etc/xray/clients/$(basename "$f")" "600"
    done
  else
    log "No .uuid files in backups/clients/ — fresh UUIDs will be generated."
  fi
fi

# ── 5. Upload users.txt ───────────────────────────────────────────────────────

upload "$USERS_FILE" "/etc/xray/users.txt" "644"
log "User list: $(tr '\n' ' ' < "$USERS_FILE")"

# ── 6. Upload Alloy config ────────────────────────────────────────────────────

upload "$ALLOY_CONFIG" "/etc/alloy/config.alloy" "640"
remote chown root:alloy /etc/alloy/config.alloy

# ── 7. Run xray-setup.sh --regen ─────────────────────────────────────────────

log "Running xray-setup.sh --regen..."
remote /usr/local/sbin/xray-setup.sh --regen

# ── 8. Start / restart all services ──────────────────────────────────────────

log "Starting services..."
remote systemctl restart conduit xray xray-exporter alloy nginx

sleep 5
if remote systemctl is-active --quiet conduit xray xray-exporter alloy nginx; then
  log "All services active."
else
  log "WARNING: one or more services failed to start. Check: journalctl -u conduit -u xray -u xray-exporter -u alloy -u nginx"
fi

# ── 9. Download fresh backups ─────────────────────────────────────────────────

log "Downloading updated backups..."
mkdir -p "$BACKUPS_DIR/clients"

# conduit_key.json — Conduit writes this on first startup; give it a moment
sleep 5
if download "/var/lib/conduit/data/conduit_key.json" "$BACKUPS_DIR/conduit_key.json" 2>/dev/null; then
  log "  Saved backups/conduit_key.json"
else
  log "  conduit_key.json not yet available — re-run 'terraform apply' in ~30s to download it."
fi

# Reality keypair
if download "/etc/xray/keypair.env" "$BACKUPS_DIR/keypair.env"; then
  log "  Saved backups/keypair.env"
fi

# Per-user .uuid and .txt files
# Use a single remote command to list them, then download each over the
# existing multiplexed connection.
while IFS= read -r rf; do
  [[ -z "$rf" ]] && continue
  name=$(basename "$rf")
  if download "$rf" "$BACKUPS_DIR/clients/$name"; then
    log "  Saved backups/clients/$name"
  fi
done < <(remote "ls /etc/xray/clients/*.uuid /etc/xray/clients/*.txt 2>/dev/null || true")

log ""
log "Provisioning complete."
log "VLESS URIs are in: $BACKUPS_DIR/clients/*.txt"
log "Metrics flowing to Grafana Cloud."
