#!/usr/bin/env bash
# scripts/provision.sh
#
# Executed locally by Terraform's null_resource.provision via local-exec.
# Environment variables set by Terraform:
#   SERVER_IP    — public IPv4 of the server
#   SERVER_ID    — hcloud server id (used to detect a genuine rebuild)
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
: "${PROBE_SRC:?}"

# Expand ~ in SSH_KEY_PATH (Terraform passes it literally if set in tfvars)
SSH_KEY_PATH="${SSH_KEY_PATH/#\~/$HOME}"

# ── SSH ControlMaster setup ───────────────────────────────────────────────────
# A temp socket file is used as the ControlPath. All subsequent ssh/scp calls
# reference this socket and reuse the single authenticated connection.

CONTROL_DIR=$(mktemp -d)
CONTROL_SOCKET="${CONTROL_DIR}/ssh-ctl.sock"
trap 'ssh -o ControlPath="${CONTROL_SOCKET}" -O exit deploy@${SERVER_IP} 2>/dev/null; rm -rf "${CONTROL_DIR}"' EXIT

BASE_OPTS=(
  -i "${SSH_KEY_PATH}"
  -o StrictHostKeyChecking=accept-new
  -o UserKnownHostsFile="${BACKUPS_DIR}/known_hosts"
  -o BatchMode=yes
  -o ConnectTimeout=10
  -o ControlMaster=auto
  -o ControlPath="${CONTROL_SOCKET}"
  -o ControlPersist=60
  -o ServerAliveInterval=15
  -o ServerAliveCountMax=4
  -o LogLevel=ERROR
)

SSH="ssh ${BASE_OPTS[*]} deploy@${SERVER_IP}"
# SCP also supports ControlPath — it reuses the master connection
SCP="scp -q ${BASE_OPTS[*]}"

log()    { echo "[provision] $*"; }
# Provisioner connects as the non-root `deploy` user (root SSH login is disabled
# in cloud-init). deploy has NOPASSWD sudo, so privileged work is `sudo`-wrapped.
remote() { $SSH -- sudo "$@"; }

# Shared host-key / rebuild-detection helpers.
# shellcheck source=lib/provision-guards.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/provision-guards.sh"

upload() {
  local src="$1" dst="$2" perms="${3:-0644}"
  # deploy can't write system paths directly; stage in /tmp, then install as root.
  # $$ plus the known basename made the old /tmp/prov.$$.<name> path guessable by
  # any local account on the target: a file or symlink pre-created there receives
  # the uploaded content — which includes keypair.env and client UUIDs. Let the
  # remote side pick an unpredictable, mode-0600 name instead.
  local stage
  stage="$($SSH -- 'umask 077; mktemp /tmp/prov.XXXXXXXXXX')"
  [ -n "$stage" ] || { log "ERROR: could not create a staging file on ${SERVER_IP}"; return 1; }
  $SCP "$src" "deploy@${SERVER_IP}:${stage}"
  remote install -m "$perms" "$stage" "$dst"
  $SSH -- rm -f "$stage"
  log "Uploaded $(basename "$src") → $dst"
}

download() {
  local src="$1" dst="$2"
  # Sources are root-owned/0600 → read via sudo cat. Stage to .partial so a
  # missing source never leaves a truncated file in backups/. Create the partial
  # private: a redirect at the ambient umask leaves retrieved key material
  # world-readable on the operator workstation until the chmod lands.
  if ( umask 077; remote cat "$src" > "$dst.partial" 2>/dev/null ); then
    mv "$dst.partial" "$dst"
    chmod 600 "$dst"
  else
    rm -f "$dst.partial"
    return 1
  fi
}

# ── 1. Wait for the server, then for cloud-init ───────────────────────────────
# Two bounded phases so a permanent problem fails fast instead of burning the
# whole budget (the failure mode that prolonged the 2026-07-04 DR outage, where
# a stale host key made the old single loop wait ~55 min before giving up):
#   A. Wait for SSH to work at all — the box may still be booting. Classify the
#      failure: a connection-level error means "still booting, retry"; a host-key
#      or auth error is permanent, so bail immediately with the cause + fix.
#   B. Once SSH works, wait for cloud-init to finish. Iterations are fast (the
#      connection is already up), and it's bounded so a *hung* cloud-init
#      (status stuck 'running', sentinel never written) can't stall for ~an hour.

# A `terraform -replace` rebuild keeps the static IP but regenerates the SSH host
# keys, so the stale pin has to go before the SSH below can accept-new the fresh
# one. But clearing it on EVERY apply (as this used to) lets accept-new re-trust
# whatever key answers — defeating the one check that catches an on-path attacker.
# So clear it only when the box was genuinely rebuilt: SERVER_ID (the hcloud server
# id, from terraform state) changed since it was last recorded, an unforgeable
# rebuild signal. A changed key NOT backed by a new id (the MITM case) is left
# pinned and fails closed in Phase A below. VIADUCT_HOST_KEY_RESET=1 forces the
# reset for an out-of-band key change that kept the same id (e.g. an OS reinstall).
vh_reset_host_key_pin_if_requested "${SERVER_IP}" "${BACKUPS_DIR}/known_hosts" \
  "${SERVER_ID:-}" "${BACKUPS_DIR}/known_hosts.serverid"

# ── Phase A: wait for SSH to succeed (bounded ~10 min); establishes the master.
log "Waiting for ${SERVER_IP} to accept SSH (up to 10 min)..."
BOOT_DEADLINE=$(( SECONDS + 600 ))
until ssh_err=$($SSH -- true 2>&1); do
  # $SSH returned non-zero. A connection-level failure (refused / timed out /
  # no route) means the box is still booting → keep waiting. A host-key or auth
  # failure will NEVER resolve by retrying → fail fast with the cause.
  if echo "$ssh_err" | grep -qiE 'host key|identification has changed|permission denied|authenticat'; then
    log "ERROR: SSH to ${SERVER_IP} failed for a non-transient reason — not a boot delay:"
    printf '%s\n' "$ssh_err" | sed 's/^/  | /'
    log "  If the host key changed on a rebuild, clear it and re-apply:"
    log "    ssh-keygen -R ${SERVER_IP} -f ${BACKUPS_DIR}/known_hosts"
    exit 1
  fi
  if (( SECONDS >= BOOT_DEADLINE )); then
    log "ERROR: timed out after 10 min — ${SERVER_IP} never accepted SSH. Last error:"
    printf '%s\n' "$ssh_err" | sed 's/^/  | /'
    exit 1
  fi
  log "  not reachable yet (still booting?), retrying in 10s..."
  sleep 10
done
log "SSH established."

# The pin now belongs to this instance. Record its id so the next run can tell a
# genuine rebuild (id changed) from an ordinary apply, and NOT clear the pin then.
vh_record_server_id "${SERVER_ID:-}" "${BACKUPS_DIR}/known_hosts.serverid"

# ── Phase B: wait for cloud-init to finish (fast iterations; the master is up).
log "Waiting for cloud-init to finish (up to 10 min)..."
CI_DEADLINE=$(( SECONDS + 600 ))
while true; do
  # 'cloud-init status' prints 'status: done' | 'running' | 'error'. runcmd
  # continues past failures by default, so an early step can fail and still
  # write the sentinel — hence we require BOTH status=done AND the sentinel.
  CI_STATUS=$(remote "cloud-init status" 2>/dev/null || true)
  if echo "$CI_STATUS" | grep -q "status: error"; then
    log "ERROR: cloud-init finished with errors — a runcmd step failed."
    log "  ssh deploy@${SERVER_IP} 'sudo cloud-init status --long; sudo journalctl -u cloud-init --no-pager -n 100'"
    exit 1
  fi
  if echo "$CI_STATUS" | grep -q "status: done" && remote "test -f /var/lib/cloud-init-done" 2>/dev/null; then
    log "cloud-init complete."
    break
  fi
  if (( SECONDS >= CI_DEADLINE )); then
    log "ERROR: timed out after 10 min waiting for cloud-init (status may be stuck 'running')."
    log "  ssh deploy@${SERVER_IP} 'sudo cloud-init status --long; sudo journalctl -u cloud-init --no-pager -n 100'"
    exit 1
  fi
  log "  cloud-init still running..."
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

# ── 7b. Build + upload the probe binary (linux/amd64) ─────────────────────────
log "Building probe (linux/amd64)..."
( cd "$PROBE_SRC" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "${CONTROL_DIR}/probe" . )
# Upload to a temp path then atomically mv into place. A direct scp truncates
# the destination, which the kernel refuses (ETXTBSY) when probe.service is
# already running the old binary; rename swaps the inode without touching it.
upload "${CONTROL_DIR}/probe" "/usr/local/bin/probe.new" "755"
remote mv -f /usr/local/bin/probe.new /usr/local/bin/probe

# ── 8. Start / restart all services ──────────────────────────────────────────

log "Starting services..."
remote systemctl restart conduit xray xray-exporter xray-user-stats alloy nginx xray-probe-client probe

sleep 5
if remote systemctl is-active --quiet conduit xray xray-exporter xray-user-stats alloy nginx xray-probe-client probe; then
  log "All services active."
else
  log "WARNING: one or more services failed to start. Check: journalctl -u conduit -u xray -u xray-exporter -u xray-user-stats -u alloy -u nginx -u xray-probe-client -u probe"
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
#
# The list is read on FD 3, not stdin: download() runs `ssh` (via remote cat), and
# ssh with an inherited stdin would read the rest of this list itself — draining the
# pipe so the loop stops after the first file, silently backing up only the first
# client. Keeping the list on FD 3 leaves the inner ssh's stdin alone.
while IFS= read -r rf <&3; do
  [[ -z "$rf" ]] && continue
  name=$(basename "$rf")
  if download "$rf" "$BACKUPS_DIR/clients/$name"; then
    log "  Saved backups/clients/$name"
  fi
done 3< <($SSH -- "sudo sh -c 'ls /etc/xray/clients/*.uuid /etc/xray/clients/*.txt 2>/dev/null || true'")

log ""
log "Provisioning complete."
log "VLESS URIs are in: $BACKUPS_DIR/clients/*.txt"
log "Metrics flowing to Grafana Cloud."
