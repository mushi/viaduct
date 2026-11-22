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
#   CF_INI       — local path to the rendered cloudflare-certbot.ini
#   VLESS_DOMAIN — the domain the TLS certificate is issued for
#
# Every SSH and SCP operation shares one connection, opened once per run (see
# "One SSH connection per run" below).

set -euo pipefail

: "${SERVER_IP:?}"
: "${SSH_KEY_PATH:?}"
: "${BACKUPS_DIR:?}"
: "${USERS_FILE:?}"
: "${ALLOY_CONFIG:?}"
: "${CF_INI:?}"
: "${VLESS_DOMAIN:?}"
: "${PROBE_SRC:?}"

# Expand ~ in SSH_KEY_PATH (Terraform passes it literally if set in tfvars)
SSH_KEY_PATH="${SSH_KEY_PATH/#\~/$HOME}"

# ── One SSH connection per run ────────────────────────────────────────────────
# Intrusion prevention between the operator and the node (seen on a home router)
# treats a stream of short-lived SSH connections as a brute-force attempt and
# drops the traffic. So a run opens ONE master connection and holds it:
#   - ssh_connect opens it, backing off 15s → 30s → 60s while the box boots
#     (about a dozen attempts over ten minutes, not one every 10s);
#   - every command and copy rides on it with ControlMaster=no, so none of them
#     can quietly open a connection of its own;
#   - ControlPersist keeps it across idle stretches (the probe build) and lets it
#     lapse ten minutes after the run if the exit trap never fired;
#   - if it drops, rssh/rscp reconnect the same way and retry the command.

CONTROL_DIR=$(mktemp -d)
CONTROL_SOCKET="${CONTROL_DIR}/ssh-ctl.sock"
trap 'ssh -o ControlPath="${CONTROL_SOCKET}" -O exit deploy@${SERVER_IP} 2>/dev/null; rm -rf "${CONTROL_DIR}"' EXIT

BASE_OPTS=(
  -i "${SSH_KEY_PATH}"
  -o StrictHostKeyChecking=accept-new
  -o UserKnownHostsFile="${BACKUPS_DIR}/known_hosts"
  -o BatchMode=yes
  -o ConnectTimeout=10
  -o ControlPath="${CONTROL_SOCKET}"
  -o ServerAliveInterval=15
  -o ServerAliveCountMax=4
  -o LogLevel=ERROR
)
CLIENT_OPTS=("${BASE_OPTS[@]}" -o ControlMaster=no)

log()    { echo "[provision] $*"; }

ssh_master_up() {
  ssh -o ControlPath="${CONTROL_SOCKET}" -O check "deploy@${SERVER_IP}" >/dev/null 2>&1
}

# ssh_connect <budget-seconds>: open the master connection unless it is already up.
# A connection-level failure (refused, timed out, no route) is retried with backoff
# until the budget runs out; a host-key or authentication failure will never resolve
# by retrying, so it stops the run at once with the cause and the fix.
ssh_connect() {
  local budget="${1:-300}" delay=15 deadline err
  ssh_master_up && return 0
  deadline=$(( SECONDS + budget ))
  while :; do
    if err=$(ssh "${BASE_OPTS[@]}" -o ControlMaster=yes -o ControlPersist=10m \
               -fN "deploy@${SERVER_IP}" 2>&1); then
      return 0
    fi
    if printf '%s' "$err" | grep -qiE 'host key|identification has changed|permission denied|authenticat'; then
      log "ERROR: SSH to ${SERVER_IP} failed for a non-transient reason — not a boot delay:"
      printf '%s\n' "$err" | sed 's/^/  | /'
      log "  A rebuild is auto-detected from the hcloud server id; this key changed"
      log "  WITHOUT a new id. If that was an intended out-of-band change, re-apply with"
      log "  VIADUCT_HOST_KEY_RESET=1 (or clear the pin: ssh-keygen -R ${SERVER_IP} -f ${BACKUPS_DIR}/known_hosts)."
      exit 1
    fi
    if (( SECONDS + delay > deadline )); then
      log "ERROR: ${SERVER_IP} did not accept SSH within ${budget}s. Last error:"
      printf '%s\n' "$err" | sed 's/^/  | /'
      return 1
    fi
    log "  ${SERVER_IP} not reachable yet; retrying in ${delay}s..."
    sleep "$delay"
    delay=$(( delay * 2 > 60 ? 60 : delay * 2 ))
  done
}

# rssh <command...>: run a command over the shared connection. Exit status 255 with
# the master gone means the connection dropped, not that the command failed, so
# reconnect and retry (up to three attempts). Every command passed here is safe to
# repeat. Never use it with stdin: a retry cannot replay what was already read.
rssh() {
  local attempt rc=255
  for attempt in 1 2 3; do
    ssh_connect 300 || return 255
    ssh "${CLIENT_OPTS[@]}" "deploy@${SERVER_IP}" -- "$@" && return 0 || rc=$?
    if [ "$rc" -ne 255 ] || ssh_master_up; then return "$rc"; fi
    log "  SSH connection dropped; reconnecting (attempt ${attempt} of 3)..."
  done
  return "$rc"
}

# rssh_stdin <command...>: as rssh, for a command that reads stdin. Reconnects first
# if needed, but never retries the command itself.
rssh_stdin() {
  ssh_connect 300 || return 255
  ssh "${CLIENT_OPTS[@]}" "deploy@${SERVER_IP}" -- "$@"
}

# rscp <src> <remote-dst>: copy over the shared connection, retrying a dropped one.
rscp() {
  local attempt rc=255
  for attempt in 1 2 3; do
    ssh_connect 300 || return 255
    scp -q "${CLIENT_OPTS[@]}" "$1" "deploy@${SERVER_IP}:$2" && return 0 || rc=$?
    ssh_master_up && return "$rc"
    log "  SSH connection dropped during a copy; reconnecting (attempt ${attempt} of 3)..."
  done
  return "$rc"
}

# Provisioner connects as the non-root `deploy` user (root SSH login is disabled
# in cloud-init). deploy has NOPASSWD sudo, so privileged work is `sudo`-wrapped.
remote() { rssh sudo "$@"; }

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
  stage="$(rssh 'umask 077; mktemp /tmp/prov.XXXXXXXXXX')"
  [ -n "$stage" ] || { log "ERROR: could not create a staging file on ${SERVER_IP}"; return 1; }
  rscp "$src" "${stage}"
  remote install -m "$perms" "$stage" "$dst"
  rssh rm -f "$stage"
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

# A fresh node: rebuilt, or never fully provisioned (no server id recorded yet). Only a
# fresh node is rebooted into an installed kernel fix here (§10); a live one waits for
# the 03:30 unattended-upgrades window.
if [ "${VIADUCT_HOST_KEY_RESET:-0}" = "1" ] || [ ! -f "${BACKUPS_DIR}/known_hosts.serverid" ] || \
   vh_server_was_rebuilt "${SERVER_ID:-}" "${BACKUPS_DIR}/known_hosts.serverid"; then
  FRESH=1
else
  FRESH=0
fi

# ── Phase A: wait for SSH to succeed (bounded ~10 min); opens the one connection.
log "Waiting for ${SERVER_IP} to accept SSH (up to 10 min)..."
ssh_connect 600 || exit 1
log "SSH established."

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
      if ! vh_is_uuid "$(cat "$f")"; then
        log "ERROR: $f does not contain a UUID. Refusing to upload it."
        log "       A backup carrying a planted value would otherwise survive a rebuild."
        exit 1
      fi
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

# ── 6b. Cloudflare credentials and the TLS certificate ────────────────────────
# The token arrives here rather than in user_data. certbot's renewal timer reads the
# same file, so it stays on the box (root, 0600). The first certificate is issued
# once; on a box that already has one, certbot is not run.

upload "$CF_INI" "/etc/cloudflare-certbot.ini" "600"
if ! remote test -d "/etc/letsencrypt/live/${VLESS_DOMAIN}"; then
  log "Obtaining the TLS certificate for ${VLESS_DOMAIN} (DNS-01)..."
  remote certbot certonly --dns-cloudflare \
    --dns-cloudflare-credentials /etc/cloudflare-certbot.ini \
    -d "${VLESS_DOMAIN}" --non-interactive --agree-tos \
    --register-unsafely-without-email --dns-cloudflare-propagation-seconds 30
fi
remote nginx -t

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
    # The listing comes from the node, so a .uuid is untrusted until it looks like
    # one. Discard rather than store: a bad value kept here is re-uploaded next apply.
    if [[ "$name" == *.uuid ]] && ! vh_is_uuid "$(cat "$BACKUPS_DIR/clients/$name")"; then
      rm -f "$BACKUPS_DIR/clients/$name"
      log "  WARNING: $name from the node is not a UUID — discarded, not backed up."
    else
      log "  Saved backups/clients/$name"
    fi
  fi
done 3< <(rssh "sudo sh -c 'ls /etc/xray/clients/*.uuid /etc/xray/clients/*.txt 2>/dev/null || true'")

# ── 10. Run the installed kernel ──────────────────────────────────────────────
# The boot baseline installs kernel fixes, but the node keeps running the kernel it
# booted until something reboots it. A fresh node is rebooted now, so it never serves
# on a kernel with a known fix pending; a live node is left to the 03:30 window.
if remote "grep -q '^linux-' /run/reboot-required.pkgs" 2>/dev/null; then
  if [ "$FRESH" = 1 ]; then
    log "A kernel update is installed but not running; rebooting into it..."
    # Not rssh: a retry after the connection drops would reboot the node a second time.
    # --no-block returns before the shutdown begins.
    ssh "${CLIENT_OPTS[@]}" "deploy@${SERVER_IP}" -- sudo systemctl reboot --no-block || true
    ssh -o ControlPath="${CONTROL_SOCKET}" -O exit "deploy@${SERVER_IP}" >/dev/null 2>&1 || true
    sleep 30   # let sshd stop, so the reconnect below does not reach the old boot
    ssh_connect 600 || { log "ERROR: ${SERVER_IP} did not come back after the kernel reboot."; exit 1; }
    if remote "grep -q '^linux-' /run/reboot-required.pkgs" 2>/dev/null; then
      log "ERROR: still not running the installed kernel after a reboot ($(rssh uname -r))."
      exit 1
    fi
    log "Running kernel $(rssh uname -r)."
    if remote systemctl is-active --quiet conduit xray xray-exporter xray-user-stats alloy nginx xray-probe-client probe; then
      log "All services active after the reboot."
    else
      log "WARNING: one or more services did not come back after the reboot. Check: sudo ops-journal <unit>"
    fi
  else
    log "NOTE: a kernel update is installed but not running; unattended-upgrades reboots into it at 03:30."
  fi
fi

log ""
log "Provisioning complete."
log "VLESS URIs are in: $BACKUPS_DIR/clients/*.txt"
log "Metrics flowing to Grafana Cloud."

# Everything above succeeded (set -e), so this box is fully provisioned. Record its
# hcloud server id as the baseline the next apply compares against to detect a
# rebuild. Last, so a run that fails partway is retried as a fresh node.
vh_record_server_id "${SERVER_ID:-}" "${BACKUPS_DIR}/known_hosts.serverid"
