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
: "${PROBE_SRC:?}"

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

# A `terraform -replace` rebuild keeps the static IP but regenerates the SSH
# host keys. Drop any stale key for this IP from our dedicated known_hosts so
# the SSH below can accept-new the fresh key instead of hard-failing on a
# changed host key (StrictHostKeyChecking=accept-new rejects *changed* keys).
# Mirrors the same treatment applied to the GCP host below.
ssh-keygen -R "${SERVER_IP}" -f "${BACKUPS_DIR}/known_hosts" >/dev/null 2>&1 || true

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
    log "  ssh root@${SERVER_IP} 'cloud-init status --long; journalctl -u cloud-init --no-pager -n 100'"
    exit 1
  fi
  if echo "$CI_STATUS" | grep -q "status: done" && remote "test -f /var/lib/cloud-init-done" 2>/dev/null; then
    log "cloud-init complete."
    break
  fi
  if (( SECONDS >= CI_DEADLINE )); then
    log "ERROR: timed out after 10 min waiting for cloud-init (status may be stuck 'running')."
    log "  ssh root@${SERVER_IP} 'cloud-init status --long; journalctl -u cloud-init --no-pager -n 100'"
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

# ── 8. Build + upload the probe binary (linux/amd64) ─────────────────────
log "Building probe (linux/amd64)..."
( cd "$PROBE_SRC" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "${CONTROL_DIR}/probe" . )
# Upload to a temp path then atomically mv into place. A direct scp truncates
# the destination in place, which the kernel refuses (ETXTBSY) when probe.service
# is already running the old binary. rename() swaps the inode without touching
# the busy one; the running process keeps the old inode until its restart below.
upload "${CONTROL_DIR}/probe" "/usr/local/bin/probe.new" "755"
remote mv -f /usr/local/bin/probe.new /usr/local/bin/probe

# ── 9. Start / restart all services ──────────────────────────────────────────

log "Starting services..."
remote systemctl restart conduit xray xray-exporter xray-user-stats alloy nginx xray-probe-client probe

sleep 5
if remote systemctl is-active --quiet conduit xray xray-exporter xray-user-stats alloy nginx xray-probe-client probe; then
  log "All services active."
else
  log "WARNING: one or more services failed to start. Check: journalctl -u conduit -u xray -u xray-exporter -u xray-user-stats -u alloy -u nginx"
fi

# ── 8b. SPIRE agent: trust bundle + join token from the GCP SPIRE server ──────
# Optional — only runs when GCP_SERVER_IP is set (the multi-cloud lab). The
# agent binary, config, and unit are installed by cloud-init; here we fetch the
# bundle + a one-time join token from the GCP SPIRE server and start the agent.
# GCP must be deployed (SPIRE server running) before Hetzner.

if [[ -n "${GCP_SERVER_IP:-}" ]]; then
  if remote "systemctl is-active --quiet spire-agent" 2>/dev/null; then
    log "SPIRE agent already running — skipping attestation."
  else
    log "Fetching SPIRE trust bundle + join token from GCP server ${GCP_SERVER_IP}..."
    GCP_KEY="${GCP_SSH_KEY_PATH/#\~/$HOME}"
    GCP_OPTS=(-i "${GCP_KEY}" -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=30 -o LogLevel=ERROR)
    # Drop any stale host key (the GCP node may have been rebuilt with a new one).
    ssh-keygen -R "${GCP_SERVER_IP}" >/dev/null 2>&1 || true
    GCP_SSH=(ssh "${GCP_OPTS[@]}" "${GCP_SSH_USER}@${GCP_SERVER_IP}")

    "${GCP_SSH[@]}" -- "sudo spire-server bundle show" > "${CONTROL_DIR}/bundle.crt"
    TOKEN=$("${GCP_SSH[@]}" -- "sudo spire-server token generate -spiffeID spiffe://${TRUST_DOMAIN}/hetzner -ttl 600" | awk '/Token:/{print $2}')
    [[ -n "$TOKEN" ]] || { log "ERROR: failed to mint SPIRE join token from GCP server."; exit 1; }

    upload "${CONTROL_DIR}/bundle.crt" "/opt/spire/agent/bootstrap.crt" "644"
    remote "umask 077; printf 'JOIN_TOKEN_ARG=-joinToken %s\n' '$TOKEN' > /opt/spire/agent/join.env"
    remote "systemctl daemon-reload && systemctl enable --now spire-agent"
    sleep 3
    if remote "systemctl is-active --quiet spire-agent"; then
      log "SPIRE agent attested and running."
    else
      log "WARNING: spire-agent failed to start. Check: journalctl -u spire-agent"
    fi
  fi
fi

# ── 10. Download fresh backups ─────────────────────────────────────────────────

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
