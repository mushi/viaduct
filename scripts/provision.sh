#!/usr/bin/env bash
# scripts/provision.sh
#
# Executed locally by Terraform's terraform_data.provision via local-exec.
# Environment variables set by Terraform:
#   SERVER_IP    — public IPv4 of the server
#   SSH_KEY_PATH — local path to the SSH private key
#   BACKUPS_DIR  — local path to the backups/ directory
#   USERS_FILE   — local path to the generated users.txt
#   ALLOY_CONFIG — local path to the rendered alloy-config.alloy
#
# Every SSH and SCP operation shares one connection, opened once per run (see
# "One SSH connection per run" below).

set -euo pipefail

: "${SERVER_IP:?}"
: "${SSH_KEY_PATH:?}"
: "${BACKUPS_DIR:?}"
: "${USERS_FILE:?}"
: "${ALLOY_CONFIG:?}"
: "${PROBE_SRC:?}"

# Shared guards: host-key pinning + the allowlists applied to any value that a
# remote node produces before it is interpolated into a root command elsewhere.
# shellcheck source=scripts/lib/provision-guards.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${SCRIPT_DIR}/lib/provision-guards.sh"

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

upload() {
  local src="$1" dst="$2" perms="${3:-0644}"
  # deploy can't write system paths directly; stage in /tmp, then install as root.
  # $$ is the local provisioner's PID and the basename is known, so the old
  # /tmp/prov.$$.<name> path was guessable by any account on the target. A file or
  # symlink pre-created there receives the uploaded content — which includes
  # keypair.env and client UUIDs. Let the remote side pick an unpredictable name.
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
  # missing source never leaves a truncated file in backups/.
  # Create the partial file private: a redirect at the ambient umask leaves retrieved
  # key material world-readable on the operator workstation until the chmod lands.
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

# A `terraform -replace` rebuild keeps the static IP but regenerates the SSH
# host keys, so the stale pin has to go before the SSH below can accept-new the
# fresh one. A rebuild is detected automatically: SERVER_ID (the hcloud server
# id) changes only on a recreate, and the guard clears the pin when it differs
# from the id recorded next to known_hosts. A key change NOT backed by a new id
# (the on-path-attacker case) is left pinned and fails closed in Phase A below.
#
# VIADUCT_HOST_KEY_RESET=1 forces the reset — the escape hatch for an out-of-band
# key change that kept the same server id (e.g. an OS reinstall).
# Detect a re-keyed box once, before the id is re-recorded after Phase A: either the
# hcloud server id changed (a genuine -replace) or the operator forced it. The same
# signal clears the host-key pin (next) AND rotates this spoke's WireGuard registry
# key (§8b), so a rebuild self-heals with no manual step.
if [ "${VIADUCT_HOST_KEY_RESET:-0}" = "1" ] || \
   vh_server_was_rebuilt "${SERVER_ID:-}" "${BACKUPS_DIR}/known_hosts.serverid"; then
  REBUILT=1
else
  REBUILT=0
fi
# A fresh node: rebuilt, or never fully provisioned (no server id recorded yet). Only a
# fresh node is rebooted into an installed kernel fix here (§11); a live one waits for
# the 03:30 unattended-upgrades window.
if [ "$REBUILT" = 1 ] || [ ! -f "${BACKUPS_DIR}/known_hosts.serverid" ]; then
  FRESH=1
else
  FRESH=0
fi

vh_reset_host_key_pin_if_requested "${SERVER_IP}" "${BACKUPS_DIR}/known_hosts" \
  "${SERVER_ID:-}" "${BACKUPS_DIR}/known_hosts.serverid"

# ── Phase A: wait for SSH to succeed (bounded ~10 min); opens the one connection.
log "Waiting for ${SERVER_IP} to accept SSH (up to 10 min)..."
ssh_connect 600 || exit 1
log "SSH established."
# The server-id record is written at the very END of this script, not here: it is the
# baseline that detects the NEXT rebuild, and it must not advance until provisioning
# (including the WireGuard registration in §8b) has fully succeeded — otherwise a failure
# after this point would burn the REBUILT signal and a retry would skip the auto-rotation.

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
      # These came off a node on some earlier run. Shape-check before pushing them
      # back: the node renders them into config.json and every client URI.
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

# ── 6b. Converge the Vault secret-fetch script and Alloy's journal access ─────
# Both of these otherwise ship only inside cloud-init user_data, and main.tf pins
# `ignore_changes = [user_data]`, so an edit to either reaches a running box only on a
# rebuild. That is how the node ended up running a config.alloy that referenced
# GRAFANA_LOKI_URL against a grafana.env the old fetch script never wrote it into —
# Alloy loaded, reported every component healthy, and shipped nothing. Upload them here
# so a plain `terraform apply` converges an existing node.
upload "${SCRIPT_DIR}/lib/mesh-trust.sh" "/usr/local/bin/lib/mesh-trust.sh" "644"
upload "${SCRIPT_DIR}/fetch-hetzner-secrets.sh" "/usr/local/bin/fetch-hetzner-secrets.sh" "755"

# loki.source.journal reads the journal files, which are group-readable only by
# systemd-journal (mode 2640). cloud-init sets SupplementaryGroups in the unit for fresh
# builds; this drop-in is the same grant for a box built before that, and a harmless
# duplicate on one built after. Without it the journal source reads zero entries and
# reports healthy — a silent failure with no error anywhere.
# Staged and uploaded rather than written by a remote redirect: `remote` sudo-prefixes the
# COMMAND, but a `>` in the string is applied by the remote login shell as `deploy`, which
# cannot write under /etc. upload() installs as root and is the idiom used everywhere else.
printf '[Service]\nSupplementaryGroups=systemd-journal\n' > "${CONTROL_DIR}/10-journal.conf"
remote install -d -m 0755 /etc/systemd/system/alloy.service.d
upload "${CONTROL_DIR}/10-journal.conf" "/etc/systemd/system/alloy.service.d/10-journal.conf" "644"
remote systemctl daemon-reload

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

# Services are (re)started in section 9 below, AFTER section 8b brings up the mesh and
# fetches the Vault secrets + TLS cert that nginx and alloy now depend on.

# ── 8b. WireGuard mesh + SPIRE agent (multi-cloud lab; GCP_SERVER_IP set) ─────
# Both steps reach the GCP control plane over IAP TCP forwarding (the admin
# channel — GCP has no public SSH), reusing the instance-metadata key. gcloud
# tracks host keys by instance ID, so a rebuilt server does not jam on a stale
# key the way IP-keyed ssh did. GCP must be deployed (SPIRE server running) first.
#
# ORDER MATTERS: the mesh comes up FIRST, because the SPIRE agent's runtime
# server_address is now the hub's MESH IP (10.99.0.1) — the agent can only reach
# the server once wg0 is up. Bootstrap itself (peer registration, token mint)
# rides IAP, never the mesh, so it works before the mesh exists and after the
# Phase-2 lockdown drops the public control-plane ports.
if [[ -n "${GCP_SERVER_IP:-}" ]]; then
  command -v gcloud >/dev/null || { log "ERROR: gcloud not found; required to reach the IAP-only GCP control plane."; exit 1; }
  : "${GCP_INSTANCE:?GCP_INSTANCE required to reach the GCP control plane via IAP}"
  : "${GCP_ZONE:?GCP_ZONE required to reach the GCP control plane via IAP}"
  : "${WG_PORT:?}" "${WG_MESH_IP:?}"
  GCP_KEY="${GCP_SSH_KEY_PATH/#\~/$HOME}"
  gcp_ssh() {
    gcloud compute ssh "${GCP_SSH_USER}@${GCP_INSTANCE}" \
      --zone "${GCP_ZONE}" ${GCP_PROJECT:+--project "${GCP_PROJECT}"} \
      --tunnel-through-iap --ssh-key-file="${GCP_KEY}" \
      --ssh-flag="-o StrictHostKeyChecking=accept-new" \
      --ssh-flag="-o ConnectTimeout=30" \
      --command "$1"
  }

  # ── 8b-i. WireGuard mesh: register with the hub and bring up wg0 ────────────
  # cloud-init generated this node's WG key (0600 on disk). Publish its public key
  # to the hub's Vault registry over IAP, receive the hub's public key + endpoint +
  # the shared PSK, write wg0.conf, start wg-quick. The hub adds us as a live peer
  # inside wg-register-peer.sh.
  log "Registering WireGuard peer with the hub ${GCP_INSTANCE} (via IAP)..."
  HZ_PUB="$(remote cat /etc/wireguard/wg0.pub)"
  [[ -n "$HZ_PUB" ]] || { log "ERROR: Hetzner wg0.pub missing (cloud-init key-gen did not run)."; exit 1; }

  # HZ_PUB is produced by the Hetzner node and is about to be interpolated into a
  # string that gcloud hands to a shell on the HUB, under sudo. Non-empty is not a
  # security check: root on the spoke could return "x; <command> #" and execute it
  # as root on the control plane. Admit only the exact WireGuard key shape.
  vh_require vh_is_wg_key  "Hetzner wg0.pub (HZ_PUB)" "$HZ_PUB"   || exit 1
  vh_require vh_is_mesh_ip "mesh IP (WG_MESH_IP)"     "$WG_MESH_IP" || exit 1

  # On a genuine rebuild the box generated a fresh WireGuard key, so the registry
  # still holds the old one and the hub refuses a re-register. Clear the stale entry
  # first — authorised by the rebuild signal (an id change only the operator's
  # -replace produces), so a routine re-provision (same key) never rotates the PSK.
  # Tolerant: an un-updated hub without the script just falls back to the refusal.
  if [ "${REBUILT}" = "1" ]; then
    log "WireGuard: rebuild detected — rotating this spoke's mesh registry key."
    gcp_ssh "sudo /usr/local/bin/wg-deregister-peer.sh hetzner" >/dev/null 2>&1 \
      || log "  (deregister skipped: hub lacks wg-deregister-peer.sh or it failed; register will print the manual step if the key differs)"
  fi

  REG_OUT="$(gcp_ssh "sudo /usr/local/bin/wg-register-peer.sh hetzner '${HZ_PUB}' '${WG_MESH_IP}'")"
  HUB_PUB="$(printf '%s\n' "$REG_OUT" | awk '/^hub_public_key /{print $2}')"
  WG_PSK="$(printf  '%s\n' "$REG_OUT" | awk '/^psk /{print $2}')"
  [[ -n "$HUB_PUB" && -n "$WG_PSK" ]] || { log "ERROR: hub registration returned no key/psk. Is GCP on the current startup.sh?"; exit 1; }

  # Both values come from the hub's reply and are interpolated into the unquoted
  # wg0.conf heredoc below. A reply carrying a newline would not corrupt one value
  # — it would add WireGuard directives (an AllowedIPs = 0.0.0.0/0 and an attacker
  # Endpoint route this node's traffic). The key shape admits no newline.
  vh_require vh_is_wg_key "hub public key (HUB_PUB)" "$HUB_PUB" || exit 1
  vh_require vh_is_wg_key "mesh preshared key (WG_PSK)" "$WG_PSK" || exit 1

  # %i stays literal for wg-quick; the heredoc is unquoted so the vars expand.
  WG_CONF="$(cat <<EOF
[Interface]
Address = ${WG_MESH_IP}/24
PostUp = wg set %i private-key /etc/wireguard/wg0.key

[Peer]
PublicKey = ${HUB_PUB}
PresharedKey = ${WG_PSK}
Endpoint = ${GCP_SERVER_IP}:${WG_PORT}
AllowedIPs = 10.99.0.0/24
PersistentKeepalive = 25
EOF
)"
  # Compound write to a root-owned 0600 path: pipe in and let one sudo shell write it.
  printf '%s\n' "$WG_CONF" | rssh_stdin "sudo sh -c 'umask 077; cat > /etc/wireguard/wg0.conf'"
  rssh "sudo sh -c 'systemctl daemon-reload && systemctl enable wg-quick@wg0 && systemctl restart wg-quick@wg0'"
  sleep 2
  if remote "wg show wg0 >/dev/null 2>&1"; then
    log "WireGuard mesh: wg0 up (hub 10.99.0.1, self ${WG_MESH_IP})."
  else
    log "WARNING: wg0 failed to come up. Check: journalctl -u wg-quick@wg0"
  fi

  # ── 8b-ii. SPIRE agent: trust bundle + join token, then start ───────────────
  # The agent binary, config, and unit are installed by cloud-init; here we fetch
  # the bundle + a one-time join token from the GCP SPIRE server and start the
  # agent. It dials server_address = 10.99.0.1 (mesh) — hence AFTER the mesh above.
  # Ask whether the agent is ATTESTED, not whether systemd has a process. A crashlooping
  # unit cycles active -> failed -> activating, so `systemctl is-active` answers differently
  # depending on the instant it is sampled: on 2026-09-05 it returned true for an agent with
  # 821 restarts and an expired SVID, the run logged "already running", skipped the mint, and
  # left the node without an identity. `healthcheck` fails unless the Workload API is serving,
  # which is exactly the condition that makes re-attestation unnecessary.
  if remote "/usr/local/bin/spire-agent healthcheck -socketPath /run/spire-agent/public/api.sock >/dev/null 2>&1"; then
    log "SPIRE agent healthy and attested — skipping attestation."
  else
    log "Fetching SPIRE trust bundle + join token from GCP server ${GCP_INSTANCE} (via IAP)..."
    gcp_ssh "sudo spire-server bundle show" > "${CONTROL_DIR}/bundle.crt"
    TOKEN=$(gcp_ssh "sudo spire-server token generate -spiffeID spiffe://${TRUST_DOMAIN}/hetzner -ttl 600" | awk '/Token:/{print $2}')
    [[ -n "$TOKEN" ]] || { log "ERROR: failed to mint SPIRE join token from GCP server."; exit 1; }

    upload "${CONTROL_DIR}/bundle.crt" "/opt/spire/agent/bootstrap.crt" "644"
    # Piped over stdin into a root-only setter, which writes it into agent.conf.
    # Never as an argument: an EnvironmentFile expanded into ExecStart put the token
    # in /proc/<pid>/cmdline, and a token on this command line would be visible in
    # the node's own process list just as plainly.
    printf '%s\n' "$TOKEN" | rssh_stdin "sudo /usr/local/sbin/spire-agent-join-token"
    rssh "sudo sh -c 'systemctl daemon-reload && systemctl enable --now spire-agent'"
    sleep 3
    if remote "systemctl is-active --quiet spire-agent"; then
      log "SPIRE agent attested and running."
    else
      log "WARNING: spire-agent failed to start. Check: journalctl -u spire-agent"
    fi
  fi

  # ── 8b-iii. Register the vault-agent workload entry on the GCP SPIRE server ────
  # The one-shot secrets fetch (fetch-hetzner-secrets.sh) runs as the viaduct-secrets
  # user; SPIRE issues it the vault-agent SVID by matching unix:uid. The agent's own
  # ID is spiffe://TRUST_DOMAIN/hetzner (set by the join token's -spiffeID), so that is
  # the stable parent. Delete-then-create so the selector always tracks the current uid
  # (a rebuilt box may reallocate it).
  SECRETS_UID="$(remote id -u viaduct-secrets 2>/dev/null || true)"
  if [[ -n "$SECRETS_UID" ]]; then
    # Produced by the Hetzner node and interpolated below into a spire-server
    # command string that runs as root on the hub. Digits only — a uid has no
    # legitimate reason to contain anything a shell would act on.
    vh_require vh_is_uid "viaduct-secrets uid (SECRETS_UID)" "$SECRETS_UID" || exit 1

    log "Registering the hetzner vault-agent SPIRE entry (uid ${SECRETS_UID})..."
    EID="$(gcp_ssh "sudo spire-server entry show -spiffeID spiffe://${TRUST_DOMAIN}/hetzner/vault-agent" 2>/dev/null | awk '/Entry ID/{print $NF}')"
    [[ -n "$EID" ]] && gcp_ssh "sudo spire-server entry delete -entryID ${EID}" >/dev/null 2>&1 || true
    gcp_ssh "sudo spire-server entry create \
      -spiffeID spiffe://${TRUST_DOMAIN}/hetzner/vault-agent \
      -parentID spiffe://${TRUST_DOMAIN}/hetzner \
      -selector unix:uid:${SECRETS_UID} \
      -dns vault-agent.hetzner" >/dev/null \
      && log "vault-agent SPIRE entry registered." \
      || log "WARNING: vault-agent SPIRE entry create failed; check the GCP SPIRE server."
  else
    log "WARNING: viaduct-secrets user not found on the box; skipping vault-agent SPIRE entry."
  fi

  # ── 8b-iv. Fetch the Vault-delivered secrets, then start their consumers ────────
  # Mesh + SPIRE agent + the vault-agent entry now exist, so the box can fetch
  # kv/hetzner/{grafana,cloudflare} from Vault into tmpfs. Alloy needs grafana.env;
  # certbot needs cloudflare.ini for the initial cert. The entry can take a few seconds
  # to reach the agent, so retry the fetch.
  if [[ -n "$SECRETS_UID" ]]; then
    log "Fetching Hetzner secrets from Vault into tmpfs..."
    # Ask the unit whether it SUCCEEDED, not whether the files exist. hetzner-secrets is
    # Type=oneshot with RemainAfterExit=yes, so is-active is true only after a clean run.
    # `test -s` was checking a tmpfs artifact that outlives the run that wrote it: on
    # 2026-09-05 it passed against a grafana.env rendered the previous day while the unit
    # was crashlooping on a failed SVID fetch, and the provisioner reported success.
    for _ in 1 2 3 4 5; do
      remote "systemctl restart hetzner-secrets.service" 2>/dev/null || true
      remote "systemctl is-active --quiet hetzner-secrets.service" && break
      sleep 5
    done
    if remote "systemctl is-active --quiet hetzner-secrets.service"; then
      # hetzner-secrets-ready.path is PathExists=, which fires on the file appearing, not on
      # it changing. On a box where grafana.env already existed (the common re-provision) the
      # re-render above adds the Loki variables without retriggering anything, so restart
      # Alloy here to pick them up. Tolerant: on a first deploy the .path has it covered.
      remote systemctl restart alloy.service 2>/dev/null || true
      log "Vault secrets rendered to tmpfs. The TLS cert and Alloy/nginx are obtained/started"
      log "on the box by hetzner-secrets-ready.path — the provisioner no longer runs certbot"
      log "itself (two certbot instances at once collide on its lock)."
    else
      log "NOTE: secrets not rendered in-band yet (the mesh is still converging). No action needed:"
      log "      hetzner-secrets retries every 15s until it succeeds, and hetzner-secrets-ready.path"
      log "      then obtains the cert and starts Alloy/nginx automatically. If it never renders,"
      log "      check 'journalctl -u hetzner-secrets' and that kv/hetzner/{grafana,cloudflare} are seeded."
    fi
  fi
fi

# ── 9. Start / restart all services ──────────────────────────────────────────
# The secret-dependent services (alloy, nginx) are NOT restarted here: they are owned by
# hetzner-secrets-ready.path on the box, which obtains the cert and starts them once the
# Vault secrets render — however long the mesh takes to converge. Restarting them here would
# race that (and fail before the cert/grafana.env exist). Tolerant restart of the rest.
log "Starting services..."
remote systemctl restart conduit xray xray-exporter xray-user-stats xray-probe-client probe || true

sleep 5
if remote systemctl is-active --quiet conduit xray xray-exporter xray-user-stats xray-probe-client probe; then
  log "All services active."
else
  log "WARNING: one or more services failed to start. Check: journalctl -u conduit -u xray -u xray-exporter -u xray-user-stats -u alloy -u nginx"
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
#
# The list is read on FD 3, not stdin: download() runs `ssh` (via remote cat), and
# ssh with an inherited stdin would read the rest of this list itself — draining the
# pipe so the loop stops after the first file. That silently backed up only the first
# client and lost every other user's .uuid/.txt (observed 2026-08-14). Keeping the list
# on FD 3 leaves the inner ssh's stdin alone.
while IFS= read -r rf <&3; do
  [[ -z "$rf" ]] && continue
  name=$(basename "$rf")
  if download "$rf" "$BACKUPS_DIR/clients/$name"; then
    # The remote listing is produced by the node, so treat every .uuid it hands
    # back as untrusted until it looks like a UUID. Discard rather than store:
    # a bad value kept here is re-uploaded on the next apply.
    if [[ "$name" == *.uuid ]] && ! vh_is_uuid "$(cat "$BACKUPS_DIR/clients/$name")"; then
      rm -f "$BACKUPS_DIR/clients/$name"
      log "  WARNING: $name from the node is not a UUID — discarded, not backed up."
    else
      log "  Saved backups/clients/$name"
    fi
  fi
done 3< <(rssh "sudo sh -c 'ls /etc/xray/clients/*.uuid /etc/xray/clients/*.txt 2>/dev/null || true'")

# ── 11. Run the installed kernel ──────────────────────────────────────────────
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
    if remote systemctl is-active --quiet conduit xray xray-exporter xray-user-stats xray-probe-client probe; then
      log "All services active after the reboot."
    else
      log "WARNING: one or more services did not come back after the reboot. Check: journalctl -u conduit -u xray -u xray-exporter -u xray-user-stats -u probe"
    fi
  else
    log "NOTE: a kernel update is installed but not running; unattended-upgrades reboots into it at 03:30."
  fi
fi

log ""
log "Provisioning complete."
log "VLESS URIs are in: $BACKUPS_DIR/clients/*.txt"
log "Metrics flowing to Grafana Cloud."

# Everything above succeeded (set -e), so this box is fully provisioned. Record its hcloud
# server id as the baseline the next apply compares against to detect a rebuild — driving
# both the host-key-pin clear and the WireGuard peer-key rotation. Deferred to here (not
# right after SSH) so a failure mid-provision leaves the signal intact for the retry.
vh_record_server_id "${SERVER_ID:-}" "${BACKUPS_DIR}/known_hosts.serverid"
