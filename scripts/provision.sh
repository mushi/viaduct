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

# Shared guards: host-key pinning + the allowlists applied to any value that a
# remote node produces before it is interpolated into a root command elsewhere.
# shellcheck source=scripts/lib/provision-guards.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/provision-guards.sh"

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

upload() {
  local src="$1" dst="$2" perms="${3:-0644}"
  # deploy can't write system paths directly; stage in /tmp, then install as root.
  # $$ is the local provisioner's PID and the basename is known, so the old
  # /tmp/prov.$$.<name> path was guessable by any account on the target. A file or
  # symlink pre-created there receives the uploaded content — which includes
  # keypair.env and client UUIDs. Let the remote side pick an unpredictable name.
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
# fresh one. That is a deliberate, infrequent act: dropping the pin on *every*
# apply meant accept-new re-trusted whatever key answered for SERVER_IP, which
# is precisely the check that catches an on-path attacker.
#
# Set VIADUCT_HOST_KEY_RESET=1 when you are knowingly rebuilding. Otherwise the
# pin is kept, and a genuinely changed key surfaces as the host-key failure
# handled in Phase A below — which prints the exact command to clear it.
vh_reset_host_key_pin_if_requested "${SERVER_IP}" "${BACKUPS_DIR}/known_hosts"

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
  printf '%s\n' "$WG_CONF" | $SSH -- "sudo sh -c 'umask 077; cat > /etc/wireguard/wg0.conf'"
  $SSH -- "sudo sh -c 'systemctl daemon-reload && systemctl enable wg-quick@wg0 && systemctl restart wg-quick@wg0'"
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
  if remote "systemctl is-active --quiet spire-agent" 2>/dev/null; then
    log "SPIRE agent already running — skipping attestation."
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
    printf '%s\n' "$TOKEN" | $SSH -- "sudo /usr/local/sbin/spire-agent-join-token"
    $SSH -- "sudo sh -c 'systemctl daemon-reload && systemctl enable --now spire-agent'"
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
    for _ in 1 2 3 4 5; do
      remote "systemctl restart hetzner-secrets.service" 2>/dev/null || true
      remote "test -s /run/hetzner-secrets/grafana.env" && break
      sleep 5
    done
    if remote "test -s /run/hetzner-secrets/grafana.env" && remote "test -s /run/hetzner-secrets/cloudflare.ini"; then
      log "Vault secrets rendered to tmpfs."
      # Initial TLS cert (guarded so routine re-applies do not re-hit Let's Encrypt). nginx
      # and alloy themselves are (re)started in section 9 below, once this cert + grafana.env exist.
      if [[ -n "${VLESS_DOMAIN:-}" ]] && ! remote "test -d /etc/letsencrypt/live/${VLESS_DOMAIN}"; then
        log "Obtaining the initial Let's Encrypt cert for ${VLESS_DOMAIN}..."
        remote "certbot certonly --dns-cloudflare --dns-cloudflare-credentials /run/hetzner-secrets/cloudflare.ini -d ${VLESS_DOMAIN} --non-interactive --agree-tos --register-unsafely-without-email --dns-cloudflare-propagation-seconds 30" \
          && log "Initial cert obtained." \
          || log "WARNING: certbot failed; check the token in kv/hetzner/cloudflare."
      fi
    else
      log "WARNING: Vault secrets not rendered; Alloy + certbot will lack credentials. Check 'journalctl -u hetzner-secrets' and that kv/hetzner/{grafana,cloudflare} are seeded."
    fi
  fi
fi

# ── 9. Start / restart all services ──────────────────────────────────────────
# After section 8b: the mesh is up, secrets are in tmpfs (alloy's EnvironmentFile), and the
# TLS cert exists (nginx). Tolerant restart so one failing unit warns rather than aborting.
log "Starting services..."
remote systemctl restart conduit xray xray-exporter xray-user-stats alloy nginx xray-probe-client probe || true

sleep 5
if remote systemctl is-active --quiet conduit xray xray-exporter xray-user-stats alloy nginx xray-probe-client probe; then
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
while IFS= read -r rf; do
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
done < <($SSH -- "sudo sh -c 'ls /etc/xray/clients/*.uuid /etc/xray/clients/*.txt 2>/dev/null || true'")

log ""
log "Provisioning complete."
log "VLESS URIs are in: $BACKUPS_DIR/clients/*.txt"
log "Metrics flowing to Grafana Cloud."
