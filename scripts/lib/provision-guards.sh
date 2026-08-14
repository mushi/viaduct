#!/usr/bin/env bash
# scripts/lib/provision-guards.sh
#
# Shared guards for the provisioning scripts (scripts/provision.sh and
# aws/scripts/wg-mesh-join.sh). Sourced, never executed directly.
#
# These functions sit on the boundary where a value produced by one node is
# about to be interpolated into a command string executed as root on a
# *different* node. Quoting alone is not sufficient there, so every value is
# checked against a strict allowlist and rejected outright if it does not match.

# ── Host-key pinning ─────────────────────────────────────────────────────────

# vh_server_was_rebuilt <server_id> <serverid_file>
#
# True (0) iff an id was recorded on a previous run and differs from the current
# one — i.e. the instance was recreated since the last successful provision. False
# when no id is recorded yet (first run / adoption) or the ids match. The id is
# minted by the cloud provider and read from terraform state, so it is a rebuild
# signal an on-path attacker cannot forge. Drives both the host-key-pin reset and
# the WireGuard peer-key rotation, so a genuine rebuild self-heals with no flag.
vh_server_was_rebuilt() {
    local server_id="${1:-}" serverid_file="${2:-}" recorded
    [ -n "$server_id" ] && [ -n "$serverid_file" ] && [ -f "$serverid_file" ] || return 1
    recorded="$(cat "$serverid_file" 2>/dev/null || true)"
    [ -n "$recorded" ] && [ "$recorded" != "$server_id" ]
}

# vh_reset_host_key_pin_if_requested <host> <known_hosts_file> [server_id] [serverid_file]
#
# Remove a recorded host key ONLY when the box was genuinely rebuilt — never on
# an ordinary apply. A `terraform -replace` regenerates the box's SSH host keys
# while keeping the static IP, so the stale pin has to go; but clearing it on
# every apply would let the following SSH (StrictHostKeyChecking=accept-new)
# re-trust whatever key answered, which is exactly the check that catches an
# on-path attacker.
#
# Two ways the reset is authorised, in order:
#
#   1. VIADUCT_HOST_KEY_RESET=1 — explicit operator override. The escape hatch for
#      the one case auto-detection deliberately will NOT act on: an out-of-band
#      key change on the same server (e.g. an OS reinstall that keeps the hcloud
#      server id). A genuinely changed key with no new id must stay operator-gated.
#
#   2. The hcloud server id changed since the pin was recorded. The id is minted
#      by hcloud and read into terraform state; it changes only when the instance
#      is recreated, which is also the only thing that regenerates the host keys.
#      An attacker MITM-ing the SSH to the static IP cannot forge a new id (that
#      needs hcloud-account compromise, a strictly higher bar), so clearing the
#      stale pin here is safe. A key change NOT backed by a new id (the MITM case:
#      same id, unexpected key) is left pinned and fails closed on the next SSH.
#
# When neither holds and the key really did change, the SSH in provision.sh fails
# with a host-key error and prints the exact command to run.
vh_reset_host_key_pin_if_requested() {
    local host="$1" known_hosts="$2" server_id="${3:-}" serverid_file="${4:-}"

    if [ "${VIADUCT_HOST_KEY_RESET:-0}" = "1" ]; then
        ssh-keygen -R "$host" -f "$known_hosts" >/dev/null 2>&1 || true
        return 0
    fi

    if vh_server_was_rebuilt "$server_id" "$serverid_file"; then
        ssh-keygen -R "$host" -f "$known_hosts" >/dev/null 2>&1 || true
        return 0
    fi
    return 0
}

# vh_record_server_id <server_id> <serverid_file>
#
# Persist the hcloud server id the current host-key pin belongs to, so the next
# run can tell a genuine rebuild (id changed) from an ordinary apply (id
# unchanged). Call only after SSH to the box has succeeded. A no-op if either
# argument is empty, so an apply with no id available simply keeps the old record.
vh_record_server_id() {
    local server_id="${1:-}" serverid_file="${2:-}"
    [ -n "$server_id" ] && [ -n "$serverid_file" ] || return 0
    printf '%s\n' "$server_id" > "$serverid_file"
}

# ── Input allowlists ─────────────────────────────────────────────────────────

# vh_is_wg_key <value>
#
# A WireGuard public key or preshared key is the base64 encoding of exactly 32
# bytes: 43 characters from the base64 alphabet followed by '='. The 43rd
# character carries the key's last 4 significant bits plus 2 zero padding bits, so
# its base64 value is a multiple of 4 — the class [AEIMQUYcgkosw048]. (An earlier
# form omitted '0' and '8', which rejected 1 in 8 otherwise-valid keys at random.)
#
# Admitting only this shape leaves no character that a shell could treat as a
# metacharacter, and no newline that could inject a directive into a rendered
# wg0.conf.
vh_is_wg_key() {
    [[ "${1:-}" =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$ ]]
}

# vh_is_mesh_ip <value>
#
# A host address inside the 10.99.0.0/24 mesh. Excludes .0 (network) and .255
# (broadcast).
vh_is_mesh_ip() {
    [[ "${1:-}" =~ ^10\.99\.0\.([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$ ]]
}

# vh_is_uid <value>
#
# A POSIX numeric user id. Digits only, no leading '+'/'-', bounded length.
vh_is_uid() {
    [[ "${1:-}" =~ ^[0-9]{1,10}$ ]]
}

# vh_require <validator> <label> <value>
#
# Apply a validator and abort loudly when it rejects. The offending value is
# printed with non-printing characters escaped (%q) so a payload containing
# newlines or control characters cannot forge surrounding log lines.
# vh_is_uuid <value>
#
# A client UUID restored from backup is node-authored material: it is re-uploaded to
# /etc/xray/clients and rendered into config.json and every client URI. Shape-check it
# at both ends of the round trip so a compromised node cannot plant a value that
# survives a rebuild.
vh_is_uuid() {
    [[ "${1:-}" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]
}

vh_require() {
    local validator="$1" label="$2" value="${3:-}"

    if ! "$validator" "$value"; then
        printf 'ERROR: %s failed validation (%s): %q\n' \
            "$label" "$validator" "$value" >&2
        printf '       Refusing to interpolate an unvalidated value into a command executed as root.\n' >&2
        return 1
    fi
    return 0
}
