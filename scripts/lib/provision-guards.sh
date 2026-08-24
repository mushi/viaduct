#!/usr/bin/env bash
# scripts/lib/provision-guards.sh
#
# Helpers sourced by scripts/provision.sh. Kept in a library so they can be unit
# tested directly (tests/test_provision_host_key_pin.py) without running the
# provisioner.

# vh_server_was_rebuilt <server_id> <serverid_file>
#
# True only when a server id is recorded AND differs from the current one — i.e. the
# instance was recreated. False when no id is recorded yet (first run / adoption) or
# the ids match. The id is minted by the cloud provider and read from terraform state,
# so it is a rebuild signal an on-path attacker cannot forge.
vh_server_was_rebuilt() {
    local server_id="${1:-}" serverid_file="${2:-}" recorded
    [ -n "$server_id" ] && [ -n "$serverid_file" ] && [ -f "$serverid_file" ] || return 1
    recorded="$(cat "$serverid_file" 2>/dev/null || true)"
    [ -n "$recorded" ] && [ "$recorded" != "$server_id" ]
}

# vh_reset_host_key_pin_if_requested <host> <known_hosts_file> [server_id] [serverid_file]
#
# Remove a recorded host key ONLY when the box was genuinely rebuilt — never on an
# ordinary apply. A `terraform -replace` regenerates the box's SSH host keys while
# keeping the static IP, so the stale pin has to go; but clearing it on every apply
# would let the following SSH (StrictHostKeyChecking=accept-new) re-trust whatever key
# answered, which is exactly the check that catches an on-path attacker.
#
# Two ways the reset is authorised, in order:
#   1. VIADUCT_HOST_KEY_RESET=1 — explicit operator override, for the one case
#      auto-detection deliberately will NOT act on: an out-of-band key change on the
#      same server (e.g. an OS reinstall that keeps the hcloud server id).
#   2. The hcloud server id changed since the pin was recorded. The id changes only
#      when the instance is recreated, which is also the only thing that regenerates
#      the host keys. An attacker MITM-ing the SSH to the static IP cannot forge a new
#      id, so clearing the stale pin here is safe. A key change NOT backed by a new id
#      (the MITM case) is left pinned and fails closed on the next SSH.
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
# Persist the hcloud server id the current host-key pin belongs to, so the next run can
# tell a genuine rebuild (id changed) from an ordinary apply (id unchanged). Call only
# after SSH to the box has succeeded. A no-op if either argument is empty.
vh_record_server_id() {
    local server_id="${1:-}" serverid_file="${2:-}"
    [ -n "$server_id" ] && [ -n "$serverid_file" ] || return 0
    printf '%s\n' "$server_id" > "$serverid_file"
}
