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

# vh_reset_host_key_pin_if_requested <host> <known_hosts_file>
#
# Remove a recorded host key ONLY when the operator has explicitly signalled a
# rebuild via VIADUCT_HOST_KEY_RESET=1.
#
# A `terraform -replace` regenerates the box's SSH host keys while keeping the
# static IP, so the stale pin genuinely has to go — but that is a deliberate,
# infrequent act. Clearing the pin on every apply meant the following SSH
# (StrictHostKeyChecking=accept-new) re-trusted whatever key answered, which is
# exactly the check that would otherwise catch an on-path attacker.
#
# When no reset is requested and the key really did change, the SSH below fails
# with a host-key error and provision.sh prints the exact command to run.
vh_reset_host_key_pin_if_requested() {
    local host="$1" known_hosts="$2"

    if [ "${VIADUCT_HOST_KEY_RESET:-0}" = "1" ]; then
        ssh-keygen -R "$host" -f "$known_hosts" >/dev/null 2>&1 || true
        return 0
    fi
    return 0
}

# ── Input allowlists ─────────────────────────────────────────────────────────

# vh_is_wg_key <value>
#
# A WireGuard public key or preshared key is the base64 encoding of exactly 32
# bytes: 43 characters from the base64 alphabet followed by '='. The final
# pre-padding character encodes only two significant bits, so it is restricted
# to [AEIMQUYcgkosw4].
#
# Admitting only this shape leaves no character that a shell could treat as a
# metacharacter, and no newline that could inject a directive into a rendered
# wg0.conf.
vh_is_wg_key() {
    [[ "${1:-}" =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw4]=$ ]]
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
