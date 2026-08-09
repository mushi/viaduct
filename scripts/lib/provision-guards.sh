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
