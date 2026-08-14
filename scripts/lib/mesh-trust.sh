#!/usr/bin/env bash
# scripts/lib/mesh-trust.sh
#
# Preconditions for the trust-on-first-use fetches that cross the WireGuard mesh.
# Sourced, never executed directly.
#
# The design deliberately relies on the mesh for peer authentication rather than on
# pinned certificate fingerprints. That premise has one gap: systemd's
# `After=wg-quick@wg0.service` orders unit *start*, and wg-quick returns once the
# interface is configured — not once a peer handshake has completed. A fetch issued in
# that window is authenticated by nothing at all. These helpers make the premise true
# at the moment of the fetch, and fail closed on a certificate that cannot be the hub's.

# How recent a handshake must be to count as a live peer. WireGuard rekeys well
# inside this, so a healthy tunnel always satisfies it.
: "${VH_HANDSHAKE_MAX_AGE:=180}"

# Allow tests (and hosts with wg elsewhere on PATH) to inject the binary.
: "${WG_BIN:=wg}"

# _vh_ip2int <dotted-ipv4> -> prints the 32-bit integer, or returns non-zero if the
# input is not a well-formed IPv4 (exactly four octets, each 0-255). Validating here is
# what keeps a garbage allowed-ips field (e.g. a regex-looking "10299203") from being
# mistaken for an address.
_vh_ip2int() {
    local a b c d rest o
    IFS=. read -r a b c d rest <<EOF
$1
EOF
    [ -n "$d" ] && [ -z "$rest" ] || return 1
    for o in "$a" "$b" "$c" "$d"; do
        case "$o" in ''|*[!0-9]*) return 1 ;; esac
        [ "$o" -le 255 ] || return 1
    done
    printf '%u\n' "$(( (a << 24) | (b << 16) | (c << 8) | d ))"
}

# _vh_cidr_contains <ip> <cidr> -> 0 if <ip> falls inside <cidr> (a bare IP is /32).
# Proper prefix containment, not a string match: 10.99.0.1 IS in 10.99.0.0/24, and
# 10.99.0.3 is NOT in 10.99.0.30/32.
_vh_cidr_contains() {
    local ip="$1" cidr="$2" net prefix ipi neti mask
    net="${cidr%/*}"; prefix="${cidr#*/}"
    [ "$net" = "$cidr" ] && prefix=32
    case "$prefix" in ''|*[!0-9]*) return 1 ;; esac
    [ "$prefix" -le 32 ] || return 1
    ipi="$(_vh_ip2int "$ip")"  || return 1
    neti="$(_vh_ip2int "$net")" || return 1
    [ "$prefix" -eq 0 ] && return 0
    mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
    [ "$(( ipi & mask ))" -eq "$(( neti & mask ))" ]
}

# vh_wait_for_mesh_handshake <peer_ip> [iface] [timeout_seconds]
#
# Block until the peer whose allowed-ips cover <peer_ip> has a handshake newer than
# VH_HANDSHAKE_MAX_AGE. Returns non-zero on timeout so the caller can fail closed.
vh_wait_for_mesh_handshake() {
    local peer_ip="$1" iface="${2:-wg0}" timeout="${3:-60}"
    local deadline=$(( SECONDS + timeout ))
    local pubkey now hs pk rest c

    while :; do
        # Map peer_ip -> public key by prefix CONTAINMENT over each peer's allowed-ips.
        #
        # Containment, not string equality: on a spoke the hub peer carries the whole
        # mesh as 10.99.0.0/24, so an exact "10.99.0.1/32" field match never found it
        # and the gate failed on a healthy tunnel. Containment still rejects the
        # original defect — 10.99.0.3 is not inside 10.99.0.30/32 — on which the
        # provenance of the federation bundle imports and the Vault cert fetch rests.
        pubkey=""
        while read -r pk rest; do
            [ -n "$pk" ] || continue
            for c in $rest; do
                if _vh_cidr_contains "$peer_ip" "$c"; then pubkey="$pk"; break; fi
            done
            [ -n "$pubkey" ] && break
        done < <("$WG_BIN" show "$iface" allowed-ips 2>/dev/null)

        if [ -n "$pubkey" ]; then
            hs="$("$WG_BIN" show "$iface" latest-handshakes 2>/dev/null \
                | awk -v k="$pubkey" '$1 == k { print $2; exit }')"
            now="$(date +%s)"
            if [ -n "$hs" ] && [ "$hs" -gt 0 ] 2>/dev/null \
               && [ $(( now - hs )) -lt "$VH_HANDSHAKE_MAX_AGE" ]; then
                return 0
            fi
        fi

        if [ "$SECONDS" -ge "$deadline" ]; then
            printf 'ERROR: no live WireGuard handshake with %s on %s after %ss.\n' \
                "$peer_ip" "$iface" "$timeout" >&2
            printf '       Refusing to trust-on-first-use across a mesh that has not authenticated the peer.\n' >&2
            return 1
        fi
        sleep 2
    done
}

# vh_verify_cert_san <cert_file> <expected_ip>
#
# Fail closed on a captured certificate that is empty, unparseable, expired, or whose
# subjectAltName does not cover <expected_ip>.
#
# `openssl s_client ... 2>/dev/null | openssl x509` writes an empty file when nothing
# answers, and an empty CA file produces a confusing downstream failure rather than a
# clear refusal — so emptiness is checked explicitly.
vh_verify_cert_san() {
    local cert="$1" expected_ip="$2"

    if [ ! -s "$cert" ]; then
        printf 'ERROR: captured certificate %s is empty — nothing answered, or the capture failed.\n' "$cert" >&2
        return 1
    fi
    if ! openssl x509 -in "$cert" -noout >/dev/null 2>&1; then
        printf 'ERROR: captured certificate %s is not a parseable X.509 certificate.\n' "$cert" >&2
        return 1
    fi
    if ! openssl x509 -in "$cert" -noout -checkend 0 >/dev/null 2>&1; then
        printf 'ERROR: captured certificate %s has expired.\n' "$cert" >&2
        return 1
    fi
    if ! openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null \
         | grep -qE "IP Address:${expected_ip}([^0-9]|$)"; then
        printf 'ERROR: captured certificate %s does not list %s in its subjectAltName.\n' \
            "$cert" "$expected_ip" >&2
        printf '       It cannot be the control-plane listener certificate; refusing to use it as the CA.\n' >&2
        return 1
    fi
    return 0
}

# vh_is_spiffe_bundle <file>
#
# A SPIFFE trust bundle is a JWKS document with at least one key. `spire-server bundle
# set` will accept a malformed or truncated document more readily than it should, so
# callers validate before installing a federated root.
# A grep for '"keys"' is NOT sufficient: a truncated response such as `{"keys":`
# contains that substring, and `bundle set` would install it. The document must
# actually parse. If neither jq nor python3 is present we fail closed rather than
# degrade to a substring match.
vh_is_spiffe_bundle() {
    local f="$1"
    [ -s "$f" ] || return 1

    if command -v jq >/dev/null 2>&1; then
        jq -e 'has("keys") and (.keys | type == "array") and (.keys | length > 0)' \
            "$f" >/dev/null 2>&1 || return 1
        return 0
    fi

    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
sys.exit(0 if isinstance(d, dict) and isinstance(d.get("keys"), list) and d["keys"] else 1)' \
            "$f" >/dev/null 2>&1 || return 1
        return 0
    fi

    printf 'ERROR: neither jq nor python3 available to validate the SPIFFE bundle; refusing to install an unvalidated trust root.\n' >&2
    return 1
}
