#!/usr/bin/env bash
# scripts/get-checksums.sh
#
# Prints the SHA-256 pins for each pinned binary, ready to paste into
# terraform.tfvars. Run this whenever you change a *_version variable.
#
# Source: the GitHub Releases API (assets[].digest) — the binaries are NOT
# downloaded or hashed locally. GitHub doesn't compute a digest for every asset
# (older uploads return null; alloy is currently one), so for those we fall back
# to the project's own published checksum file (e.g. Grafana's SHA256SUMS).
#
# NOTE on trust: neither the API digest nor an upstream sums file is a
# supply-chain guarantee — both come from the same source as the artifact. The
# protection is the RECORDED pin in terraform.tfvars: it's a point-in-time value
# that cloud-init enforces at deploy and that no longer moves if upstream
# changes. This script just makes that pin convenient to (re)generate.
#
# Usage:
#   ./scripts/get-checksums.sh [path/to/terraform.tfvars]
#
# Requirements: curl, jq.  Optional: GITHUB_TOKEN (raises the API rate limit).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TFVARS="${1:-${SCRIPT_DIR}/../terraform.tfvars}"
AWS_TFVARS="${SCRIPT_DIR}/../aws/terraform.tfvars"
DEFAULTS_FILE="${SCRIPT_DIR}/../variables.tf"
AWS_DEFAULTS_FILE="${SCRIPT_DIR}/../aws/variables.tf"

command -v jq >/dev/null || { echo "ERROR: jq is required" >&2; exit 1; }

# ── GitHub Releases API: the sha256 digest GitHub recorded for an asset ────────
# Echoes the bare hex (sha256: prefix stripped), or empty when GitHub has none
# (null digest, missing asset, or a fetch error — the caller validates).
api_digest() {
  local repo="$1" tag="$2" asset="$3" url json
  url="https://api.github.com/repos/$repo/releases/tags/$tag"
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    json=$(curl -fsSL -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      -H "Authorization: Bearer $GITHUB_TOKEN" "$url") || return 0
  else
    json=$(curl -fsSL -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" "$url") || return 0
  fi
  printf '%s' "$json" \
    | jq -r --arg n "$asset" '.assets[] | select(.name==$n) | .digest // empty' \
    | sed 's/^sha256://'
}

# ── Read a variable value from tfvars or variables.tf ────────────────────────
# Uses awk instead of sed to avoid BSD/GNU sed incompatibilities. Extraction
# uses the POSIX two-arg match() (RSTART/RLENGTH) rather than gawk's three-arg
# capture-array form — macOS ships BWK awk, which doesn't support the latter
# and fails silently under the `2>/dev/null || true` below, which used to make
# every lookup here fall through to hardcoded defaults on macOS.
# Matches:   varname = "value"   (with any surrounding whitespace)
#
# Checked in order: TFVARS (the file passed on the command line, or root
# terraform.tfvars by default), aws/terraform.tfvars, root variables.tf,
# aws/variables.tf. AWS-only vars (awscli_version, k3s_*) live exclusively in
# the aws/ root, so it's always searched regardless of which TFVARS is given.

get_var() {
  local name="$1" default="$2" val="" f

  for f in "$TFVARS" "$AWS_TFVARS"; do
    [[ -f "$f" ]] || continue
    val=$(awk -v key="$name" '
      $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
        if (match($0, /"[^"]+"/)) {
          v = substr($0, RSTART + 1, RLENGTH - 2)
          if (v != "") { print v; exit }
        }
      }
    ' "$f" 2>/dev/null || true)
    [[ -n "$val" ]] && { echo "$val"; return; }
  done

  # Fall back to default = "..." in variables.tf
  for f in "$DEFAULTS_FILE" "$AWS_DEFAULTS_FILE"; do
    [[ -f "$f" ]] || continue
    val=$(awk -v key="$name" '
      /variable[[:space:]]+"/ && $0 ~ "\"" key "\"" { found=1 }
      found && /default[[:space:]]*=/ {
        if (match($0, /"[^"]+"/)) {
          v = substr($0, RSTART + 1, RLENGTH - 2)
          if (v != "") { print v; exit }
        }
      }
      found && /^}/ { found=0 }
    ' "$f" 2>/dev/null || true)
    [[ -n "$val" ]] && { echo "$val"; return; }
  done

  echo "$default"
}

CONDUIT_VERSION=$(get_var "conduit_version"            "release-cli-2.0.0")
XRAY_VERSION=$(get_var "xray_version"                  "v26.4.25")
ALLOY_VERSION=$(get_var "alloy_version"                "v1.8.3")
XRAY_EXPORTER_VERSION=$(get_var "xray_exporter_version" "v0.2.0")
GEOIP_VERSION=$(get_var "geoip_version"                "202608050239")
GEOSITE_VERSION=$(get_var "geosite_version"            "20260807145230")
AWSCLI_VERSION=$(get_var "awscli_version"              "2.36.19")

echo "Fetching digests from the GitHub Releases API:"
echo "  conduit          $CONDUIT_VERSION"
echo "  xray-core        $XRAY_VERSION"
echo "  grafana-alloy    $ALLOY_VERSION"
echo "  xray-exporter    $XRAY_EXPORTER_VERSION"
echo "  geoip.dat        $GEOIP_VERSION"
echo "  geosite (dlc)    $GEOSITE_VERSION"
echo ""

CONDUIT_SHA256=$(api_digest "Psiphon-Inc/conduit"           "$CONDUIT_VERSION"       "conduit-linux-amd64")
XRAY_ZIP_SHA256=$(api_digest "XTLS/Xray-core"               "$XRAY_VERSION"          "Xray-linux-64.zip")
XRAY_EXPORTER_SHA256=$(api_digest "compassvpn/xray-exporter" "$XRAY_EXPORTER_VERSION" "xray-exporter-linux-amd64")
GEOIP_SHA256=$(api_digest "v2fly/geoip"                    "$GEOIP_VERSION"         "geoip.dat")
GEOSITE_SHA256=$(api_digest "v2fly/domain-list-community"  "$GEOSITE_VERSION"       "dlc.dat")

# ── Artifacts with no release API: hash them here ─────────────────────────────
# The k3s installer and the aws-cli zip are served straight off a vendor CDN, so
# there is no published digest to read. Hashing them locally is exactly as strong
# as the API digests above — see the trust note at the top of this file. What
# matters either way is that the value gets RECORDED in terraform.tfvars.
# sha256sum on Linux, shasum on macOS — this script runs on operator laptops.
hash_url() {
  if command -v sha256sum >/dev/null; then
    curl -fsSL "$1" | sha256sum | awk '{print $1}'
  else
    curl -fsSL "$1" | shasum -a 256 | awk '{print $1}'
  fi
}

echo "Hashing artifacts served without a release API:"
echo "  k3s installer    https://get.k3s.io"
echo "  aws-cli v2       $AWSCLI_VERSION (linux aarch64)"
echo ""
K3S_INSTALLER_SHA256=$(hash_url "https://get.k3s.io" || true)
AWSCLI_ZIP_SHA256=$(hash_url "https://awscli.amazonaws.com/awscli-exe-linux-aarch64-$AWSCLI_VERSION.zip" || true)

# Alloy assets frequently have no API digest → fall back to Grafana's SHA256SUMS.
ALLOY_ZIP_SHA256=$(api_digest "grafana/alloy" "$ALLOY_VERSION" "alloy-linux-amd64.zip")
if [[ -z "$ALLOY_ZIP_SHA256" ]]; then
  echo "  (alloy: no API digest — reading Grafana SHA256SUMS instead)"
  ALLOY_ZIP_SHA256=$(curl -fsSL \
    "https://github.com/grafana/alloy/releases/download/${ALLOY_VERSION}/SHA256SUMS" \
    | awk '/alloy-linux-amd64\.zip/ {print $1; exit}' || true)
fi

# ── Fail loudly if any pin is still empty ─────────────────────────────────────
missing=""
[[ -z "$CONDUIT_SHA256" ]]       && missing+=" conduit"
[[ -z "$XRAY_ZIP_SHA256" ]]      && missing+=" xray"
[[ -z "$ALLOY_ZIP_SHA256" ]]     && missing+=" alloy"
[[ -z "$XRAY_EXPORTER_SHA256" ]] && missing+=" xray-exporter"
[[ -z "$GEOIP_SHA256" ]]         && missing+=" geoip"
[[ -z "$GEOSITE_SHA256" ]]       && missing+=" geosite"
[[ -z "$K3S_INSTALLER_SHA256" ]] && missing+=" k3s-installer"
[[ -z "$AWSCLI_ZIP_SHA256" ]]    && missing+=" aws-cli"
if [[ -n "$missing" ]]; then
  echo "ERROR: no digest found for:$missing" >&2
  echo "  Check the version/asset name. If the asset predates GitHub-computed" >&2
  echo "  digests and has no published checksum file, hash it manually." >&2
  exit 1
fi

# ── Output ────────────────────────────────────────────────────────────────────

echo ""
echo "══════════════════════════════════════════════════════════════"
echo " Add these lines to your root terraform.tfvars:"
echo "══════════════════════════════════════════════════════════════"
echo ""
echo "conduit_sha256       = \"$CONDUIT_SHA256\""
echo "xray_zip_sha256      = \"$XRAY_ZIP_SHA256\""
echo "alloy_zip_sha256     = \"$ALLOY_ZIP_SHA256\""
echo "xray_exporter_sha256 = \"$XRAY_EXPORTER_SHA256\""
echo "geoip_sha256         = \"$GEOIP_SHA256\""
echo "geosite_sha256       = \"$GEOSITE_SHA256\""
echo "geoip_version        = \"$GEOIP_VERSION\""
echo "geosite_version      = \"$GEOSITE_VERSION\""
echo ""
echo " …and these to aws/terraform.tfvars:"
echo ""
echo "k3s_installer_sha256 = \"$K3S_INSTALLER_SHA256\""
echo "awscli_zip_sha256    = \"$AWSCLI_ZIP_SHA256\""
echo "awscli_version       = \"$AWSCLI_VERSION\""
echo ""

# ── Is anything newer upstream? ───────────────────────────────────────────────
# The digests above are computed against the versions CURRENTLY pinned, which is
# what you want for a re-verify. But three of these track a moving upstream, and
# without this you would have no way to learn a new tag exists — you would keep
# re-printing the digest of the version you already have.
latest_tag() { curl -fsSL -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/$1/releases/latest" 2>/dev/null | jq -r '.tag_name // empty'; }

NEW_GEOIP="$(latest_tag v2fly/geoip || true)"
NEW_GEOSITE="$(latest_tag v2fly/domain-list-community || true)"
NEW_AWSCLI="$(curl -fsSL -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/aws/aws-cli/tags" 2>/dev/null \
  | jq -r '[.[].name | select(startswith("2."))][0] // empty' || true)"

newer=""
[ -n "$NEW_GEOIP" ]   && [ "$NEW_GEOIP"   != "$GEOIP_VERSION" ]   && newer="$newer\n  geoip_version   $GEOIP_VERSION -> $NEW_GEOIP"
[ -n "$NEW_GEOSITE" ] && [ "$NEW_GEOSITE" != "$GEOSITE_VERSION" ] && newer="$newer\n  geosite_version $GEOSITE_VERSION -> $NEW_GEOSITE"
[ -n "$NEW_AWSCLI" ]  && [ "$NEW_AWSCLI"  != "$AWSCLI_VERSION" ]  && newer="$newer\n  awscli_version  $AWSCLI_VERSION -> $NEW_AWSCLI"

if [ -n "$newer" ]; then
  echo "══════════════════════════════════════════════════════════════"
  echo " Newer upstream releases exist:"
  printf "$newer\n"
  echo ""
  echo " To move: set the version above in tfvars, re-run this script, then paste"
  echo " the regenerated digest alongside it."
  echo "══════════════════════════════════════════════════════════════"
  echo ""
fi

# The k3s installer has no version of its own — get.k3s.io is edited in place, so the
# digest changing IS the only signal. Re-run this script to pick up the new one.
