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
DEFAULTS_FILE="${SCRIPT_DIR}/../variables.tf"

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
# Uses awk instead of sed to avoid BSD/GNU sed incompatibilities.
# Matches:   varname = "value"   (with any surrounding whitespace)

get_var() {
  local name="$1" default="$2" val=""

  # Try terraform.tfvars first
  if [[ -f "$TFVARS" ]]; then
    val=$(awk -v key="$name" '
      $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
        # Extract the value between the first pair of double-quotes on the line
        match($0, /"([^"]+)"/, arr)
        if (arr[1] != "") { print arr[1]; exit }
      }
    ' "$TFVARS" 2>/dev/null || true)
    [[ -n "$val" ]] && { echo "$val"; return; }
  fi

  # Fall back to default = "..." in variables.tf
  if [[ -f "$DEFAULTS_FILE" ]]; then
    val=$(awk -v key="$name" '
      /variable[[:space:]]+"/ && $0 ~ "\"" key "\"" { found=1 }
      found && /default[[:space:]]*=/ {
        match($0, /"([^"]+)"/, arr)
        if (arr[1] != "") { print arr[1]; exit }
      }
      found && /^}/ { found=0 }
    ' "$DEFAULTS_FILE" 2>/dev/null || true)
    [[ -n "$val" ]] && { echo "$val"; return; }
  fi

  echo "$default"
}

CONDUIT_VERSION=$(get_var "conduit_version"            "release-cli-2.0.0")
XRAY_VERSION=$(get_var "xray_version"                  "v26.4.25")
ALLOY_VERSION=$(get_var "alloy_version"                "v1.8.3")
XRAY_EXPORTER_VERSION=$(get_var "xray_exporter_version" "v0.2.0")

echo "Fetching digests from the GitHub Releases API:"
echo "  conduit          $CONDUIT_VERSION"
echo "  xray-core        $XRAY_VERSION"
echo "  grafana-alloy    $ALLOY_VERSION"
echo "  xray-exporter    $XRAY_EXPORTER_VERSION"
echo ""

CONDUIT_SHA256=$(api_digest "Psiphon-Inc/conduit"           "$CONDUIT_VERSION"       "conduit-linux-amd64")
XRAY_ZIP_SHA256=$(api_digest "XTLS/Xray-core"               "$XRAY_VERSION"          "Xray-linux-64.zip")
XRAY_EXPORTER_SHA256=$(api_digest "compassvpn/xray-exporter" "$XRAY_EXPORTER_VERSION" "xray-exporter-linux-amd64")

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
if [[ -n "$missing" ]]; then
  echo "ERROR: no digest found for:$missing" >&2
  echo "  Check the version/asset name. If the asset predates GitHub-computed" >&2
  echo "  digests and has no published checksum file, hash it manually." >&2
  exit 1
fi

# ── Output ────────────────────────────────────────────────────────────────────

echo ""
echo "══════════════════════════════════════════════════════════════"
echo " Add these lines to your terraform.tfvars:"
echo "══════════════════════════════════════════════════════════════"
echo ""
echo "conduit_sha256       = \"$CONDUIT_SHA256\""
echo "xray_zip_sha256      = \"$XRAY_ZIP_SHA256\""
echo "alloy_zip_sha256     = \"$ALLOY_ZIP_SHA256\""
echo "xray_exporter_sha256 = \"$XRAY_EXPORTER_SHA256\""
echo ""
echo "══════════════════════════════════════════════════════════════"
