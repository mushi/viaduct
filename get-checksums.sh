#!/usr/bin/env bash
# scripts/get-checksums.sh
#
# Downloads each binary for the versions in terraform.tfvars (or defaults
# from variables.tf) and prints SHA-256 checksums ready to paste into
# terraform.tfvars. Run this whenever you update a *_version variable.
#
# Usage:
#   ./scripts/get-checksums.sh [path/to/terraform.tfvars]
#
# Requirements: curl, sha256sum (Linux) or shasum (macOS), unzip

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TFVARS="${1:-${SCRIPT_DIR}/../terraform.tfvars}"
DEFAULTS_FILE="${SCRIPT_DIR}/../variables.tf"

# ── Portable SHA-256 ──────────────────────────────────────────────────────────

sha256() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum &>/dev/null; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "ERROR: no sha256sum or shasum found" >&2; exit 1
  fi
}

sha512() {
  if command -v sha512sum &>/dev/null; then
    sha512sum "$1" | awk '{print $1}'
  elif command -v shasum &>/dev/null; then
    shasum -a 512 "$1" | awk '{print $1}'
  else
    echo "ERROR: no sha512sum or shasum found" >&2; exit 1
  fi
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

CONDUIT_VERSION=$(get_var "conduit_version"       "release-cli-2.0.0")
XRAY_VERSION=$(get_var "xray_version"             "v26.4.25")
ALLOY_VERSION=$(get_var "alloy_version"           "v1.8.3")

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Fetching checksums for:"
echo "  conduit          $CONDUIT_VERSION"
echo "  xray-core        $XRAY_VERSION"
echo "  grafana-alloy    $ALLOY_VERSION"
echo "  xray-exporter    (downloaded at runtime via GitHub API — no checksum needed)"
echo ""

# ── Conduit ───────────────────────────────────────────────────────────────────

echo -n "Downloading conduit-linux-amd64... "
curl -fsSL \
  "https://github.com/Psiphon-Inc/conduit/releases/download/${CONDUIT_VERSION}/conduit-linux-amd64" \
  -o "$TMPDIR/conduit"
CONDUIT_SHA256=$(sha256 "$TMPDIR/conduit")
echo "done"

# ── Xray-core ─────────────────────────────────────────────────────────────────

echo -n "Downloading Xray-linux-64.zip... "
curl -fsSL \
  "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip" \
  -o "$TMPDIR/xray.zip"
XRAY_ZIP_SHA256=$(sha256 "$TMPDIR/xray.zip")
echo "done"

# Cross-check against Xray's upstream .dgst file (contains SHA-512)
DGST_URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip.dgst"
if curl -fsSL --max-time 10 "$DGST_URL" -o "$TMPDIR/xray.dgst" 2>/dev/null; then
  PUBLISHED_SHA512=$(awk '/SHA-512/ {print $2}' "$TMPDIR/xray.dgst" || true)
  if [[ -n "$PUBLISHED_SHA512" ]]; then
    ACTUAL_SHA512=$(sha512 "$TMPDIR/xray.zip")
    if [[ "$PUBLISHED_SHA512" == "$ACTUAL_SHA512" ]]; then
      echo "  ✓ Xray SHA-512 cross-check passed against upstream .dgst"
    else
      echo "  ✗ FATAL: Xray SHA-512 cross-check FAILED — do not use this binary!" >&2
      exit 1
    fi
  else
    echo "  (SHA-512 not found in .dgst — skipping cross-check)"
  fi
else
  echo "  (.dgst not available — skipping cross-check)"
fi

# ── Grafana Alloy ─────────────────────────────────────────────────────────────

echo -n "Downloading alloy-linux-amd64.zip... "
curl -fsSL \
  "https://github.com/grafana/alloy/releases/download/${ALLOY_VERSION}/alloy-linux-amd64.zip" \
  -o "$TMPDIR/alloy.zip"
ALLOY_ZIP_SHA256=$(sha256 "$TMPDIR/alloy.zip")
echo "done"

# Cross-check against Grafana's SHA256SUMS
SUMS_URL="https://github.com/grafana/alloy/releases/download/${ALLOY_VERSION}/SHA256SUMS"
if curl -fsSL --max-time 10 "$SUMS_URL" -o "$TMPDIR/alloy.sha256sums" 2>/dev/null; then
  PUBLISHED_ALLOY=$(awk '/alloy-linux-amd64\.zip/ {print $1}' "$TMPDIR/alloy.sha256sums" || true)
  if [[ -n "$PUBLISHED_ALLOY" ]]; then
    if [[ "$PUBLISHED_ALLOY" == "$ALLOY_ZIP_SHA256" ]]; then
      echo "  ✓ Alloy SHA-256 cross-check passed against upstream SHA256SUMS"
    else
      echo "  ✗ FATAL: Alloy SHA-256 cross-check FAILED — do not use this binary!" >&2
      exit 1
    fi
  fi
else
  echo "  (SHA256SUMS not available — skipping cross-check)"
fi

# ── Output ────────────────────────────────────────────────────────────────────

echo ""
echo "══════════════════════════════════════════════════════════════"
echo " Add these lines to your terraform.tfvars:"
echo "══════════════════════════════════════════════════════════════"
echo ""
echo "conduit_sha256  = \"$CONDUIT_SHA256\""
echo "xray_zip_sha256 = \"$XRAY_ZIP_SHA256\""
echo "alloy_zip_sha256 = \"$ALLOY_ZIP_SHA256\""
echo ""
echo "(xray-exporter checksum is verified at runtime against the"
echo " release's own checksums file — no value needed here.)"
echo ""
echo "══════════════════════════════════════════════════════════════"
