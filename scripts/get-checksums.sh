#!/usr/bin/env bash
# scripts/get-checksums.sh
#
# Re-derives every digest in pins.json from upstream for the versions pinned there, and
# reports any that differ. With --write it records the new digests in pins.json, ready to
# review as a diff. Change a version by editing pins.json, then run this with --write.
#
# Sources: the GitHub Releases API (assets[].digest) for release binaries; the project's
# own checksum file where GitHub has no digest (alloy's SHA256SUMS); the registries for
# container image digests; a local hash for the two artifacts served off vendor CDNs
# (get.k3s.io, the aws-cli zip). Binaries are not downloaded except for those two.
#
# NOTE on trust: neither the API digest nor an upstream sums file is a supply-chain
# guarantee — both come from the same source as the artifact. The protection is the
# RECORDED pin in pins.json: a point-in-time value the nodes enforce at boot that no
# longer moves if upstream changes. This script makes that pin convenient to
# (re)generate; read the diff before committing it.
#
# Usage:
#   ./scripts/get-checksums.sh            # verify; exit 1 if any pin differs or is unreadable
#   ./scripts/get-checksums.sh --write    # also record the new digests in pins.json
#
# Requirements: curl, jq. Optional: GITHUB_TOKEN (raises the API rate limit).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PINS="${PINS_FILE:-${SCRIPT_DIR}/../pins.json}"
WRITE=0
[ "${1:-}" = "--write" ] && WRITE=1

command -v jq >/dev/null || { echo "ERROR: jq is required" >&2; exit 1; }
[ -f "$PINS" ] || { echo "ERROR: $PINS not found" >&2; exit 1; }
pin() { jq -r "$1" "$PINS"; }

# ── Upstream digest sources ──────────────────────────────────────────────────
# GitHub Releases API: the sha256 GitHub recorded for an asset, bare hex, or empty when
# it has none (null digest, missing asset, fetch error — the caller reports it).
RATE_FLAG=$(mktemp); trap 'rm -f "$RATE_FLAG"' EXIT; rm -f "$RATE_FLAG"
api_digest() {
  local repo="$1" tag="$2" asset="$3" auth=() body
  [ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
  body=$(curl -sSL -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" \
    ${auth[@]+"${auth[@]}"} "https://api.github.com/repos/$repo/releases/tags/$tag" 2>/dev/null || true)
  # Unauthenticated callers get 60 requests an hour; an exhausted quota looks like a
  # missing digest unless it is called out.
  if printf '%s' "$body" | grep -q 'API rate limit exceeded'; then : > "$RATE_FLAG"; return 0; fi
  printf '%s' "$body" | jq -r --arg n "$asset" '.assets[]? | select(.name==$n) | .digest // empty' \
    | sed 's/^sha256://' || true
}

# sha256sum on Linux, shasum on macOS — this runs on operator laptops.
hash_url() {
  if command -v sha256sum >/dev/null; then curl -fsSL "$1" | sha256sum | awk '{print $1}'
  else curl -fsSL "$1" | shasum -a 256 | awk '{print $1}'; fi
}

# The multi-arch index digest a registry serves for name:tag ("sha256:<hex>").
image_digest() {
  local name="$1" tag="$2" accept tok
  accept='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json'
  case "$name" in
    ghcr.io/*)
      tok=$(curl -fsS "https://ghcr.io/token?scope=repository:${name#ghcr.io/}:pull" | jq -r .token)
      curl -fsSI -H "Authorization: Bearer $tok" -H "Accept: $accept" \
        "https://ghcr.io/v2/${name#ghcr.io/}/manifests/$tag" ;;
    registry.k8s.io/*)
      curl -fsSIL -H "Accept: $accept" "https://registry.k8s.io/v2/${name#registry.k8s.io/}/manifests/$tag" ;;
    *)
      case "$name" in */*) ;; *) name="library/$name" ;; esac
      curl -fsS "https://hub.docker.com/v2/repositories/$name/tags/$tag" \
        | jq -r '"docker-content-digest: " + .digest' ;;
  esac 2>/dev/null | awk -F': ' 'tolower($1)=="docker-content-digest" {d=$2} END {gsub("\r","",d); print d}' || true
}

# ── Compare each pin with upstream ───────────────────────────────────────────
UPDATES=()
MISSING=""
check() {  # label jq-path upstream-value
  local label="$1" path="$2" new="$3" old
  old=$(pin "$path")
  if [ -z "$new" ]; then MISSING="$MISSING $label"; printf '  %-34s NO UPSTREAM VALUE\n' "$label"; return; fi
  if [ "$old" = "$new" ]; then printf '  %-34s ok\n' "$label"
  else printf '  %-34s CHANGED  %.19s -> %.19s\n' "$label" "$old" "$new"; UPDATES+=("$path"$'\t'"$new"); fi
}

CONDUIT=$(pin .conduit.version); XRAY=$(pin .xray.version); EXPORTER=$(pin .xray_exporter.version)
ALLOY=$(pin .alloy.version); SPIRE=$(pin .spire.version); K3S=$(pin .k3s.version)
AWSCLI=$(pin .awscli.version); GEOIP=$(pin .geoip.version); GEOSITE=$(pin .geosite.version)

echo "Verifying pins.json against upstream:"
check "conduit $CONDUIT amd64"        '.conduit.sha256["linux-amd64"]'  "$(api_digest Psiphon-Inc/conduit "$CONDUIT" conduit-linux-amd64)"
check "conduit $CONDUIT arm64"        '.conduit.sha256["linux-arm64"]'  "$(api_digest Psiphon-Inc/conduit "$CONDUIT" conduit-linux-arm64)"
check "xray $XRAY"                    '.xray.sha256["Xray-linux-64.zip"]' "$(api_digest XTLS/Xray-core "$XRAY" Xray-linux-64.zip)"
check "xray-exporter $EXPORTER"       '.xray_exporter.sha256["linux-amd64"]' "$(api_digest compassvpn/xray-exporter "$EXPORTER" xray-exporter-linux-amd64)"
check "spire $SPIRE amd64"            '.spire.sha256["linux-amd64-musl"]' "$(api_digest spiffe/spire "v$SPIRE" "spire-$SPIRE-linux-amd64-musl.tar.gz")"
check "spire $SPIRE arm64"            '.spire.sha256["linux-arm64-musl"]' "$(api_digest spiffe/spire "v$SPIRE" "spire-$SPIRE-linux-arm64-musl.tar.gz")"
check "geoip $GEOIP"                  '.geoip.sha256'   "$(api_digest v2fly/geoip "$GEOIP" geoip.dat)"
check "geosite $GEOSITE"              '.geosite.sha256' "$(api_digest v2fly/domain-list-community "$GEOSITE" dlc.dat)"

# Alloy assets frequently have no API digest, so fall back to Grafana's SHA256SUMS.
ALLOY_ZIP=$(api_digest grafana/alloy "$ALLOY" alloy-linux-amd64.zip)
[ -n "$ALLOY_ZIP" ] || ALLOY_ZIP=$(curl -fsSL "https://github.com/grafana/alloy/releases/download/$ALLOY/SHA256SUMS" 2>/dev/null \
  | awk '/ alloy-linux-amd64\.zip$/ {print $1; exit}' || true)
check "alloy $ALLOY"                  '.alloy.sha256["alloy-linux-amd64.zip"]' "$ALLOY_ZIP"

# Served off vendor CDNs with no published digest: hash here. The k3s installer has no
# version of its own — get.k3s.io is edited in place, so the digest changing IS the only
# signal; review upstream's install.sh diff before recording a new one.
check "k3s installer (get.k3s.io)"    '.k3s.installer_sha256' "$(hash_url https://get.k3s.io || true)"
check "aws-cli $AWSCLI aarch64"       '.awscli.sha256["linux-aarch64.zip"]' \
  "$(hash_url "https://awscli.amazonaws.com/awscli-exe-linux-aarch64-$AWSCLI.zip" || true)"

for img in $(pin '.images | keys[]'); do
  name=$(pin ".images.$img.name"); tag=$(pin ".images.$img.tag")
  check "image $img:$tag"             ".images.$img.digest" "$(image_digest "$name" "$tag")"
done

# Vault installs from HashiCorp's apt repository, which has no digest to pin: confirm the
# pinned package version is published for the pinned Ubuntu release, or the boot fails.
VAULT_APT="$(pin .vault.version)-$(pin .vault.apt_revision)"; CODENAME=$(pin .ubuntu.codename)
if curl -fsSL "https://apt.releases.hashicorp.com/dists/$CODENAME/main/binary-amd64/Packages" 2>/dev/null \
    | awk '/^Package: vault$/ {p=1} p && /^Version:/ {print $2; p=0}' | grep -qx "$VAULT_APT"; then
  printf '  %-34s ok\n' "vault apt $VAULT_APT ($CODENAME)"
else
  MISSING="$MISSING vault-apt"; printf '  %-34s NOT PUBLISHED for %s\n' "vault apt $VAULT_APT" "$CODENAME"
fi

# ── Record or report ─────────────────────────────────────────────────────────
echo ""
if [ ${#UPDATES[@]} -gt 0 ] && [ "$WRITE" -eq 1 ]; then
  tmp=$(mktemp "${PINS}.XXXXXX")
  cp "$PINS" "$tmp"
  for u in "${UPDATES[@]}"; do
    jq --arg v "${u#*$'\t'}" "${u%%$'\t'*} = \$v" "$tmp" > "$tmp.next" && mv "$tmp.next" "$tmp"
  done
  mv "$tmp" "$PINS"
  echo "Recorded ${#UPDATES[@]} new digest(s) in pins.json. Review: git diff pins.json"
elif [ ${#UPDATES[@]} -gt 0 ]; then
  echo "${#UPDATES[@]} pin(s) differ from upstream. Re-run with --write to record them."
elif [ -z "$MISSING" ]; then
  echo "Every pin matches upstream."
fi
if [ -n "$MISSING" ]; then
  echo "ERROR: no upstream value for:$MISSING" >&2
  if [ -f "$RATE_FLAG" ]; then
    echo "  The GitHub API rate limit is exhausted (60/hour unauthenticated); export GITHUB_TOKEN or retry later." >&2
  else
    echo "  Check the version or asset name in pins.json." >&2
  fi
  exit 1
fi
[ ${#UPDATES[@]} -eq 0 ] || [ "$WRITE" -eq 1 ] || exit 1
