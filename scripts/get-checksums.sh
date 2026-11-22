#!/usr/bin/env bash
# scripts/get-checksums.sh
#
# Re-derives every digest in pins.json from upstream for the versions pinned there and
# reports any that differ. With --write it records the new digests in pins.json, ready
# to review as a diff. Change a version by editing pins.json (or scripts/update-pins.sh),
# then run this with --write.
#
# Source per asset, first that answers: the GitHub Releases API (assets[].digest); the
# release's own SHA256SUMS file; otherwise the asset is downloaded and hashed here.
#
# NOTE on trust: neither the API digest nor an upstream sums file is a supply-chain
# guarantee; both come from the same source as the artifact. The protection is the
# RECORDED pin in pins.json: a point-in-time value cloud-init enforces at boot that no
# longer moves if upstream changes. A digest that changes for an already-pinned version
# means upstream replaced a published file; find out why before recording it.
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

RATE_FLAG=$(mktemp); trap 'rm -f "$RATE_FLAG"' EXIT; rm -f "$RATE_FLAG"

gh_api() {  # path -> body, or empty on error
  local auth=()
  [ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
  curl -sSL -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" \
    ${auth[@]+"${auth[@]}"} "https://api.github.com/$1" 2>/dev/null || true
}

# sha256sum on Linux, shasum on macOS: this runs on operator laptops too.
sha256_stdin() {
  if command -v sha256sum >/dev/null; then sha256sum | awk '{print $1}'
  else shasum -a 256 | awk '{print $1}'; fi
}

upstream_digest() {  # repo tag asset -> bare hex, or empty
  local repo="$1" tag="$2" asset="$3" body d
  body=$(gh_api "repos/$repo/releases/tags/$tag")
  # Unauthenticated callers get 60 requests an hour; an exhausted quota looks like a
  # missing digest unless it is called out.
  if printf '%s' "$body" | grep -q 'API rate limit exceeded'; then : > "$RATE_FLAG"; return 0; fi
  d=$(printf '%s' "$body" | jq -r --arg n "$asset" \
        '.assets[]? | select(.name==$n) | .digest // empty' 2>/dev/null | sed 's/^sha256://' || true)
  if [ -z "$d" ]; then
    d=$(curl -fsSL "https://github.com/$repo/releases/download/$tag/SHA256SUMS" 2>/dev/null \
        | awk -v a="$asset" '$2 == a || $2 == "*" a {print $1; exit}' || true)
  fi
  if [ -z "$d" ] && printf '%s' "$body" | jq -e --arg n "$asset" '.assets[]? | select(.name==$n)' >/dev/null 2>&1; then
    d=$(curl -fsSL "https://github.com/$repo/releases/download/$tag/$asset" 2>/dev/null | sha256_stdin || true)
    [ "$d" = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ] && d=""  # empty body
  fi
  printf '%s' "$d"
}

UPDATES=()
MISSING=""
echo "Verifying pins.json against upstream:"
for entry in $(jq -r 'to_entries[] | select(.value | type == "object" and has("source")) | .key' "$PINS"); do
  repo=$(jq -r --arg e "$entry" '.[$e].source' "$PINS")
  tag=$(jq -r --arg e "$entry" '.[$e].version' "$PINS")
  for asset in $(jq -r --arg e "$entry" '.[$e].sha256 | keys[]' "$PINS"); do
    label="$entry $tag $asset"
    old=$(jq -r --arg e "$entry" --arg a "$asset" '.[$e].sha256[$a]' "$PINS")
    new=$(upstream_digest "$repo" "$tag" "$asset")
    if [ -z "$new" ]; then
      MISSING="$MISSING $entry/$asset"; printf '  %-58s NO UPSTREAM VALUE\n' "$label"
    elif [ "$old" = "$new" ]; then
      printf '  %-58s ok\n' "$label"
    else
      printf '  %-58s CHANGED  %.12s -> %.12s\n' "$label" "$old" "$new"
      UPDATES+=("$entry"$'\t'"$asset"$'\t'"$new")
    fi
  done
done

echo ""
if [ ${#UPDATES[@]} -gt 0 ] && [ "$WRITE" -eq 1 ]; then
  tmp=$(mktemp "${PINS}.XXXXXX")
  cp "$PINS" "$tmp"
  for u in "${UPDATES[@]}"; do
    IFS=$'\t' read -r e a d <<< "$u"
    jq --arg e "$e" --arg a "$a" --arg d "$d" '.[$e].sha256[$a] = $d' "$tmp" > "$tmp.next" && mv "$tmp.next" "$tmp"
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
