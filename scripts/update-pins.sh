#!/usr/bin/env bash
# scripts/update-pins.sh
#
# Moves each version in pins.json to the newest upstream release that has been public
# for at least COOL_OFF_DAYS (default 4): long enough for a bad or hijacked release to
# be noticed and pulled before a node installs it. Majors are included. Drafts,
# prereleases and tags without the entry's tag_prefix are ignored, and a version never
# moves backwards. Digests are not touched; run scripts/get-checksums.sh --write next.
#
# Usage:
#   ./scripts/update-pins.sh                  # edit pins.json in place
#   SUMMARY_FILE=out.md ./scripts/update-pins.sh   # also write a Markdown list of bumps
#
# Requirements: curl, jq. Optional: GITHUB_TOKEN (raises the API rate limit).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PINS="${PINS_FILE:-${SCRIPT_DIR}/../pins.json}"
COOL_OFF_DAYS="${COOL_OFF_DAYS:-4}"
SUMMARY_FILE="${SUMMARY_FILE:-}"

command -v jq >/dev/null || { echo "ERROR: jq is required" >&2; exit 1; }
[ -f "$PINS" ] || { echo "ERROR: $PINS not found" >&2; exit 1; }
[ -z "$SUMMARY_FILE" ] || : > "$SUMMARY_FILE"

releases() {  # repo -> JSON array of releases, or exit 1
  local auth=() body
  [ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
  body=$(curl -fsSL -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" \
    ${auth[@]+"${auth[@]}"} "https://api.github.com/repos/$1/releases?per_page=100") || return 1
  printf '%s' "$body" | jq -e 'type == "array"' >/dev/null || return 1
  printf '%s' "$body"
}

# The newest eligible release as "tag<TAB>published_at<TAB>html_url", or empty. Tags
# compare by their numeric fields after the prefix (v26.11.10 > v26.11.9; dated geo
# tags compare as one number), not by publish time, so a backport released after a
# newer line is never chosen over it. A tag lands in a download URL in cloud-init, so a
# tag with anything beyond letters, digits and . _ + - is skipped, never written to pins.json.
NEWEST='
  def key($p): ($p | length) as $n | .[$n:] | [scan("[0-9]+") | tonumber];
  [ .[]
    | select(.draft | not) | select(.prerelease | not)
    | select(.tag_name | startswith($prefix))
    | select(.tag_name | test("^[A-Za-z0-9][A-Za-z0-9._+-]*$"))
    | select((.published_at | fromdateiso8601) <= (now - ($days | tonumber) * 86400))
  ]
  | max_by(.tag_name | key($prefix))
  | if . == null then empty else "\(.tag_name)\t\(.published_at)\t\(.html_url)" end'

newer() {  # prefix current candidate -> exit 0 if candidate sorts above current
  jq -en --arg p "$1" --arg a "$2" --arg b "$3" \
    'def key($p): ($p | length) as $n | .[$n:] | [scan("[0-9]+") | tonumber];
     ($b | key($p)) > ($a | key($p))' >/dev/null
}

FAILED=""
BUMPED=0
for entry in $(jq -r 'to_entries[] | select(.value | type == "object" and has("source")) | .key' "$PINS"); do
  repo=$(jq -r --arg e "$entry" '.[$e].source' "$PINS")
  prefix=$(jq -r --arg e "$entry" '.[$e].tag_prefix // ""' "$PINS")
  current=$(jq -r --arg e "$entry" '.[$e].version' "$PINS")
  if ! list=$(releases "$repo"); then
    FAILED="$FAILED $entry"; printf '  %-14s could not list releases of %s\n' "$entry" "$repo"; continue
  fi
  pick=$(printf '%s' "$list" | jq -r --arg prefix "$prefix" --arg days "$COOL_OFF_DAYS" "$NEWEST")
  if [ -z "$pick" ]; then
    printf '  %-14s %s (no release older than %s days)\n' "$entry" "$current" "$COOL_OFF_DAYS"; continue
  fi
  IFS=$'\t' read -r tag published url <<< "$pick"
  if [ "$tag" != "$current" ] && newer "$prefix" "$current" "$tag"; then
    jq --arg e "$entry" --arg v "$tag" '.[$e].version = $v' "$PINS" > "$PINS.next" && cat "$PINS.next" > "$PINS"
    rm -f "$PINS.next"
    BUMPED=$((BUMPED + 1))
    printf '  %-14s %s -> %s (published %s)\n' "$entry" "$current" "$tag" "${published%%T*}"
    [ -z "$SUMMARY_FILE" ] || printf -- '- **%s**: `%s` → `%s`, published %s ([release notes](%s))\n' \
      "$entry" "$current" "$tag" "${published%%T*}" "$url" >> "$SUMMARY_FILE"
  else
    printf '  %-14s %s (current)\n' "$entry" "$current"
  fi
done

echo ""
echo "$BUMPED version(s) moved."
if [ -n "$FAILED" ]; then
  echo "ERROR: could not check:$FAILED (GitHub API error or rate limit; export GITHUB_TOKEN)" >&2
  exit 1
fi
