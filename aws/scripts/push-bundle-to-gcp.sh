#!/usr/bin/env bash
# Fetch the AWS SPIRE server's trust bundle and set it on the GCP SPIRE server, so
# GCP re-trusts viaduct.aws after an AWS rebuild (a fresh datastore mints a new CA,
# so the bundle changes). The fetch runs ON the GCP box, which reaches AWS :8443
# over the WireGuard mesh (10.99.0.3) post-lockdown, and pipes straight into
# `spire-server bundle set`, all over one IAP session. The bundle is a CA cert
# (public); this only writes GCP's copy of the peer bundle, and touches nothing on
# AWS. https_spiffe federation self-heals normal ca_ttl rotations on its own; this
# exists only for a rebuild's discontinuous CA.
set -euo pipefail

: "${AWS_BUNDLE_URL:?}"; : "${AWS_TRUST_DOMAIN:?}"
: "${GCP_INSTANCE:?}"; : "${GCP_ZONE:?}"; : "${GCP_SSH_USER:?}"; : "${GCP_SSH_KEY_PATH:?}"
command -v gcloud >/dev/null || { echo "ERROR: gcloud required for the IAP tunnel to GCP." >&2; exit 1; }

GCP_KEY="${GCP_SSH_KEY_PATH/#\~/$HOME}"
TIMEOUT="${TIMEOUT:-300}"; INTERVAL="${INTERVAL:-10}"

# Remote script: retry until the AWS bundle endpoint serves (SPIRE may still be
# starting after the rebuild), then import. Local vars are baked in by the unquoted
# heredoc; remote-side vars are escaped. curl -sk is trust-on-first-use, the same
# as the manual step this replaces.
# Mesh peer whose handshake gates the fetch below. The bundle endpoint is only
# reachable over wg0, so the URL's host is the AWS node's mesh address.
AWS_MESH_HOST="$(printf '%s' "$AWS_BUNDLE_URL" | sed -E 's#^[a-z]+://([^:/]+).*#\1#')"

# The checks below are inlined rather than sourced from scripts/lib/mesh-trust.sh:
# this block runs on the GCP box, which is not a deployment target for that library
# (the Hetzner and AWS nodes each get their own copy). Keep the two implementations
# in step — tests/test_push_bundle_import.py asserts both controls are present here.
read -r -d '' REMOTE <<EOF || true
set -e

# vh_wait_for_mesh_handshake, inline: wg-quick returning does not mean a peer has
# authenticated. Without this the fetch can run across a mesh that authenticates nobody.
deadline=\$(( SECONDS + 30 ))
until pubkey=\$(wg show wg0 allowed-ips 2>/dev/null | awk -v ip="$AWS_MESH_HOST/32" '{ for (i = 2; i <= NF; i++) if (\$i == ip) { print \$1; exit } }') \\
      && [ -n "\$pubkey" ] \\
      && hs=\$(wg show wg0 latest-handshakes 2>/dev/null | awk -v k="\$pubkey" '\$1 == k { print \$2; exit }') \\
      && [ -n "\$hs" ] && [ "\$hs" -gt 0 ] && [ \$(( \$(date +%s) - hs )) -lt 180 ]; do
  if [ "\$SECONDS" -ge "\$deadline" ]; then
    echo "ERROR: no live WireGuard handshake with $AWS_MESH_HOST; refusing to import a trust root over an unauthenticated mesh" >&2
    exit 1
  fi
  sleep 2
done

for _ in \$(seq 1 $((TIMEOUT / INTERVAL))); do
  if bundle=\$(curl -sf -k --max-time 10 "$AWS_BUNDLE_URL"); then
    # vh_is_spiffe_bundle, inline: `bundle set` accepts a truncated document, and this
    # one becomes a federated root that immediately drives refresh-aws-certrole.sh.
    # A substring test for '"keys"' is not enough — a truncated \`{"keys":\` contains
    # it — so the document must actually parse; fail closed if no parser exists.
    if command -v jq >/dev/null 2>&1; then
      printf '%s' "\$bundle" | jq -e 'has("keys") and (.keys|type=="array") and (.keys|length>0)' >/dev/null 2>&1 || {
        echo "ERROR: response from $AWS_BUNDLE_URL is not a well-formed SPIFFE bundle; refusing to install it as a trust root" >&2; exit 1; }
    elif command -v python3 >/dev/null 2>&1; then
      printf '%s' "\$bundle" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if isinstance(d,dict) and isinstance(d.get("keys"),list) and d["keys"] else 1)' >/dev/null 2>&1 || {
        echo "ERROR: response from $AWS_BUNDLE_URL is not a well-formed SPIFFE bundle; refusing to install it as a trust root" >&2; exit 1; }
    else
      echo "ERROR: no jq or python3 on the GCP box to validate the bundle; refusing to install an unvalidated trust root" >&2; exit 1
    fi
    printf '%s' "\$bundle" | sudo spire-server bundle set -format spiffe -id "spiffe://$AWS_TRUST_DOMAIN"
    echo "OK: viaduct.aws bundle set on the GCP server"
    # Then refresh the Vault aws-vault-agent cert role with the new CA, so AWS
    # workloads can still authenticate to Vault after the rebuild.
    sudo /usr/local/bin/refresh-aws-certrole.sh "$AWS_TRUST_DOMAIN"
    exit 0
  fi
  sleep $INTERVAL
done
echo "ERROR: AWS bundle endpoint unreachable from GCP after ${TIMEOUT}s" >&2
exit 1
EOF

echo "Pushing viaduct.aws bundle to the GCP SPIRE server over IAP..."
gcloud compute ssh "${GCP_SSH_USER}@${GCP_INSTANCE}" \
  --zone "${GCP_ZONE}" ${GCP_PROJECT:+--project "${GCP_PROJECT}"} \
  --tunnel-through-iap --ssh-key-file="${GCP_KEY}" \
  --ssh-flag="-o StrictHostKeyChecking=accept-new" \
  --command "$REMOTE"
