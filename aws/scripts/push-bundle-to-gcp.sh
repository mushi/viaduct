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
read -r -d '' REMOTE <<EOF || true
set -e
for _ in \$(seq 1 $((TIMEOUT / INTERVAL))); do
  if bundle=\$(curl -sf -k --max-time 10 "$AWS_BUNDLE_URL"); then
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
