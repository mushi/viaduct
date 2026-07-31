#!/usr/bin/env bash
# Cross-cloud bootstrap (viaduct-crosscloud.service). Runs at boot and retries until the
# GCP control plane is reachable over the WireGuard mesh, then:
#   1. imports the viaduct.gcp federated trust bundle (https_spiffe), bootstrapping the
#      federation trust that SPIRE's federates_with polling then maintains;
#   2. deploys Alloy, whose init container fetches GCP Vault's cert over the mesh and
#      cert-auths for its Grafana token at pod start.
# Config from /opt/viaduct/crosscloud.env (GCP_IP = the hub mesh IP, GCP_TRUST_DOMAIN).
# No Vault cert is fetched or fingerprint-pinned here: the mesh authenticates the peer, so
# Alloy trusts-on-first-use over it (self-healing across a GCP cert rotation, no refresh).
set -uo pipefail
. /opt/viaduct/crosscloud.env
KUBECTL="k3s kubectl"
SPIRE="/opt/spire/bin/spire-server"

attempt() {
  curl -sf -k --max-time 10 "https://$GCP_IP:8443" \
    | $SPIRE bundle set -format spiffe -id "spiffe://$GCP_TRUST_DOMAIN" || return 1
  $KUBECTL apply -f /opt/viaduct/k8s/20-alloy.yaml || return 1
  return 0
}

for i in $(seq 1 80); do
  attempt && { echo "cross-cloud bootstrap complete"; exit 0; }
  echo "cross-cloud bootstrap attempt $i failed; retry in 15s (mesh up yet? aws-vault-agent Vault role seeded?)"
  sleep 15
done
echo "gave up after ~20 min; re-run with: systemctl restart viaduct-crosscloud"
exit 1
