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
# Installed next to this script by startup.sh.tpl. Provides the mesh handshake gate
# and SPIFFE bundle validation; see the library for why After=wg-quick is not enough.
# shellcheck source=../../scripts/lib/mesh-trust.sh
. /opt/viaduct/lib/mesh-trust.sh
KUBECTL="k3s kubectl"
SPIRE="/opt/spire/bin/spire-server"

attempt() {
  # The retry text below ("mesh up yet?") is the tell: this unit is expected to run
  # before the mesh is usable. Whatever answers 10.99.0.1:8443 in that window would
  # otherwise become a permanent trust root for the whole viaduct.gcp domain.
  vh_wait_for_mesh_handshake "$GCP_IP" wg0 30 || return 1

  local bundle; bundle="$(mktemp)"
  # shellcheck disable=SC2064
  trap "rm -f '$bundle'" RETURN

  curl -sf -k --max-time 10 "https://$GCP_IP:8443" > "$bundle" || return 1
  # `spire-server bundle set` will accept a truncated document; validate first so a
  # partial or hostile response never becomes a federated root.
  vh_is_spiffe_bundle "$bundle" || {
    echo "ERROR: response from $GCP_IP:8443 is not a well-formed SPIFFE bundle; refusing to install it as a trust root" >&2
    return 1
  }
  $SPIRE bundle set -format spiffe -id "spiffe://$GCP_TRUST_DOMAIN" < "$bundle" || return 1
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
