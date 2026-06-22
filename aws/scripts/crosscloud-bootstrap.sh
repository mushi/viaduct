#!/usr/bin/env bash
# Cross-cloud bootstrap (viaduct-crosscloud.service). Retries until the GCP control
# plane is reachable (firewall open to this EIP), then:
#   1. imports the viaduct.gcp federated trust bundle (https_spiffe)
#   2. fetches GCP Vault's listener CA, verifies its pinned fingerprint
#   3. publishes it as the vault-ca ConfigMap
#   4. deploys Alloy (SVID cert-auths cross-cloud to GCP Vault for its Grafana token)
# Config from /opt/viaduct/crosscloud.env (GCP_IP, GCP_FP, GCP_TRUST_DOMAIN).
set -uo pipefail
. /opt/viaduct/crosscloud.env
KUBECTL="k3s kubectl"
SPIRE="/opt/spire/bin/spire-server"

attempt() {
  curl -sk "https://$GCP_IP:8443" | $SPIRE bundle set -format spiffe -id "spiffe://$GCP_TRUST_DOMAIN" || return 1
  mkdir -p /etc/vault-agent/tls
  openssl s_client -connect "$GCP_IP:8200" </dev/null 2>/dev/null | openssl x509 -out /tmp/vault-ca.crt || return 1
  FP=$(openssl x509 -in /tmp/vault-ca.crt -noout -fingerprint -sha256 | cut -d= -f2)
  if [ "$FP" != "$GCP_FP" ]; then echo "FATAL: vault.crt fingerprint mismatch ($FP != $GCP_FP)"; return 2; fi
  install -m0644 /tmp/vault-ca.crt /etc/vault-agent/tls/vault-ca.crt; rm -f /tmp/vault-ca.crt
  $KUBECTL create configmap vault-ca -n viaduct \
    --from-file=vault-ca.crt=/etc/vault-agent/tls/vault-ca.crt --dry-run=client -o yaml | $KUBECTL apply -f - || return 1
  $KUBECTL apply -f /opt/viaduct/k8s/20-alloy.yaml || return 1
  return 0
}

for i in $(seq 1 80); do
  if attempt; then echo "cross-cloud bootstrap complete"; exit 0; fi
  rc=$?
  [ "$rc" = "2" ] && { echo "ABORTED (fingerprint mismatch — possible MITM)"; exit 2; }
  echo "cross-cloud bootstrap attempt $i failed; retry in 15s (is the GCP firewall open to this EIP + Vault aws-vault-agent role configured?)"
  sleep 15
done
echo "gave up after ~20 min; re-run with: systemctl start viaduct-crosscloud"
exit 1
