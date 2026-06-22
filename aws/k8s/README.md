# AWS node — Kubernetes manifests

`aws/startup.sh` deploys all of this automatically at instance creation (manifests
embedded via Terraform `file()`) and is the source of truth for ordering.

> [!IMPORTANT]  
> Vault TLS authentication requires manual steps, documented [below](#vault-cert-auth-bootstrap).


## Manifests

| File | Purpose |
|---|---|
| `00-namespaces-rbac.yaml` | `spire` + `viaduct` namespaces; SA + token for the host agent's k8s WorkloadAttestor; SA `vault-agent` (the workload identity) |
| `01-spiffe-csi-driver.yaml` | SPIFFE CSI driver — projects the agent's Workload API socket into pods (upstream v0.2.12, socket path adapted) |
| `10-conduit.yaml` | Egress-capped Conduit relay + metrics Service |
| `20-alloy.yaml` | Alloy → Grafana Cloud; fetches its token cross-cloud from GCP Vault |

## Sequence (performed by `startup.sh`)

1. Install SPIRE server + agent and k3s; apply `00` → host writes the SA token to `/opt/spire/conf/agent/k8s-sa-token`, agent gains the `k8s` attestor.
2. Apply `01` (CSI) and `10` (Conduit).
3. Register `spiffe://viaduct.aws/vault-agent` — parent = the runtime `aws_iid` agent ID, selectors `k8s:ns:viaduct` + `k8s:sa:vault-agent`, `-dns vault-agent.aws`.
4. Cross-cloud bootstrap (`../scripts/crosscloud-bootstrap.sh`, retries until GCP is reachable): import the `viaduct.gcp` federated bundle, fetch + fingerprint-verify `vault.crt`, create the `vault-ca` ConfigMap, apply `20` (Alloy). **Requires the Vault role below.**

To apply by hand, follow the same order — substitute the `__GCP_CONTROL_PLANE_IP__`
placeholder in `20` first (`sed "s|__GCP_CONTROL_PLANE_IP__|<gcp-ip>|g"`), and ensure the
Vault role exists before applying `20`.

## Vault cert auth bootstrap

Not automatable in `startup.sh` (needs a privileged Vault token). Run on the GCP box:

```sh
export VAULT_ADDR=https://127.0.0.1:8200 VAULT_SKIP_VERIFY=true
read -rsp 'VAULT_TOKEN: ' VAULT_TOKEN; export VAULT_TOKEN; echo   # prompted, kept out of shell history

# trust the viaduct.aws root (from GCP's federated bundle store) for cert-auth
sudo /usr/local/bin/spire-server bundle list -id spiffe://viaduct.aws -format pem > /tmp/aws-root.pem
vault policy write aws-workload - <<'EOF'
path "kv/data/aws/*" { capabilities = ["read"] }
EOF
vault write auth/cert/certs/aws-vault-agent \
  display_name=aws-vault-agent policies=aws-workload \
  certificate=@/tmp/aws-root.pem \
  allowed_uri_sans="spiffe://viaduct.aws/vault-agent" \
  token_ttl=20m token_max_ttl=1h
rm -f /tmp/aws-root.pem

# the AWS node's own secrets (disjoint per node): Grafana Cloud creds for Alloy
vault kv put kv/aws/grafana \
  prometheus_url='<grafana_cloud_prometheus_url>' \
  prometheus_user='<grafana_cloud_prometheus_user>' \
  api_key='<grafana_cloud_metrics:write_token>'
```

> Use a scoped admin token, not the root token, for this. If you must use root,
> `vault token revoke -self` when done — root tokens have no TTL and otherwise live
> on indefinitely (in memory, `~/.vault-token`, scrollback).

## Notes

- The `vault-ca` ConfigMap, the SA token, and the SPIRE entry aren't vendored as YAML — they depend on a host cert, a runtime instance-id, and a generated token.
- Egress cost is bounded by the host `egress-guardrail` timer (auto-stop near 90 GB/mo); the gauge `aws_mtd_egress_bytes` / `aws_egress_cap_bytes` reaches Grafana via the Alloy unix-exporter textfile collector.

## Hardening (deferred)

- The host k8s SA token (`spire-agent-token` Secret → `/opt/spire/conf/agent/k8s-sa-token`) is **long-lived**. It's read-only (pods/nodes get/list) and `0600 root`, so low risk on a single-node box — but to drop the standing token, remove the Secret and have a systemd timer mint a short-lived one (`kubectl create token spire-agent -n spire --duration=24h`) that rewrites the file. (A DaemonSet agent gets a projected token natively; the host agent we run for `aws_iid` can't use a projected-token volume.)
