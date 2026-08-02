# AWS node: Kubernetes manifests

`aws/startup.sh` deploys all of this automatically at instance creation (manifests
embedded via Terraform `file()`) and is the source of truth for ordering. The Vault side
(the `aws-vault-agent` cert role, `aws-workload` policy, `kv/aws/grafana` secret) is set up
per [docs/RUNBOOK.md](../../docs/RUNBOOK.md).

## Topology (host vs. pods)

The bare VM runs the identity and mesh plane and k3s itself; the relay and telemetry run as
pods. SPIRE runs on the **host** (its agent does `aws_iid` node attestation and so cannot be
a pod), and the agent's Workload API socket is projected into pods by the SPIFFE CSI driver,
which is how a pod gets an SVID.

```
┌─ AWS EC2 t4g.small · viaduct.aws ────────────────────────────────────────────────┐
│ HOST (bare VM)                                                                   │
│ wg0 10.99.0.3    WireGuard mesh ──►  GCP control plane (Vault, SPIRE root)       │
│ SPIRE server     self-signed CA, keys in AWS KMS · federation :8443 ◄─► GCP      │
│ SPIRE agent      aws_iid node attestation · serves the Workload API socket       │
│ k3s server       --disable traefik, servicelb                                    │
│ timers           spire-agent-token (k8s SA token) · egress-guardrail             │
│                  (~90 GB auto-stop) · viaduct-crosscloud (bootstrap)             │
├─ k3s pods ───────────────────────────────────────────────────────────────────────┤
│ spire   ns   spiffe-csi-driver (DaemonSet)                                       │
│              └ projects the agent's Workload API socket into pods                │
│ viaduct ns   conduit (Deployment + PVC) ──► Psiphon brokers (capped)             │
│              alloy (Deployment); init: fetch-svid + vault-fetch                  │
│                ├─► GCP Vault (SVID cert-auth over mesh) → Grafana token          │
│                └─► Grafana Cloud (metrics)                                       │
└──────────────────────────────────────────────────────────────────────────────────┘
```

## Manifests

| File | Purpose |
|---|---|
| `00-namespaces-rbac.yaml` | `spire` + `viaduct` namespaces; SA + read-only pods/nodes ClusterRole for the host agent's k8s WorkloadAttestor (token is minted/rotated on the host, not a standing Secret); SA `vault-agent` (the workload identity) |
| `01-spiffe-csi-driver.yaml` | SPIFFE CSI driver, projects the agent's Workload API socket into pods (upstream v0.2.12, socket path adapted) |
| `10-conduit.yaml` | Egress-capped Conduit relay + metrics Service |
| `20-alloy.yaml` | Alloy → Grafana Cloud; fetches its token cross-cloud from GCP Vault |

## Sequence (performed by `startup.sh`)

1. Install SPIRE server + agent and k3s; apply `00` → host mints a short-lived SA token (`kubectl create token spire-agent -n spire --duration=24h`) to `/opt/spire/conf/agent/k8s-sa-token` and starts a systemd timer that rotates it (see [Hardening](#hardening)); agent gains the `k8s` attestor.
2. Apply `01` (CSI) and `10` (Conduit).
3. Register `spiffe://viaduct.aws/vault-agent`, parent = the runtime `aws_iid` agent ID, selectors `k8s:ns:viaduct` + `k8s:sa:vault-agent`, `-dns vault-agent.aws`.
4. Cross-cloud bootstrap (`../scripts/crosscloud-bootstrap.sh`, retries until GCP is reachable over the mesh): import the `viaduct.gcp` federated bundle, then apply `20` (Alloy). Alloy's `vault-fetch` init container fetches GCP Vault's listener cert itself over the mesh (TOFU; WireGuard authenticates the peer), so there is no fingerprint to verify and no `vault-ca` ConfigMap to maintain.

Alloy authenticates to GCP Vault with the `aws-vault-agent` cert role, which
`federation-sync` creates automatically on every AWS build. The `aws-workload` policy it
carries and the `kv/aws/grafana` secret it reads are set during Vault bootstrap (see
[docs/RUNBOOK.md](../../docs/RUNBOOK.md)).

To apply by hand, follow the same order and substitute the `__GCP_CONTROL_PLANE_IP__`
placeholder in `20` first (`sed "s|__GCP_CONTROL_PLANE_IP__|<gcp-ip>|g"`).

## Notes

- The k8s SA token and the SPIRE entry aren't vendored as YAML, they depend on a runtime instance-id and a host-minted token (see [Hardening](#hardening)).
- Egress cost is bounded by the host `egress-guardrail` timer (auto-stop near 90 GB/mo); the gauge `aws_mtd_egress_bytes` / `aws_egress_cap_bytes` reaches Grafana via the Alloy unix-exporter textfile collector.

## Hardening

- **Short-lived, rotated k8s SA token (implemented).** The host k8s WorkloadAttestor no longer relies on a standing `spire-agent-token` Secret. Instead the `spire-agent-token.service` oneshot mints a 24h token (`kubectl create token spire-agent -n spire --duration=24h`, via the node's k3s admin kubeconfig) and atomically rewrites `/opt/spire/conf/agent/k8s-sa-token` (`0600 root`); the `spire-agent-token.timer` rotates it every 12h (well inside the 24h TTL) and re-mints ~1min after each boot (the root disk survives stop/start, so a persisted token can be expired on restart). `spire-agent.service` orders after the mint (weak `Wants`) so a reboot gets a fresh token before the agent starts.
  - **No restart / no attestation gap.** The k8s attestor uses the *secure* kubelet client (no read-only port is configured, so it defaults to `10250`, `secure=true`). That client re-reads `token_path` from disk on its `reload_interval` (SPIRE default 1m) on the next `Attest` call, so a rotated file is picked up automatically without restarting `spire-agent`. The atomic `mv` guarantees the attestor never reads a partially written token.
  - **RBAC surface.** The minted token authenticates *as* the `spire-agent` SA to the kubelet, carrying only the existing read-only `pods`/`nodes` `get`/`list` ClusterRole, exactly what the attestor needs. Minting (`create` on the `spire-agent` SA token) is performed by the host's k3s cluster-admin kubeconfig (`/etc/rancher/k3s/k3s.yaml`), so no standing token-creation grant is added to any in-cluster workload SA.
  - **Why host-mint and not a projected volume.** A DaemonSet agent would get a rotated projected token natively, but the host agent we run for `aws_iid` node attestation isn't a pod and can't use a projected-token volume, hence the systemd timer-mint. (vTPM/NitroTPM sealing was considered and rejected for this token: short-lived rotation is the correct fix, and NitroTPM isn't enabled on this instance.)
