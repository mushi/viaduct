# Accepted risks

Findings that were assessed, understood, and deliberately not fixed. Each entry
records the reasoning **and the condition that would invalidate it**, so a future
scan re-raising the finding can be answered without re-deriving the argument —
and so that a change which breaks the precondition is recognised as such.

---

## VULN-006 / VULN-007 — Vault gcp-auth roles authorise on host identity alone

**Status:** accepted, 2026-08-12
**Source:** `claude-conduit_VULNHUNT_RESULTS_2026-08-06-095038`, re-verified by
`/vulnhunt-fix-verify` at `819fe70` (both returned NOT_FIXED)

### The exposure

The `admin`, `restore-agent` and `wireguard-hub` roles authenticate with
`type=gce` bound to the instance's own service account. The GCE metadata server is
reachable by **any local uid** with no privilege, so any process on the control
plane can mint these tokens. Host identity is doing the whole job of process
identity.

`restore-agent` can then mint AppRole secret-ids for `spire-server`,
`snapshot-saver` and `aws-certrole-refresh`, which carry
`pki/root/sign-intermediate`, `sys/storage/raft/snapshot` and
`auth/cert/certs/aws-vault-agent` respectively. `wireguard-hub` can read the hub's
WireGuard private key.

### Why it is accepted

1. **No constrained principal exists on the hub to bypass.** The only interactive
   account is `var.ssh_user`, reached over IAP, which lands in `google-sudoers` and
   is therefore already root-equivalent. There is no `ops`-style least-privilege
   account on the control plane — that pattern exists only on Hetzner, where it is
   enforced by the sudoers wrappers (VULN-029/030).
2. **The remaining non-root principals already hold equivalent power.** They are
   the `spire` and `vault` system accounts, both `nologin`. Code execution as
   `vault` implies access to Vault's own storage; as `spire`, the SPIRE CA. The
   step from there to "can mint a Vault token" is not a meaningful escalation.
3. **The blast radius is bounded.** The `admin` policy no longer grants
   `sys/policies/acl/*` or `auth/gcp/role/*` write, so a holder cannot rebuild
   arbitrary capability, and it can no longer read `kv/data/wireguard/hub`.
4. **The alternatives cost more than the risk.** Delivering `role_id` and
   `secret_id` from a single origin (Terraform) collapses AppRole's two-factor
   split into one factor — an anti-pattern that trades a real property for a
   nominal one. Blocking metadata access per-uid adds a failure mode that impedes
   operations. SPIRE SVID authentication cannot cover `restore-agent` at all: that
   role exists to regenerate the secret-id `spire-server` needs in order to start,
   so requiring an SVID to obtain it is circular. The deployment's simplicity and
   restart resilience are deliberate design goals and outweigh this residual.

### What would invalidate this

Revisit if **any** of these becomes true:

- A constrained interactive account is added to the control plane — an `ops`
  equivalent, a CI login, a support role. It would silently inherit every
  capability listed above, and the sudoers-style boundary you would be trying to
  build for it would not hold.
- A new service runs on the hub under its own non-root uid, particularly one
  exposed to network input.
- The hub gains any network-reachable listener beyond the current IAP + WireGuard
  mesh surface.
- An AppRole policy grows beyond the single path its workload needs (guarded by
  `tests/test_vault_admin_escalation_paths.py`).

### What was done instead

Vault audit devices, which did not previously exist in any form — see
`gcp/scripts/bootstrap-vault.sh`. Prevention was declined; visibility was not.
An exercise of this residual is now on the record rather than invisible.
