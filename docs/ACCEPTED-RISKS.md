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
3. **The blast radius is bounded, but not small.** The `admin` policy no longer
   grants `sys/policies/acl/*` or `auth/gcp/role/*` write, so a holder cannot
   rebuild arbitrary capability, and it can no longer read
   `kv/data/wireguard/hub`. What it *does* still hold is worth stating plainly
   rather than leaving to be discovered:

   - create/read/update/delete on `kv/data/aws/*` and `kv/data/hetzner/*` — the
     **Cloudflare DNS-edit token** and the **Grafana Cloud keys**. The Cloudflare
     token can create records for the zone, which is a path to issuing
     certificates for the domain.
   - read/delete on `kv/data/wireguard/peers/*`, so a holder can drop a peer
     registration (a spoke disconnects at the next reconcile) though not read the
     hub key or forge a peer.

   That is the standing capability of anything on the hub that can read the GCE
   metadata identity JWT. It is accepted for the reasons above, not because it is
   trivial. An independent re-verification at `a540f43` returned PARTIAL on
   VULN-006 for exactly this: the escalation loop is closed, the class is not, and
   this file is documented risk acceptance rather than a code control.
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

---

## VULN-008 / VULN-009 — Vault listener cert and SPIFFE bundle trusted on first use

**Status:** accepted, 2026-08-13
**Source:** `claude-conduit_VULNHUNT_RESULTS_2026-08-06-095038`, re-verified by
`/vulnhunt-fix-verify` at `819fe70` (both returned NOT_FIXED)

Also covers the same idiom in `scripts/fetch-hetzner-secrets.sh`. That path is
recorded as FIXED under VULN-021, but only because VULN-021 was filed narrowly —
against the missing WireGuard precondition, not the TOFU itself. Structurally it
is identical to VULN-008.

### The exposure

Three fetches derive a trust anchor from the connection they are about to trust:

- `aws/k8s/20-alloy.yaml` — `openssl s_client` into `/tmp/vault-ca.crt`, then used
  as `VAULT_CACERT` (VULN-008)
- `aws/scripts/crosscloud-bootstrap.sh` — `curl -k` for the federation bundle,
  then `spire-server bundle set` (VULN-009)
- `scripts/fetch-hetzner-secrets.sh` — the same `s_client` capture

The added SAN check does not authenticate: a rogue responder self-signs a
certificate carrying the expected IP and satisfies it. It verifies no issuer and
no chain.

### Why it is accepted

1. **Every one of these paths is mesh-only.** The GCP hub's firewall has exactly
   two ingress rules — IAP SSH from `35.235.240.0/20`, and WireGuard UDP. There is
   no `:8200` rule. `GCP_IP` is `var.wg_hub_ip`, so all of this is `wg0` traffic.
   An attacker must already be a mesh peer, holding a registered WireGuard key and
   preshared key.
2. **Impersonating the hub additionally requires claiming its mesh address**, and
   the registry refuses that — see VULN-005's fix ("a peer may never claim the
   hub's own 10.99.0.1") plus the mesh-IP uniqueness enforced at the writer.
3. **The same reasoning already passed two sibling findings.** VULN-019 and
   VULN-020 were verified FIXED explicitly because "the response's origin is
   established by WireGuard peer authentication rather than by TOFU". VULN-009
   received the same control and was failed only because its finding text had
   pre-emptively dismissed it. The control is the same in all four.
4. **The alternative lands on the boot path.** Issuing the listener cert from
   Vault's own PKI root is the only variant that survives a rebuild (the root rides
   in the raft snapshot; `/opt/vault/tls` is on the boot disk and is regenerated
   every replacement). It needs Vault to boot self-signed, re-issue, and restart —
   in a design where rebuild-and-restore is routine, that is the one path that must
   not be brittle. It also touches ~15 call sites, and the current
   `VAULT_CACERT=<leaf>` idiom works only because the leaf is self-signed: Go
   clients would still accept a PKI-issued leaf as its own root, OpenSSL clients
   would not, so the migration is all-or-nothing.

### What would invalidate this

- The mesh gate ceasing to be sound. It is now load-bearing for VULN-008, 009,
  019, 020 and 021 alike — guarded by `tests/test_mesh_peer_match_exact.py`.
- `:8200`, `:8443` or any other control-plane port being opened beyond the mesh.
- A peer being able to claim `10.99.0.1`, or mesh-IP uniqueness being relaxed
  (`tests/test_wg_peer_registry.py`, `tests/test_verify_followup_gaps.py`).
- Mesh membership becoming obtainable without an existing node — for example a
  self-service registration path.

### What was done instead

The mesh gate was corrected. `vh_wait_for_mesh_handshake` mapped a peer IP to a
public key with an unanchored whole-line regex, so a peer at `10.99.0.30/32`
answered for `10.99.0.3`, the dots matched as wildcards, and ordering decided ties.
Since the acceptance above rests entirely on that gate, its correctness matters
more than the TOFU it is standing in for.
