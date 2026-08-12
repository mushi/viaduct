"""VULN-006 — the narrowed `admin` policy could rebuild everything it lost.

An independent verification pass returned NOT_FIXED on VULN-006 and VULN-007, and
its reasoning was correct. The earlier remediation kept the gcp-auth role binding
(the operator's decision) and narrowed the `admin` policy instead — but the
narrowed policy still granted create/update on `sys/policies/acl/*` and on
`auth/gcp/role/*`. A holder could write an unrestricted policy and bind a fresh
gcp role to the same service account, recovering arbitrary capability. Since any
local uid on the hub can obtain that token from the GCE metadata server, the
narrowing bought nothing.

Bootstrap runs entirely under the init root token (`: "${VAULT_TOKEN:?...}"` at
the top, revoked at the end), so the standing login never needed those grants.

These tests assert on the policy HCL as bootstrap-vault.sh writes it. There is no
Vault to query here, so the policy text is the artifact under test.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = REPO_ROOT / "gcp" / "scripts" / "bootstrap-vault.sh"

WRITE_CAPS = {"create", "update", "delete", "sudo"}


def policy(name: str) -> str:
    """The heredoc body of `vault policy write <name>`."""
    body = BOOTSTRAP.read_text()
    start = body.index(f"vault policy write {name} - <<'EOF'")
    start = body.index("\n", start) + 1
    return body[start: body.index("\nEOF", start)]


def rules(policy_text: str):
    """[(path, {capabilities})] for each non-comment rule."""
    out = []
    for line in policy_text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        m = re.match(r'\s*path\s+"([^"]+)"\s*\{\s*capabilities\s*=\s*\[([^\]]*)\]', line)
        if m:
            caps = {c.strip().strip('"') for c in m.group(2).split(",") if c.strip()}
            out.append((m.group(1), caps))
    return out


class AdminPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = rules(policy("admin"))

    def caps_for(self, path):
        return next((c for p, c in self.rules if p == path), None)

    def test_the_policy_was_parsed(self):
        """Anchor: an empty rule set would make every assertion below vacuous."""
        self.assertGreater(len(self.rules), 5, f"only parsed {self.rules}")

    def test_it_cannot_write_policies(self):
        """The escalation the verifier found: write a policy, bind a role, re-login."""
        caps = self.caps_for("sys/policies/acl/*") or set()
        self.assertEqual(
            caps & WRITE_CAPS, set(),
            "admin can still create/update ACL policies, so it can grant itself "
            f"anything it was narrowed out of (has {sorted(caps)})")

    def test_it_cannot_create_auth_roles(self):
        for path in ("auth/gcp/role/*", "auth/approle/role/*", "auth/cert/certs/*"):
            with self.subTest(path=path):
                caps = self.caps_for(path) or set()
                self.assertEqual(
                    caps & WRITE_CAPS, set(),
                    f"admin can still write {path}, so it can bind a new role to the "
                    f"same service account with a policy of its choosing")

    def test_it_cannot_mount_engines_or_auth_methods(self):
        for path in ("sys/mounts/*", "sys/auth/*"):
            with self.subTest(path=path):
                caps = self.caps_for(path) or set()
                self.assertEqual(caps & WRITE_CAPS, set(),
                                 f"admin can still mount at {path}")

    def test_no_rule_carries_sudo(self):
        for path, caps in self.rules:
            with self.subTest(path=path):
                self.assertNotIn("sudo", caps,
                                 f"{path} still carries sudo on the standing login")

    def test_it_cannot_read_the_wireguard_hub_private_key(self):
        """Full `kv/*` read disclosed the hub key, the CF token and the Grafana creds."""
        for path, caps in self.rules:
            if not path.startswith("kv/"):
                continue
            with self.subTest(path=path):
                self.assertNotIn(
                    "wireguard/hub", path,
                    "admin can read the hub's WireGuard private key")
                self.assertNotEqual(
                    path, "kv/*",
                    "a blanket kv/* grant still covers kv/data/wireguard/hub")

    def test_it_can_still_do_the_documented_operator_work(self):
        """Anchor: RUNBOOK.md's seeding steps must keep working."""
        for path in ("kv/data/aws/*", "kv/data/hetzner/*"):
            with self.subTest(path=path):
                caps = self.caps_for(path) or set()
                self.assertTrue({"create", "update"} <= caps,
                                f"the operator can no longer seed {path}")

    def test_it_can_still_clear_a_stale_peer_registration(self):
        """Anchor: VULN-012's documented recovery for a rebuilt spoke."""
        caps = self.caps_for("kv/data/wireguard/peers/*") or set()
        self.assertIn("delete", caps,
                      "`vault kv delete kv/wireguard/peers/<name>` no longer works, "
                      "which is the documented fix for a rebuilt spoke")


class ProvisioningStaysWithRootTest(unittest.TestCase):
    def test_bootstrap_requires_the_root_token(self):
        """The grants removed above are only needed here, under the init root token."""
        self.assertIn('VAULT_TOKEN:?', BOOTSTRAP.read_text(),
                      "bootstrap no longer demands the init root token, so the "
                      "narrowed admin policy would leave provisioning impossible")

    def test_root_is_revoked_only_after_admin_login_is_proven(self):
        """Anchor: narrowing must not be able to lock the operator out."""
        body = BOOTSTRAP.read_text()
        self.assertLess(
            body.index("vault login -method=gcp -token-only role=admin"),
            body.index("vault token revoke -self"),
            "root is revoked before the admin login is verified")


class AppRolePoliciesStayMinimalTest(unittest.TestCase):
    """VULN-007's Arm A capabilities — each already a single path. Guard against drift."""

    EXPECTED = {
        "spire-upstream": {"pki/root/sign-intermediate"},
        "snapshot": {"sys/storage/raft/snapshot"},
        "aws-certrole-refresh": {"auth/cert/certs/aws-vault-agent"},
    }

    def test_each_approle_policy_grants_exactly_one_path(self):
        for name, paths in self.EXPECTED.items():
            with self.subTest(policy=name):
                self.assertEqual({p for p, _ in rules(policy(name))}, paths,
                                 f"{name} gained a path beyond what its workload needs")


if __name__ == "__main__":
    unittest.main()
