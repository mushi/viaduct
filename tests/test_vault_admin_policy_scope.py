"""Security test: VULN-006 — the Vault admin policy must not be blanket sudo.

CWE-863. gcp/scripts/bootstrap-vault.sh wrote an `admin` policy granting sudo across
`sys/*`, `auth/*` and `pki/*`, then bound it to a gcp-auth role scoped only to the
project, zone and the instance's own service account. Any local uid on the hub can
reach the GCE metadata server, so any of them could mint that token.

Per the operator's decision the binding is retained and the policy is narrowed, so the
token can no longer seal the cluster, disable audit devices, read sys/raw, or rewrite
unrelated auth backends. These assertions read the emitted policy HCL.

Superseded in part: this file originally required the admin policy to keep the
provisioning grants "which bootstrap-vault.sh itself calls". That premise was wrong.
Bootstrap demands the init root token at the top and revokes it at the very end; its
only `role=admin` login is `-token-only ... >/dev/null`, a liveness check before the
revoke. Nothing in bootstrap ever operates as admin, so keeping those grants bought
nothing and left `sys/policies/acl/*` + `auth/gcp/role/*` as a complete escalation.
See test_vault_admin_escalation_paths.py, which asserts they are gone.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = REPO_ROOT / "gcp" / "scripts" / "bootstrap-vault.sh"

# The standing operator surface RUNBOOK.md documents. Narrowing must not remove
# these — unlike the provisioning grants, which belong to the root token.
REQUIRED = [
    "kv/data/aws/",              # vault kv put kv/aws/grafana
    "kv/data/hetzner/",          # vault kv put kv/hetzner/{grafana,cloudflare}
    "kv/data/wireguard/peers/",  # clearing a stale registration (VULN-012 recovery)
    "sys/mounts",                # read-only introspection
    "sys/auth",                  # read-only introspection
    "pki/cert/",                 # inspect the issued chain
]


def policy_body(name: str) -> str:
    """Extract a `vault policy write <name> - <<'EOF' ... EOF` heredoc body."""
    text = BOOTSTRAP.read_text()
    m = re.search(rf"vault policy write {re.escape(name)} - <<'EOF'\n(.*?)\nEOF", text, re.S)
    if not m:
        raise AssertionError(f"could not locate the {name!r} policy in bootstrap-vault.sh")
    return m.group(1)


def declared_paths(body: str):
    return re.findall(r'path\s+"([^"]+)"', body)


class AdminPolicyScopeTest(unittest.TestCase):
    def setUp(self):
        self.body = policy_body("admin")
        self.paths = declared_paths(self.body)

    def test_no_blanket_sys_grant(self):
        self.assertNotIn(
            "sys/*", self.paths,
            'the admin policy still grants all of sys/* — that includes sys/seal, '
            'sys/audit, sys/raw, sys/rekey and sys/step-down',
        )

    def test_no_blanket_auth_grant(self):
        self.assertNotIn(
            "auth/*", self.paths,
            'the admin policy still grants all of auth/* — that includes disabling auth '
            'methods and minting tokens through auth/token/*',
        )

    def test_sudo_is_not_granted_on_a_wildcard_top_level_path(self):
        """sudo is what makes root-protected endpoints reachable; keep it narrow."""
        for stanza in re.findall(r'path\s+"([^"]+)"\s*\{([^}]*)\}', self.body):
            path, caps = stanza
            if "sudo" in caps:
                self.assertNotRegex(
                    path, r'^[a-z]+/\*$',
                    f'sudo is granted on the blanket path "{path}"; scope it to the '
                    f'specific endpoints bootstrap needs',
                )

    def test_the_documented_operator_surface_survives(self):
        """Narrowing must not lock the operator out of the RUNBOOK steps.

        Note this deliberately no longer requires the provisioning paths. Bootstrap
        runs under the init root token, so those never belonged to the standing login.
        """
        joined = " ".join(self.paths)
        for needed in REQUIRED:
            self.assertIn(
                needed, joined,
                f"the admin policy no longer covers {needed!r}, which RUNBOOK.md "
                f"documents as an operator step",
            )


if __name__ == "__main__":
    unittest.main()
