"""Security test: VULN-020 — refresh-aws-certrole must validate before writing a Vault CA.

CWE-863. refresh-aws-certrole.sh takes a trust domain as $1, pulls whatever
`spire-server bundle list -id spiffe://$TD` returns, and writes it straight into
auth/cert/certs/aws-vault-agent — a Vault cert-auth role granting the aws-workload
policy. The only check was `-s` (non-empty), and $TD also lands in allowed_uri_sans.

The script is emitted from gcp/scripts/startup.sh as a heredoc; these tests extract it
and execute it against stubs so they exercise the emitted script.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
STARTUP = REPO_ROOT / "gcp" / "scripts" / "startup.sh"

VALID_PEM = subprocess.run(
    ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", os.devnull,
     "-days", "1", "-subj", "/CN=ca"], capture_output=True, text=True).stdout


def certrole_script() -> str:
    text = STARTUP.read_text()
    m = re.search(r"cat > /usr/local/bin/refresh-aws-certrole\.sh <<'CERTROLE'\n(.*?)^CERTROLE$",
                  text, re.S | re.M)
    if not m:
        raise AssertionError("could not locate the refresh-aws-certrole.sh heredoc")
    return m.group(1)


def run_certrole(tmp: str, td: str, bundle_out: str) -> subprocess.CompletedProcess:
    binp = Path(tmp) / "bin"; binp.mkdir()
    marker = Path(tmp) / "vault_write"
    (binp / "curl").write_text("#!/usr/bin/env bash\necho stub\n")
    (binp / "spire-server").write_text(
        "#!/usr/bin/env bash\ncat <<'PEMEOF'\n%s\nPEMEOF\n" % bundle_out)
    (binp / "vault").write_text(
        '#!/usr/bin/env bash\n'
        'if [ "$1" = "write" ]; then\n'
        '  case "$2" in auth/cert/certs/*) : > "%s" ;; esac\n'
        '  echo stub-token\n'
        'fi\nexit 0\n' % marker)
    for f in binp.iterdir():
        f.chmod(0o755)
    (Path(tmp) / "secret-id").write_text("x")

    script = certrole_script().replace("/opt/vault-certrole/secret-id", str(Path(tmp) / "secret-id"))
    env = dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}")
    proc = subprocess.run(["bash", "-c", script, "_", td],
                          capture_output=True, text=True, env=env, timeout=60)
    proc.wrote_cert_role = marker.exists()
    return proc


class CertRoleRefreshTest(unittest.TestCase):
    def test_rejects_an_unexpected_trust_domain(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_certrole(tmp, "attacker.example", VALID_PEM)
            self.assertFalse(
                p.wrote_cert_role,
                "an arbitrary trust domain was accepted: its bundle becomes a Vault "
                "client CA and its name lands in allowed_uri_sans",
            )

    def test_rejects_a_non_pem_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_certrole(tmp, "viaduct.aws", "not a certificate at all")
            self.assertFalse(
                p.wrote_cert_role,
                "a bundle that is not a parseable certificate was written into "
                "auth/cert/certs/aws-vault-agent",
            )

    def test_accepts_the_federated_domain_with_a_real_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_certrole(tmp, "viaduct.aws", VALID_PEM)
            self.assertTrue(
                p.wrote_cert_role,
                f"the legitimate refresh must still work (rc={p.returncode}, "
                f"stderr={p.stderr[:200]})",
            )


if __name__ == "__main__":
    unittest.main()
