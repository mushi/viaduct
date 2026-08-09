"""Security test: VULN-019 — push-bundle-to-gcp must gate and validate its import.

CWE-295. aws/scripts/push-bundle-to-gcp.sh builds a REMOTE script that runs on the GCP
box, fetches the viaduct.aws bundle with `curl -sf -k` over the mesh, and pipes it into
`spire-server bundle set`. The imported root immediately drives refresh-aws-certrole.sh,
so a bad import propagates into Vault cert auth.

The controls are inlined in the heredoc rather than sourced, because the GCP box is not
a deployment target for scripts/lib/mesh-trust.sh. These tests extract the heredoc and
execute it against stubbed `wg`, `curl` and `spire-server`, so they exercise the real
emitted script rather than grepping for a token.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PUSH = REPO_ROOT / "aws" / "scripts" / "push-bundle-to-gcp.sh"

AWS_MESH_HOST = "10.99.0.3"
BUNDLE_URL = f"https://{AWS_MESH_HOST}:8443"
TRUST_DOMAIN = "viaduct.aws"
GOOD_BUNDLE = '{"keys":[{"kty":"EC","crv":"P-256","x":"a","y":"b","use":"x509-svid"}]}'


def extract_remote() -> str:
    """Pull the REMOTE heredoc body out of the production script and bind its vars."""
    body = PUSH.read_text()
    m = re.search(r"read -r -d '' REMOTE <<EOF \|\| true\n(.*?)\nEOF\n", body, re.S)
    if not m:
        raise AssertionError("could not locate the REMOTE heredoc in push-bundle-to-gcp.sh")
    text = m.group(1)
    # The heredoc is unquoted: operator-side vars are expanded at generation time.
    text = text.replace("$AWS_MESH_HOST", AWS_MESH_HOST)
    text = text.replace("$AWS_BUNDLE_URL", BUNDLE_URL)
    text = text.replace("$AWS_TRUST_DOMAIN", TRUST_DOMAIN)
    text = re.sub(r"\$\(\(TIMEOUT / INTERVAL\)\)", "2", text)
    text = re.sub(r"\$\(\(.*?\)\)", "2", text)
    text = text.replace("$INTERVAL", "0")
    # Remote-side escapes become live shell.
    text = text.replace("\\$", "$").replace("\\\\", "\\")
    return text


def run_remote(tmp: str, handshake: str, curl_body: str | None) -> subprocess.CompletedProcess:
    """Execute the emitted remote script with stubbed wg / curl / spire-server / sudo."""
    binp = Path(tmp) / "bin"; binp.mkdir()
    (binp / "wg").write_text(
        "#!/usr/bin/env bash\n"
        'case "$2 $3" in\n'
        f'  "wg0 allowed-ips") printf "PUBKEY\\t{AWS_MESH_HOST}/32\\n" ;;\n'
        f'  "wg0 latest-handshakes") printf "PUBKEY\\t{handshake}\\n" ;;\n'
        "esac\n")
    if curl_body is None:
        (binp / "curl").write_text("#!/usr/bin/env bash\nexit 22\n")
    else:
        (binp / "curl").write_text(f"#!/usr/bin/env bash\nprintf '%s' {curl_body!r}\n")
    (binp / "spire-server").write_text("#!/usr/bin/env bash\ncat > /dev/null\necho INSTALLED_ROOT\n")
    (binp / "sudo").write_text('#!/usr/bin/env bash\nexec "$@"\n')
    for f in binp.iterdir():
        f.chmod(0o755)

    env = dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}")
    return subprocess.run(["bash", "-c", extract_remote()],
                          capture_output=True, text=True, env=env, timeout=60)


class RemoteImportGateTest(unittest.TestCase):
    def test_refuses_when_no_handshake(self):
        """Interface up, nobody authenticated -> no trust root may be installed."""
        with tempfile.TemporaryDirectory() as tmp:
            p = run_remote(tmp, handshake="0", curl_body=GOOD_BUNDLE)
            self.assertNotEqual(p.returncode, 0,
                                "remote script imported a trust root with no live mesh handshake")
            self.assertNotIn("INSTALLED_ROOT", p.stdout,
                             "spire-server bundle set was reached despite no handshake")

    def test_refuses_a_non_bundle_response(self):
        """A live mesh, but the endpoint returns something that is not a SPIFFE bundle."""
        import time
        with tempfile.TemporaryDirectory() as tmp:
            p = run_remote(tmp, handshake=str(int(time.time())), curl_body='{"keys":')
            self.assertNotIn("INSTALLED_ROOT", p.stdout,
                             "a truncated document was installed as a federated trust root")
            self.assertNotEqual(p.returncode, 0)

    def test_imports_a_good_bundle_over_a_live_mesh(self):
        import time
        with tempfile.TemporaryDirectory() as tmp:
            p = run_remote(tmp, handshake=str(int(time.time())), curl_body=GOOD_BUNDLE)
            self.assertIn("INSTALLED_ROOT", p.stdout,
                          f"a valid bundle over a live mesh must still import "
                          f"(rc={p.returncode}, stderr={p.stderr[:200]})")


if __name__ == "__main__":
    unittest.main()
