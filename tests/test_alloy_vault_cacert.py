"""Security test: VULN-008 — the Alloy init container's VAULT_CACERT must not be a tautology.

CWE-295. aws/k8s/20-alloy.yaml captures Vault's listener certificate from the very
endpoint it is then used to verify, so any responder is trusted. The pipeline also
swallows failure (`2>/dev/null`), so an empty file silently becomes the CA and the
SVID client certificate is presented to whatever answered.

A pod cannot source scripts/lib/mesh-trust.sh, so the controls are inlined. These tests
extract the init container's shell block from the manifest and execute it against a
stubbed `openssl`, exercising the emitted script rather than grepping for a token.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ALLOY = REPO_ROOT / "aws" / "k8s" / "20-alloy.yaml"
MESH_IP = "10.99.0.1"


def extract_init_block() -> str:
    """Pull the init container's inline shell out of the manifest."""
    text = ALLOY.read_text()
    m = re.search(r"^\s*- \|\n(.*?)(?=\n\s*(?:-|\w+:))", text, re.S | re.M)
    if not m:
        raise AssertionError("could not locate the init container shell block in 20-alloy.yaml")
    block = m.group(1)
    lines = [l for l in block.splitlines()]
    indent = min((len(l) - len(l.lstrip()) for l in lines if l.strip()), default=0)
    body = "\n".join(l[indent:] for l in lines)
    # The manifest is templated on the host before apply.
    body = body.replace("__GCP_CONTROL_PLANE_IP__", MESH_IP)
    # Cut at the security boundary under test: everything after the vault login is
    # config rendering into /rendered, which cannot exist in a test harness.
    out = []
    for line in body.splitlines():
        out.append(line)
        if line.strip().startswith("vault login"):
            break
    return "\n".join(out)


def run_block(tmp: str, cert_pem: str) -> subprocess.CompletedProcess:
    """Execute the init block with openssl/vault/apk stubbed; cert_pem is what s_client yields."""
    binp = Path(tmp) / "bin"; binp.mkdir()
    certfile = Path(tmp) / "served.pem"; certfile.write_text(cert_pem)

    # `openssl s_client` emits the served bytes; `openssl x509` and the rest defer to the
    # real openssl so parsing/expiry/SAN checks are genuine.
    real = subprocess.run(["bash", "-c", "command -v openssl"], capture_output=True, text=True).stdout.strip()
    (binp / "openssl").write_text(
        "#!/usr/bin/env bash\n"
        'if [ "$1" = "s_client" ]; then cat "%s"; exit 0; fi\n'
        'exec %s "$@"\n' % (certfile, real))
    marker = Path(tmp) / "vault_called"
    (binp / "vault").write_text(
        '#!/usr/bin/env bash\n'
        'if [ "$1" = "login" ]; then : > "%s"; fi\n'
        'exit 0\n' % marker)
    (binp / "apk").write_text("#!/usr/bin/env bash\nexit 0\n")
    for f in binp.iterdir():
        f.chmod(0o755)

    env = dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}")
    proc = subprocess.run(["bash", "-c", extract_init_block()],
                          capture_output=True, text=True, env=env, timeout=60)
    proc.vault_login_reached = (Path(tmp) / "vault_called").exists()
    return proc


def make_cert(tmp: str, san_ip: str) -> str:
    crt = Path(tmp) / "c.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(Path(tmp) / "c.key"), "-out", str(crt), "-days", "1",
         "-subj", "/CN=vault", "-addext", f"subjectAltName=IP:{san_ip}"],
        capture_output=True)
    return crt.read_text()


class AlloyCacertGateTest(unittest.TestCase):
    def test_rejects_an_empty_capture(self):
        """`openssl s_client ... 2>/dev/null` yields nothing when no peer answers."""
        with tempfile.TemporaryDirectory() as tmp:
            p = run_block(tmp, "")
            self.assertFalse(p.vault_login_reached,
                             "vault login proceeded with an empty CA file")
            self.assertNotEqual(p.returncode, 0, "init container did not fail closed on an empty capture")

    def test_rejects_a_cert_without_the_control_plane_ip(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_block(tmp, make_cert(tmp, "203.0.113.99"))
            self.assertFalse(p.vault_login_reached,
                             "the SVID was presented to a responder whose cert is not the hub's")
            self.assertNotEqual(p.returncode, 0)

    def test_accepts_the_control_plane_cert(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_block(tmp, make_cert(tmp, MESH_IP))
            self.assertTrue(p.vault_login_reached,
                            f"the genuine control-plane cert must still be accepted "
                            f"(rc={p.returncode}, stderr={p.stderr[:200]})")


if __name__ == "__main__":
    unittest.main()
