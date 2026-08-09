"""Security test: VULN-021 — the mesh precondition must be enforced, and the fetched cert checked.

CWE-306. scripts/fetch-hetzner-secrets.sh captures GCP Vault's listener cert with
`openssl s_client` and uses it as the CA. The unit is ordered
`After=wg-quick@wg0.service`, but wg-quick returns once the interface is configured,
not once a peer handshake has completed — so the fetch can run while the mesh
authenticates nobody. Nothing then checks that the cert actually belongs to the hub.

Drives the real helpers in scripts/lib/mesh-trust.sh.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MESH_TRUST = REPO_ROOT / "scripts" / "lib" / "mesh-trust.sh"
FETCH = REPO_ROOT / "scripts" / "fetch-hetzner-secrets.sh"

HUB_IP = "10.99.0.1"
HUB_PUBKEY = "kOtkkR2VfEHFN0m3ES0BJ0BpKbXPQ8YvvKZ5RRSXSHQ="


def uncommented(lines):
    """Source lines with comment-only lines dropped, so a commented-out guard fails."""
    return "\n".join(l for l in lines if not l.lstrip().startswith("#"))


def make_wg_stub(tmp: str, handshake_epoch: str) -> str:
    """A fake `wg` whose latest-handshakes output the helper must consume."""
    stub = Path(tmp) / "wg"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'case "$2 $3" in\n'
        f'  "wg0 allowed-ips") printf "%s\\t%s/32\\n" "{HUB_PUBKEY}" "{HUB_IP}" ;;\n'
        f'  "wg0 latest-handshakes") printf "%s\\t{handshake_epoch}\\n" "{HUB_PUBKEY}" ;;\n'
        "esac\n"
    )
    stub.chmod(0o755)
    return str(stub)


def call_wait(tmp: str, handshake_epoch: str, timeout: str = "1") -> int:
    wg = make_wg_stub(tmp, handshake_epoch)
    script = (
        f'. "{MESH_TRUST}"\n'
        f'WG_BIN="{wg}" vh_wait_for_mesh_handshake "{HUB_IP}" wg0 {timeout}\n'
    )
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True).returncode


def make_cert(tmp: str, name: str, san_ip: str, days: str = "1") -> Path:
    crt = Path(tmp) / f"{name}.crt"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(Path(tmp) / f"{name}.key"), "-out", str(crt),
         "-days", days, "-subj", f"/CN={name}", "-addext", f"subjectAltName=IP:{san_ip}"],
        capture_output=True,
    )
    return crt


def call_verify(cert: Path, expected_ip: str) -> int:
    script = f'. "{MESH_TRUST}"\nvh_verify_cert_san "{cert}" "{expected_ip}"\n'
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True).returncode


class HandshakeGateTest(unittest.TestCase):
    def test_rejects_when_no_handshake_has_occurred(self):
        """latest-handshakes == 0 means the interface is up but nobody is authenticated."""
        with tempfile.TemporaryDirectory() as tmp:
            self.assertNotEqual(
                call_wait(tmp, "0"), 0,
                "helper returned success with zero handshakes: the TOFU fetch would run "
                "while the mesh authenticates nobody, which is the whole precondition",
            )

    def test_accepts_a_recent_handshake(self):
        import time
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(
                call_wait(tmp, str(int(time.time()))), 0,
                "a live handshake with the hub peer must satisfy the precondition",
            )

    def test_rejects_a_stale_handshake(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertNotEqual(
                call_wait(tmp, "1000000000"), 0,
                "a handshake from 2001 must not count as a live mesh peer",
            )


class CertSanGateTest(unittest.TestCase):
    def test_rejects_a_cert_without_the_hub_ip(self):
        with tempfile.TemporaryDirectory() as tmp:
            rogue = make_cert(tmp, "rogue", "203.0.113.99")
            self.assertNotEqual(
                call_verify(rogue, HUB_IP), 0,
                "a responder's cert with no 10.99.0.1 SAN was accepted as the Vault CA",
            )

    def test_accepts_the_hub_cert(self):
        with tempfile.TemporaryDirectory() as tmp:
            hub = make_cert(tmp, "hub", HUB_IP)
            self.assertEqual(call_verify(hub, HUB_IP), 0,
                             "the genuine hub cert must be accepted or secrets fetch breaks")

    def test_rejects_an_empty_capture(self):
        """`openssl s_client ... 2>/dev/null` yields an empty file when the peer is absent."""
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty.crt"; empty.write_text("")
            self.assertNotEqual(call_verify(empty, HUB_IP), 0,
                                "an empty capture must not be accepted as the CA")

    def test_rejects_an_expired_cert(self):
        with tempfile.TemporaryDirectory() as tmp:
            crt = Path(tmp) / "old.crt"
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", str(Path(tmp) / "old.key"), "-out", str(crt),
                 "-days", "1", "-not_before", "20200101000000Z", "-not_after", "20200102000000Z",
                 "-subj", "/CN=old", "-addext", f"subjectAltName=IP:{HUB_IP}"],
                capture_output=True,
            )
            if not crt.exists() or crt.stat().st_size == 0:
                self.skipTest("openssl build does not support -not_before/-not_after")
            self.assertNotEqual(call_verify(crt, HUB_IP), 0, "an expired cert must be rejected")


class LibraryDeploymentTest(unittest.TestCase):
    """The helper must exist at the path the DEPLOYED script sources.

    fetch-hetzner-secrets.sh is inlined into cloud-init via `file()` (main.tf) and
    written to /usr/local/bin/. It does not run from the repo, so a repo-relative
    source that is never deployed would fail at boot while every repo-side test passed.
    """

    def test_lib_is_deployed_next_to_the_script(self):
        cloud_init = (REPO_ROOT / "cloud-init.yaml.tpl").read_text()
        main_tf = (REPO_ROOT / "main.tf").read_text()

        self.assertIn(
            "mesh_trust_lib", main_tf,
            "main.tf does not pass the mesh-trust library into the cloud-init template, "
            "so /usr/local/bin/lib/mesh-trust.sh will not exist on the node",
        )
        self.assertIn(
            "/usr/local/bin/lib/mesh-trust.sh", cloud_init,
            "cloud-init does not write the mesh-trust library to the path "
            "fetch-hetzner-secrets.sh sources; the unit would fail at boot",
        )

    def test_source_path_matches_the_deployed_path(self):
        """The script's source line must resolve to the deployed location."""
        body = FETCH.read_text()
        self.assertRegex(
            uncommented(body.splitlines()), r"\.\s+\"\$\(cd \"\$\(dirname .*\)\" && pwd\)/lib/mesh-trust\.sh\"",
            "the source line no longer resolves to <script dir>/lib/mesh-trust.sh, which is "
            "what cloud-init deploys",
        )


class FetchScriptWiringTest(unittest.TestCase):
    def test_fetch_waits_for_handshake_and_verifies_before_use(self):
        lines = FETCH.read_text().splitlines()
        try:
            capture = next(i for i, l in enumerate(lines) if "openssl s_client" in l)
        except StopIteration:
            self.fail("could not locate the openssl s_client capture in fetch-hetzner-secrets.sh")
        before = uncommented(lines[:capture])
        after_block = uncommented(lines[capture:])
        self.assertIn("vh_wait_for_mesh_handshake", before,
                      "the cert is captured before any handshake precondition is enforced")
        self.assertIn("vh_verify_cert_san", after_block,
                      "the captured cert is never verified against the expected hub IP")


if __name__ == "__main__":
    unittest.main()
