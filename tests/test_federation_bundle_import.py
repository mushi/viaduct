"""Security test: VULN-009/VULN-019 — federated bundles must be gated and validated.

CWE-295. Both directions of the SPIFFE federation exchange fetch a trust bundle with
`curl -sf -k` over the mesh and pipe it straight into `spire-server bundle set`:

  aws/scripts/crosscloud-bootstrap.sh:17   viaduct.gcp root, installed on the AWS node
  aws/scripts/push-bundle-to-gcp.sh:26     viaduct.aws root, installed on the GCP server

Whatever answers in that window becomes a permanent trust root, and a truncated
document is accepted as readily as a well-formed one. TOFU is retained by design; these
tests assert the two preconditions that make it defensible.
"""

import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MESH_TRUST = REPO_ROOT / "scripts" / "lib" / "mesh-trust.sh"
BOOTSTRAP = REPO_ROOT / "aws" / "scripts" / "crosscloud-bootstrap.sh"
PUSH = REPO_ROOT / "aws" / "scripts" / "push-bundle-to-gcp.sh"


def uncommented(lines):
    return "\n".join(l for l in lines if not l.lstrip().startswith("#"))


def is_bundle(content: str) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "b.json"
        f.write_text(content)
        script = f'. "{MESH_TRUST}"\nvh_is_spiffe_bundle "{f}"\n'
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True).returncode == 0


class BundleValidationTest(unittest.TestCase):
    def test_accepts_a_well_formed_bundle(self):
        self.assertTrue(
            is_bundle('{"keys":[{"kty":"EC","crv":"P-256","x":"a","y":"b","use":"x509-svid"}]}'),
            "a genuine SPIFFE bundle must be accepted or federation breaks",
        )

    def test_rejects_a_truncated_document(self):
        self.assertFalse(is_bundle('{"keys":'),
                         "a truncated response must not be installed as a trust root")

    def test_rejects_an_empty_response(self):
        self.assertFalse(is_bundle(""), "an empty response must not become a trust root")

    def test_rejects_a_document_with_no_keys(self):
        for doc in ['{"keys":[]}', '{}', '{"not_a_bundle":true}', 'null']:
            with self.subTest(doc=doc):
                self.assertFalse(is_bundle(doc))


class FederationWiringTest(unittest.TestCase):
    def _assert_gated(self, path: Path, label: str):
        lines = path.read_text().splitlines()
        try:
            fetch = next(i for i, l in enumerate(lines) if "curl" in l and "-k" in l)
        except StopIteration:
            self.fail(f"could not locate the curl -k fetch in {label}")
        before = uncommented(lines[:fetch])
        whole = uncommented(lines)
        self.assertIn(
            "vh_wait_for_mesh_handshake", before,
            f"{label}: the bundle is fetched before any handshake precondition is enforced, "
            f"so an unauthenticated responder becomes a permanent trust root",
        )
        self.assertIn(
            "vh_is_spiffe_bundle", whole,
            f"{label}: the fetched document reaches `spire-server bundle set` without "
            f"being validated as a SPIFFE bundle",
        )

    def test_crosscloud_bootstrap_is_gated(self):
        self._assert_gated(BOOTSTRAP, "crosscloud-bootstrap.sh")


if __name__ == "__main__":
    unittest.main()
