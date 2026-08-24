"""Xray geo data (geoip.dat / geosite.dat) must be pinned and verified against a
recorded digest — not a checksum fetched from the same release path.

geoip.dat/dlc.dat were checked against a `.sha256sum` fetched from the same mutable
release path as the artifact, which proves transport integrity and nothing else:
whatever can serve a modified .dat can serve a matching sum. And `releases/latest/`
floats, so a fixed digest could not even describe it. Both are now pinned to a release
tag with the digest recorded in variables.tf, matching conduit/xray/alloy.

The verification idiom is extracted from cloud-init.yaml.tpl and executed against a
stub, so what is asserted is that a tampered artifact actually stops the boot — not
that a `sha256sum` line is merely present.
"""

import hashlib
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CLOUD_INIT = REPO_ROOT / "cloud-init.yaml.tpl"
VARIABLES = REPO_ROOT / "variables.tf"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def render(body: str) -> str:
    return body.replace("$${", "${").replace("%%{", "%{")


def uncommented(text: str) -> str:
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def tf_default(path: Path, name: str) -> str:
    body = path.read_text()
    block = body[body.index(f'variable "{name}" {{'):]
    block = block[: block.index("\n}")]
    return re.search(r'default\s*=\s*"([^"]*)"', block).group(1)


class GeoDataPinTest(unittest.TestCase):
    def setUp(self):
        self.body = uncommented(CLOUD_INIT.read_text())

    def test_no_sum_is_fetched_from_the_release_path(self):
        self.assertNotIn(".sha256sum", self.body,
                         "a checksum is still fetched from the same release path as the "
                         "artifact, which proves transport integrity only")

    def test_pinned_to_a_release_tag_not_latest(self):
        self.assertNotIn("releases/latest/download", self.body,
                         "geo data still tracks `latest`, which a fixed digest cannot describe")

    def test_recorded_digests_are_real_sha256(self):
        for name in ("geoip_sha256", "geosite_sha256"):
            with self.subTest(variable=name):
                self.assertRegex(tf_default(VARIABLES, name), SHA256_RE,
                                 f"{name} is not a 64-hex SHA-256 — it verifies nothing")


class DigestCheckBehaviourTest(unittest.TestCase):
    """Execute the extracted verification idiom against good and tampered bytes. The
    fragment is rendered the way templatefile() renders it — every ${var} replaced by
    its variables.tf default — so what runs here is what the node runs. `overrides` lets
    a test substitute a different pin, so the accept path is exercised without shipping a
    real geo file: if the check were a no-op, changing the pin would not change the outcome."""

    @staticmethod
    def geo_fragment(overrides=None) -> str:
        body = render(CLOUD_INIT.read_text())
        start = body.index('curl -fsSL "https://github.com/v2fly/geoip')
        tail = "mv /tmp/dlc.dat /usr/local/bin/geosite.dat"
        end = body.index(tail, start) + len(tail)
        lines = body[start:end].splitlines()
        indent = min(len(l) - len(l.lstrip()) for l in lines if l.strip())
        fragment = "\n".join(l[indent:] for l in lines)
        values = dict(overrides or {})

        def resolve(m):
            return values.get(m.group(1)) or tf_default(VARIABLES, m.group(1))

        return re.sub(r"\$\{([a-z0-9_]+)\}", resolve, fragment)

    def run_fragment(self, served: bytes, overrides=None):
        tmp = tempfile.mkdtemp()
        binp = Path(tmp) / "bin"; binp.mkdir()
        blob = Path(tmp) / "served.bin"; blob.write_bytes(served)
        (binp / "curl").write_text(
            '#!/usr/bin/env bash\nout=""\nwhile [ $# -gt 0 ]; do\n'
            '  [ "$1" = "-o" ] && { out="$2"; shift; }\n  shift\ndone\n'
            'case "$out" in /*) ;; *) echo "stub curl: bad -o $out" >&2; exit 90 ;; esac\n'
            f'cp "{blob}" "$out"\nexit 0\n')
        (binp / "mv").write_text(
            f'#!/usr/bin/env bash\necho "mv $*" >> "{tmp}/installed.log"\nexit 0\n')
        for f in binp.iterdir():
            f.chmod(0o755)
        p = subprocess.run(
            ["bash", "-c", "set -e\n" + self.geo_fragment(overrides)],
            capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
            env=dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}"))
        log = Path(tmp) / "installed.log"
        p.installed = log.read_text() if log.exists() else ""
        return p

    def test_the_fragment_carries_the_recorded_pins(self):
        fragment = self.geo_fragment()
        for name in ("geoip_sha256", "geosite_sha256"):
            with self.subTest(variable=name):
                self.assertIn(tf_default(VARIABLES, name), fragment,
                              f"the rendered fragment does not carry {name}")

    def test_an_artifact_matching_the_pin_installs(self):
        """Anchor: without this every rejection below could be an unconditional abort."""
        payload = b"stand-in for the published geo data"
        digest = hashlib.sha256(payload).hexdigest()
        p = self.run_fragment(payload, overrides={"geoip_sha256": digest, "geosite_sha256": digest})
        self.assertEqual(p.returncode, 0, f"a matching artifact was rejected: {p.stderr}")
        self.assertIn("geoip.dat", p.installed, f"nothing was installed: {p.stderr}")
        self.assertIn("geosite.dat", p.installed, f"geosite.dat was not installed: {p.stderr}")

    def test_a_tampered_artifact_stops_the_boot(self):
        p = self.run_fragment(b"tampered geoip payload")
        self.assertNotEqual(p.returncode, 0,
                            "a payload not matching the pin was accepted; the routing data "
                            "Xray uses would be attacker-set")
        self.assertNotIn("geoip.dat", p.installed,
                         f"the tampered file was installed anyway: {p.installed}")

    def test_a_matching_geoip_does_not_carry_a_tampered_geosite(self):
        """Each artifact is checked against its own pin, not the first one to match."""
        payload = b"stand-in for the published geo data"
        digest = hashlib.sha256(payload).hexdigest()
        p = self.run_fragment(payload, overrides={"geoip_sha256": digest})
        self.assertNotEqual(p.returncode, 0, "geosite.dat skipped its own digest check")
        self.assertNotIn("geosite.dat", p.installed,
                         f"geosite.dat was installed unverified: {p.installed}")


if __name__ == "__main__":
    unittest.main()
