"""Security tests: VULN-028, VULN-042, VULN-048 — secret files must be created private.

All three share one root cause: a file holding key material is written at the ambient
umask and only chmod-ed afterwards, so it is world-readable for the window in between.

- VULN-028 (CWE-378): the Reality X25519 keypair is generated into a fixed
  /tmp/xray-x25519.txt — predictable as well as readable.
- VULN-042 (CWE-312): keypair.env and the per-user .uuid files are written then chmod-ed.
- VULN-048 (CWE-732): probe-client.json, a live VLESS credential, lands in /etc/xray
  (mode 0755) the same way.

These tests execute the real emitted fragments and inspect the mode of the file at the
moment it is created, before any chmod runs.
"""

import os
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TPL = REPO_ROOT / "cloud-init.yaml.tpl"
BODY = TPL.read_text()


def mode_of(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def run(script: str, tmp: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                          cwd=tmp, timeout=30)


class Vuln028TempKeypairTest(unittest.TestCase):
    """The x25519 output must not go to a predictable, world-readable path."""

    def test_no_fixed_tmp_path_for_the_keypair(self):
        self.assertNotIn(
            "/tmp/xray-x25519.txt", BODY,
            "the Reality keypair is still generated into a fixed /tmp path, which is "
            "both predictable (symlink target) and created at the ambient umask",
        )

    def test_generation_uses_mktemp_under_a_restrictive_umask(self):
        gen = BODY[BODY.index("xray x25519") - 400: BODY.index("xray x25519") + 200]
        self.assertIn("mktemp", gen, "the keypair temp file is not created with mktemp")
        self.assertRegex(gen, r"umask 077",
                         "the keypair temp file is not created under a restrictive umask")

    def test_a_umask_077_mktemp_actually_yields_0600(self):
        """Behavioural: prove the idiom used produces a private file."""
        with tempfile.TemporaryDirectory() as tmp:
            p = run('f="$(umask 077; mktemp)"; printf secret > "$f"; stat -c %a "$f" 2>/dev/null '
                    '|| stat -f %Lp "$f"; rm -f "$f"', tmp)
            self.assertEqual(p.stdout.strip(), "600",
                             f"umask 077 + mktemp did not produce a 0600 file: {p.stdout!r}")


class Vuln042KeyMaterialModeTest(unittest.TestCase):
    """keypair.env and the UUID files must be created 0600, not fixed afterwards."""

    def test_keypair_branch_sets_the_umask_before_writing(self):
        branch = BODY[BODY.index('if [[ ! -f "$KEYPAIR_FILE" ]]; then'):]
        branch = branch[:branch.index("Generated new Reality keypair")]
        self.assertRegex(branch, r"umask 077",
                         "the keypair branch writes key material at the ambient umask")

    def test_uuid_file_created_under_a_restrictive_umask(self):
        idx = BODY.index('echo "$USER_UUID" > "$UUID_FILE"')
        window = BODY[idx - 300:idx + 100]
        self.assertIn("umask 077", window,
                      "the per-user UUID file is written at the ambient umask and only "
                      "chmod-ed afterwards, so it is briefly world-readable")

    def test_write_then_chmod_yields_a_readable_window(self):
        """Behavioural: demonstrate why creation mode, not chmod, is the control."""
        with tempfile.TemporaryDirectory() as tmp:
            p = run('umask 022; printf secret > f; stat -c %a f 2>/dev/null || stat -f %Lp f', tmp)
            self.assertNotEqual(
                p.stdout.strip(), "600",
                "the ambient umask already yields 0600 here, so this environment cannot "
                "demonstrate the window; the assertion above is the binding one",
            )


class Vuln048ProbeClientTest(unittest.TestCase):
    """probe-client.json holds a live VLESS credential."""

    def test_created_under_a_restrictive_umask(self):
        idx = BODY.index('cat > "$CONFIG_DIR/probe-client.json"')
        window = BODY[idx - 400:idx + 60]
        self.assertIn("umask 077", window,
                      "probe-client.json is created at the ambient umask inside /etc/xray "
                      "(0755), disclosing a working client credential until the chmod lands")

    def test_chmod_is_retained(self):
        self.assertRegex(BODY, r'chmod 600 "\$CONFIG_DIR/probe-client\.json"',
                         "the explicit chmod was removed; it is the belt-and-braces guard "
                         "for a file created before the umask takes effect")



# ── Behavioural coverage ─────────────────────────────────────────────────────
# The assertions above match template text. That is too weak on its own for these
# two: a fixed-width character window around the probe heredoc bleeds into the
# adjacent UUID block, so deleting the umask that guards probe-client.json leaves
# the window still containing one (verified: the guarding umask sits 20 chars
# before the heredoc, the neighbouring one 402 — the window is 400 wide). And an
# assertNotIn on a single literal /tmp path says nothing about any other fixed
# name. So run the emitted fragments and look at what they create.

def _fragment(start_marker: str, end_pattern: str) -> str:
    """Slice a runcmd fragment out of the template, rendered as Terraform renders it."""
    body = BODY.replace("$${", "${").replace("%%{", "%{")
    # Snap to the start of the line: slicing mid-line makes the first line's indent
    # zero, which defeats the dedent below and leaves an unquoted heredoc terminator
    # indented — bash then reads to end of file.
    s = body.rindex("\n", 0, body.index(start_marker)) + 1
    m = re.search(end_pattern, body[s:], re.M)
    if m is None:
        raise AssertionError(f"no end match for {end_pattern!r}")
    block = body[s: s + m.end()]
    lines = block.splitlines()
    indent = min(len(l) - len(l.lstrip()) for l in lines if l.strip())
    return "\n".join(l[indent:] for l in lines)


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode) if path.exists() else None


class Vuln048ProbeClientBehaviourTest(unittest.TestCase):
    """probe-client.json must be 0600 the moment it exists, not after a chmod."""

    def run_probe_branch(self):
        tmp = Path(tempfile.mkdtemp())
        # The fragment ends at the heredoc terminator, before any chmod — so what is
        # measured is the mode at creation, which is the whole point of the finding.
        frag = _fragment('if [[ "$USERNAME" == "probe" ]]; then',
                         r"^\s*PROBEJSON\s*$")
        script = (
            "umask 022\n"                       # a deliberately permissive ambient umask
            f'CONFIG_DIR="{tmp}"\n'
            'USERNAME=probe\n'
            'USER_UUID=11111111-2222-3333-4444-555555555555\n'
            'SERVER_IP=203.0.113.10\n'
            'REALITY_PORT=443\n'
            'SNI=www.example.com\n'
            'PUBLIC_KEY=cHVibGljLWtleS1wbGFjZWhvbGRlci1mb3ItdGVzdHM=\n'
            'SHORT_ID=0123456789abcdef\n'
            + frag + "\nfi\n")
        p = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                           timeout=30, stdin=subprocess.DEVNULL)
        p.out = tmp / "probe-client.json"
        return p

    def test_the_branch_actually_writes_the_file(self):
        """Anchor: without this the mode assertion below is vacuous."""
        p = self.run_probe_branch()
        self.assertTrue(p.out.exists(),
                        f"probe-client.json was not written (rc={p.returncode}, "
                        f"stderr={p.stderr[-300:]})")
        self.assertIn("reality-out", p.out.read_text(),
                      "the rendered file is not the probe client config")

    def test_it_is_created_private(self):
        p = self.run_probe_branch()
        self.assertIsNotNone(_mode(p.out), f"nothing was created: {p.stderr[-300:]}")
        self.assertEqual(
            _mode(p.out) & 0o077, 0,
            f"probe-client.json is created {oct(_mode(p.out))} under a 022 umask. "
            f"/etc/xray is 0755 and this file holds a working client credential, so "
            f"it is disclosed for the window before the chmod lands")


class Vuln028KeypairTempFileBehaviourTest(unittest.TestCase):
    """The Reality private key must not pass through a predictable path."""

    def run_keypair_branch(self):
        tmp = Path(tempfile.mkdtemp())
        binp = tmp / "bin"
        binp.mkdir()
        modelog = tmp / "stdout_mode"

        # The fragment calls xray by absolute path, so PATH cannot stub it; rewriting
        # that one path is the only change made to the production text. The stub
        # records the mode of the file it is writing into — i.e. the mode of the
        # temporary file at the moment the private key lands in it.
        (binp / "xray").write_text(
            f'#!/usr/bin/env bash\n'
            f'{{ stat -c %a /dev/fd/1 2>/dev/null || stat -f %Lp /dev/fd/1; }} > "{modelog}"\n'
            f'printf "PrivateKey: %s\\nPublicKey: %s\\n" '
            f'"cHJpdmF0ZS1rZXktZm9yLXRlc3RzLW9ubHktbm90LXJlYWw=" '
            f'"cHVibGljLWtleS1mb3ItdGVzdHMtb25seS1ub3QtcmVhbHg="\n')
        (binp / "xray").chmod(0o755)

        frag = _fragment('if [[ ! -f "$KEYPAIR_FILE" ]]; then',
                         r'^\s*echo "Generated new Reality keypair\."\s*$')
        frag = frag.replace("/usr/local/bin/xray", str(binp / "xray"))

        script = ("umask 022\n"
                  f'KEYPAIR_FILE="{tmp}/keypair.env"\n'
                  + frag + "\nfi\n"
                  'printf "XKEY=%s\\n" "$XKEY_TMP"\n')
        p = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                           timeout=30, stdin=subprocess.DEVNULL)
        p.keypair = tmp / "keypair.env"
        p.xkey = next((l[len("XKEY="):] for l in p.stdout.splitlines()
                       if l.startswith("XKEY=")), None)
        p.staging_mode = modelog.read_text().strip() if modelog.exists() else None
        return p

    def test_the_branch_actually_generates_a_keypair(self):
        """Anchor: without this every assertion below is vacuous."""
        p = self.run_keypair_branch()
        self.assertTrue(p.keypair.exists(),
                        f"no keypair was generated (rc={p.returncode}, "
                        f"stderr={p.stderr[-300:]})")
        self.assertIn("PRIVATE_KEY=", p.keypair.read_text())

    def test_the_staging_path_is_not_predictable(self):
        """The filed vector: a fixed name is both readable and a symlink target."""
        first = self.run_keypair_branch()
        second = self.run_keypair_branch()
        self.assertTrue(first.xkey, f"no staging path was captured: {first.stderr[-300:]}")
        self.assertNotEqual(
            first.xkey, second.xkey,
            f"the Reality private key is staged at the same path on every run "
            f"({first.xkey}), so a local account can pre-create it as a symlink")

    def test_the_staging_file_is_private_when_the_key_lands_in_it(self):
        p = self.run_keypair_branch()
        self.assertIsNotNone(
            p.staging_mode,
            f"the staging mode was not observed, so this test proves nothing "
            f"(rc={p.returncode}, stderr={p.stderr[-300:]})")
        self.assertEqual(
            int(p.staging_mode, 8) & 0o077, 0,
            f"the Reality private key is written into a mode-{p.staging_mode} file "
            f"under a 022 umask, readable by any local account until it is unlinked")

    def test_the_keypair_file_is_private(self):
        p = self.run_keypair_branch()
        self.assertEqual(_mode(p.keypair) & 0o077, 0,
                         f"keypair.env is {oct(_mode(p.keypair))}")

if __name__ == "__main__":
    unittest.main()
