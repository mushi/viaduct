"""Security tests: VULN-040 and VULN-044 — provisioner staging and retrieval paths.

VULN-040 (CWE-377): upload() staged through /tmp/prov.$$.<basename> on the target. $$ is
the local provisioner's PID and the basename is known, so the path is guessable by any
account on the box; a pre-created file or symlink there receives the uploaded content —
which includes keypair.env and client UUIDs.

VULN-044 (CWE-312): download() wrote $dst.partial at the ambient umask and chmod-ed only
after the rename, leaving retrieved key material briefly world-readable on the operator
workstation.

upload() and download() are the only stager and retriever in provision.sh, so guarding
them covers every transfer.
"""

import os
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PROVISION = REPO_ROOT / "scripts" / "provision.sh"
BODY = PROVISION.read_text()


def uncommented(text: str) -> str:
    """Drop comment lines: a comment explaining the old path must not satisfy or
    violate an assertion about the code."""
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def func_body(name: str) -> str:
    start = BODY.index(f"{name}() {{")
    depth, i = 0, start
    while i < len(BODY):
        if BODY[i] == "{":
            depth += 1
        elif BODY[i] == "}":
            depth -= 1
            if depth == 0:
                return BODY[start:i + 1]
        i += 1
    raise AssertionError(f"unterminated {name}()")


class UploadStagingTest(unittest.TestCase):
    def setUp(self):
        self.up = uncommented(func_body("upload"))

    def test_no_predictable_staging_path(self):
        self.assertNotRegex(
            self.up, r'/tmp/prov\.\$\$\.',
            "upload() still stages through /tmp/prov.$$.<basename>, which any account on "
            "the target can predict and pre-create",
        )

    def test_staging_name_is_chosen_remotely_and_unpredictably(self):
        self.assertIn("mktemp", self.up,
                      "the staging path is not created with mktemp on the target")
        self.assertIn("umask 077", self.up,
                      "the staging file is not created with a restrictive umask")

    def test_staging_failure_is_handled(self):
        """An empty stage path would scp into the wrong place."""
        self.assertRegex(
            self.up, r'\[ -n "\$stage" \]',
            "upload() does not check that the remote mktemp actually produced a path",
        )

    def test_staged_file_is_still_removed(self):
        self.assertRegex(self.up, r'rm -f "\$stage"',
                         "the staged file is no longer cleaned up")


class DownloadModeTest(unittest.TestCase):
    def setUp(self):
        self.dn = uncommented(func_body("download"))

    def test_partial_file_created_under_a_restrictive_umask(self):
        self.assertIn(
            "umask 077", self.dn,
            "download() writes $dst.partial at the ambient umask, so retrieved key "
            "material is world-readable on the operator workstation until the chmod",
        )

    def test_umask_precedes_the_redirect(self):
        u = self.dn.index("umask 077")
        r = self.dn.index("> \"$dst.partial\"")
        self.assertLess(u, r, "the umask is set after the redirect, so it has no effect")

    def test_chmod_is_retained(self):
        self.assertRegex(self.dn, r'chmod 600 "\$dst"',
                         "the explicit chmod was removed")

    def test_the_idiom_actually_yields_0600(self):
        """Behavioural: prove a umask-077 subshell redirect creates a private file."""
        with tempfile.TemporaryDirectory() as tmp:
            p = subprocess.run(
                ["bash", "-c", 'umask 022; ( umask 077; printf secret > f ); '
                               'stat -c %a f 2>/dev/null || stat -f %Lp f'],
                capture_output=True, text=True, cwd=tmp, timeout=30)
            self.assertEqual(p.stdout.strip(), "600",
                             f"the subshell umask idiom did not yield 0600: {p.stdout!r}")



class DownloadPartialModeBehaviourTest(unittest.TestCase):
    """Execute the real download() and stat what it actually creates.

    The textual assertions above are satisfied by any download() containing
    "umask 077" ahead of the redirect — including forms where the umask does not
    scope the redirect, e.g. `( umask 077 ); remote cat "$src" > "$dst.partial"`,
    which leaves the partial world-readable. Only observing the mode rules that out.
    """

    def run_download(self, stub_mv: bool):
        tmp = tempfile.mkdtemp()
        # A deliberately permissive ambient umask: the bug being guarded against is
        # exactly "whatever the operator's shell happens to be set to".
        stubs = 'remote() { printf "%s" "restored-key-material"; }\n'
        if stub_mv:
            # Keep the .partial in place so its mode can be observed.
            stubs += f'mv() {{ echo "mv $*" >> "{tmp}/mv.log"; }}\n'
        script = (f'umask 022\n{stubs}{func_body("download")}\n'
                  f'download /opt/spire/agent/keypair.env "{tmp}/out"\n')
        p = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                           timeout=30, stdin=subprocess.DEVNULL)
        p.tmp = Path(tmp)
        return p

    @staticmethod
    def mode(path: Path):
        return stat.S_IMODE(path.stat().st_mode) if path.exists() else None

    def test_the_partial_is_created_private(self):
        p = self.run_download(stub_mv=True)
        partial = p.tmp / "out.partial"
        self.assertTrue(
            partial.exists(),
            f"nothing was staged, so the mode assertion below is vacuous "
            f"(rc={p.returncode}, stderr={p.stderr[-300:]})")
        self.assertEqual(partial.read_text(), "restored-key-material",
                         "the staged file does not hold what was fetched")
        self.assertEqual(
            self.mode(partial) & 0o077, 0,
            f"the staged partial is {oct(self.mode(partial))} under a 022 umask, so "
            f"retrieved key material is readable by other local accounts on the "
            f"operator workstation for the window before the chmod lands")

    def test_the_delivered_file_is_private(self):
        p = self.run_download(stub_mv=False)
        out = p.tmp / "out"
        self.assertTrue(out.exists(),
                        f"download() delivered nothing (rc={p.returncode}, {p.stderr[-300:]})")
        self.assertEqual(self.mode(out), 0o600,
                         f"the delivered file is {oct(self.mode(out))}, not 0600")
        self.assertFalse((p.tmp / "out.partial").exists(),
                         "the staging file was left behind")

if __name__ == "__main__":
    unittest.main()
