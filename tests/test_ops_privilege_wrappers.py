"""Security tests: VULN-029 and VULN-030 — the ops sudoers wildcards.

CWE-269. The ops account is meant to be inspect-only, but its sudoers entry granted
`/usr/bin/wg show *` and `/usr/bin/journalctl *`. A sudo wildcard matches the entire
remaining argument string, so those two entries also granted:

  * `sudo wg show wg0 private-key`      → the WireGuard private key for the mesh
  * `sudo journalctl --vacuum-time=1s`  → deletion of the audit record

No narrowing of the patterns removes either capability — `wg show *` cannot be
written to exclude one trailing word. Per the operator's decision the fix is a pair
of root-owned wrappers that take fixed arguments, with sudo granted only on those.

The wrappers are extracted from cloud-init.yaml.tpl and executed against stubbed
`journalctl`/`wg`, so what is asserted is the command actually issued — not the
presence of a validation line.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TPL = REPO_ROOT / "cloud-init.yaml.tpl"


def render(body: str) -> str:
    """Undo Terraform template escaping, as templatefile() does at apply time."""
    return body.replace("$${", "${").replace("%%{", "%{")


def write_file_content(path: str) -> str:
    """The rendered body of the write_files entry for `path`."""
    body = render(TPL.read_text())
    entry = body.index(f"- path: {path}\n")
    marker = body.index("content: |\n", entry) + len("content: |\n")
    tail = body[marker:]

    lines = tail.splitlines()
    indent = len(lines[0]) - len(lines[0].lstrip())
    out = []
    for line in lines:
        if line.strip() and (len(line) - len(line.lstrip())) < indent:
            break
        out.append(line[indent:])
    return "\n".join(out).rstrip() + "\n"


class WrapperHarness(unittest.TestCase):
    """Installs a wrapper plus stub journalctl/wg, and records what got invoked."""

    wrapper_path = None

    def run_wrapper(self, *args):
        tmp = tempfile.mkdtemp()
        binp = Path(tmp) / "bin"
        binp.mkdir()
        log = Path(tmp) / "invoked.log"

        for stub in ("journalctl", "wg"):
            (binp / stub).write_text(
                f'#!/usr/bin/env bash\nprintf "{stub} %s\\n" "$*" >> "{log}"\nexit 0\n')

        script = binp / Path(self.wrapper_path).name
        script.write_text(
            write_file_content(self.wrapper_path).replace("/usr/bin/", f"{binp}/"))
        for f in binp.iterdir():
            f.chmod(0o755)

        p = subprocess.run([str(script), *args], capture_output=True, text=True,
                           env=dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}"),
                           timeout=30, stdin=subprocess.DEVNULL)
        p.invoked = log.read_text().splitlines() if log.exists() else []
        return p


class OpsJournalTest(WrapperHarness):
    wrapper_path = "/usr/local/bin/ops-journal"

    def test_an_allowed_unit_is_readable(self):
        """Anchor: without this the rejection assertions below pass vacuously."""
        p = self.run_wrapper("conduit")
        self.assertEqual(p.returncode, 0, f"reading an allowed unit failed: {p.stderr}")
        self.assertTrue(
            any("-u conduit" in c for c in p.invoked),
            f"journalctl was not run against the requested unit: {p.invoked}")

    def test_vacuum_cannot_be_smuggled_in_as_a_second_argument(self):
        """The filed capability: destroying the audit record."""
        p = self.run_wrapper("conduit", "--vacuum-time=1s")
        self.assertNotEqual(p.returncode, 0, "the wrapper accepted --vacuum-time")
        self.assertEqual(
            p.invoked, [],
            f"journalctl was invoked despite the rejection: {p.invoked}")

    def test_vacuum_alone_is_rejected(self):
        p = self.run_wrapper("--vacuum-time=1s")
        self.assertNotEqual(p.returncode, 0, "the wrapper accepted --vacuum-time")
        self.assertEqual(p.invoked, [], f"journalctl was invoked: {p.invoked}")

    def test_an_unlisted_unit_is_rejected(self):
        p = self.run_wrapper("some-other-unit")
        self.assertNotEqual(p.returncode, 0, "an unlisted unit was accepted")
        self.assertEqual(p.invoked, [], f"journalctl was invoked: {p.invoked}")

    def test_the_allowlist_literal_is_passed_not_the_callers_string(self):
        """A partial match must not let extra text ride along into journalctl."""
        p = self.run_wrapper("conduit --vacuum-files")
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(p.invoked, [], f"journalctl was invoked: {p.invoked}")


class OpsWgStatusTest(WrapperHarness):
    wrapper_path = "/usr/local/bin/ops-wg-status"

    def test_status_is_readable(self):
        """Anchor: the wrapper must still do the job ops needs it for."""
        p = self.run_wrapper()
        self.assertEqual(p.returncode, 0, f"wg status failed: {p.stderr}")
        self.assertEqual(
            [c.strip() for c in p.invoked], ["wg show"],
            f"expected a bare `wg show`, which hides the private key; got {p.invoked}")

    def test_the_private_key_subcommand_is_rejected(self):
        """The filed capability: reading the mesh private key."""
        p = self.run_wrapper("wg0", "private-key")
        self.assertNotEqual(p.returncode, 0, "the wrapper accepted `wg0 private-key`")
        self.assertEqual(p.invoked, [], f"wg was invoked despite rejection: {p.invoked}")

    def test_dump_is_rejected(self):
        """`wg show <if> dump` prints the private key as its first field."""
        p = self.run_wrapper("wg0", "dump")
        self.assertNotEqual(p.returncode, 0, "the wrapper accepted `wg0 dump`")
        self.assertEqual(p.invoked, [], f"wg was invoked: {p.invoked}")


class OpsSudoersTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        body = TPL.read_text()
        ops = body.index("- name: ops")
        block = body[ops: body.index("\nwrite_files:", ops)]
        cls.rule = next(l for l in block.splitlines() if l.strip().startswith("sudo:"))

    def test_journalctl_is_not_reachable_directly(self):
        self.assertNotIn(
            "/usr/bin/journalctl", self.rule,
            "ops can still sudo journalctl directly, so --vacuum-* is still reachable")

    def test_wg_is_not_reachable_directly(self):
        self.assertNotIn(
            "/usr/bin/wg", self.rule,
            "ops can still sudo wg directly, so `wg show wg0 private-key` is reachable")

    def test_the_wrappers_are_granted(self):
        """Anchor: the negative assertions above would also pass on an empty rule."""
        for wrapper in ("/usr/local/bin/ops-journal", "/usr/local/bin/ops-wg-status"):
            self.assertIn(wrapper, self.rule, f"{wrapper} is not sudo-able by ops")

    def test_wrappers_are_root_owned_and_not_writable_by_ops(self):
        body = TPL.read_text()
        for wrapper in ("/usr/local/bin/ops-journal", "/usr/local/bin/ops-wg-status"):
            entry = body[body.index(f"- path: {wrapper}\n"):]
            entry = entry[: entry.index("content: |")]
            self.assertIn("owner: root:root", entry, f"{wrapper} is not root-owned")
            self.assertRegex(
                entry, r'permissions: "0755"',
                f"{wrapper} is not 0755; an ops-writable wrapper defeats the whole fix")


if __name__ == "__main__":
    unittest.main()
