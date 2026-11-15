"""The Ubuntu baseline the node's first boot applies (os-baseline.sh in cloud-init).

Ubuntu 26.04 breaks the boot three ways without it: apt refuses the coreutils swap
(an essential package), plain `upgrade` holds a new kernel back, and nothing reboots
into an installed kernel fix. These run the real library, extracted from
cloud-init.yaml.tpl, under `sh` with apt, dpkg and ls stubbed.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TPL = REPO_ROOT / "cloud-init.yaml.tpl"
LIB_PATH = "/usr/local/lib/viaduct/os-baseline.sh"


def library() -> str:
    """The rendered body of the os-baseline.sh write_files entry."""
    body = TPL.read_text().replace("$${", "${").replace("%%{", "%{")
    entry = body.index(f"- path: {LIB_PATH}\n")
    marker = body.index("content: |\n", entry) + len("content: |\n")
    lines = body[marker:].splitlines()
    indent = len(lines[0]) - len(lines[0].lstrip())
    out = []
    for line in lines:
        if line.strip() and (len(line) - len(line.lstrip())) < indent:
            break
        out.append(line[indent:])
    return "\n".join(out).rstrip() + "\n"


class Harness(unittest.TestCase):
    def run_lib(self, call, gnu_installed=False, ls_says="ls (GNU coreutils) 9.7", apt_fails=False):
        """Source the library (system paths redirected into a temp dir) and run `call`."""
        tmp = Path(tempfile.mkdtemp())
        binp = tmp / "bin"
        binp.mkdir()
        calls = tmp / "calls.log"
        (binp / "apt-get").write_text(
            f'#!/bin/sh\necho "apt-get $*" >> "{calls}"\n{"exit 1" if apt_fails else "exit 0"}\n')
        (binp / "dpkg-query").write_text(
            "#!/bin/sh\n" + ("printf 'install ok installed'\n" if gnu_installed else "exit 1\n"))
        (binp / "ls").write_text(f'#!/bin/sh\necho "{ls_says}"\n')
        for f in binp.iterdir():
            f.chmod(0o755)
        etc = tmp / "etc"
        (etc / "apt" / "apt.conf.d").mkdir(parents=True)
        script = tmp / "run.sh"
        script.write_text(library().replace("/etc/", f"{etc}/") + "\n" + call + "\n")
        p = subprocess.run(["sh", str(script)], capture_output=True, text=True, timeout=60,
                           stdin=subprocess.DEVNULL,
                           env=dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}"))
        p.calls = calls.read_text().splitlines() if calls.exists() else []
        p.etc = etc
        return p


class GnuCoreutilsTest(Harness):
    def test_the_swap_names_the_removal_and_allows_it(self):
        """apt refuses to drop the essential uutils variant implicitly."""
        p = self.run_lib("osb_gnu_coreutils")
        self.assertEqual(p.returncode, 0, p.stderr)
        swap = [c for c in p.calls if "coreutils-from-gnu" in c]
        self.assertTrue(swap, f"no swap was attempted: {p.calls}")
        self.assertIn("--allow-remove-essential", swap[0])
        self.assertIn("coreutils-from-uutils-", swap[0])

    def test_an_installed_swap_is_not_repeated(self):
        p = self.run_lib("osb_gnu_coreutils", gnu_installed=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse([c for c in p.calls if "install" in c], p.calls)

    def test_a_swap_that_did_not_take_fails_the_boot(self):
        p = self.run_lib("osb_gnu_coreutils", ls_says="ls (uutils coreutils) 0.10.0")
        self.assertNotEqual(p.returncode, 0, "uutils still active, yet the baseline reported success")
        self.assertIn("FATAL", p.stderr)

    def test_a_failed_install_fails_the_boot(self):
        p = self.run_lib("osb_gnu_coreutils", apt_fails=True, ls_says="ls (uutils coreutils) 0.10.0")
        self.assertNotEqual(p.returncode, 0)


class UpgradeAndRebootTest(Harness):
    def test_the_upgrade_installs_new_kernel_packages(self):
        """Plain `upgrade` holds linux-image-<version> back; the kernel stays vulnerable."""
        p = self.run_lib("osb_security_upgrade")
        self.assertTrue(any("upgrade --with-new-pkgs" in c for c in p.calls), p.calls)

    def test_apt_waits_for_the_dpkg_lock(self):
        p = self.run_lib("osb_security_upgrade")
        self.assertTrue(all("DPkg::Lock::Timeout=" in c for c in p.calls if c.startswith("apt-get")), p.calls)

    def test_reboot_policy_reboots_into_kernel_fixes(self):
        p = self.run_lib("osb_auto_reboot")
        conf = (p.etc / "apt" / "apt.conf.d" / "52viaduct-auto-reboot").read_text()
        self.assertIn('Unattended-Upgrade::Automatic-Reboot "true";', conf)
        self.assertIn('Unattended-Upgrade::Automatic-Reboot-Time "03:30";', conf)

    def test_the_baseline_runs_in_order_and_stops_on_failure(self):
        p = self.run_lib("osb_baseline")
        self.assertEqual(p.returncode, 0, p.stderr)
        order = [next(i for i, c in enumerate(p.calls) if needle in c)
                 for needle in ("apt-get -o DPkg::Lock::Timeout=600 -y -q update", "coreutils-from-gnu", "--with-new-pkgs")]
        self.assertEqual(order, sorted(order), f"update, swap, upgrade out of order: {p.calls}")
        failed = self.run_lib("osb_baseline", ls_says="ls (uutils coreutils) 0.10.0")
        self.assertNotEqual(failed.returncode, 0)
        self.assertFalse(any("--with-new-pkgs" in c for c in failed.calls),
                         "the upgrade ran although GNU coreutils were not active")


class BootWiringTest(unittest.TestCase):
    def test_the_library_is_posix_sh(self):
        """cloud-init runs runcmd under dash."""
        body = library()
        tmp = Path(tempfile.mkdtemp()) / "lib.sh"
        tmp.write_text(body)
        self.assertEqual(subprocess.run(["sh", "-n", str(tmp)]).returncode, 0)
        for bashism in (r"\[\[", r"^\s*function\s", r"\$'", r"\bdeclare\b", r"\blocal\s+-[an]"):
            with self.subTest(bashism=bashism):
                self.assertNotRegex(body, re.compile(bashism, re.M))

    def test_the_baseline_runs_first_and_a_failure_stops_the_boot(self):
        """cloud-init's runcmd carries on past a failing command unless it exits."""
        body = TPL.read_text()
        runcmd = body[body.index("\nruncmd:\n"):]
        first = next(l for l in runcmd.splitlines()[2:] if l.strip().startswith("- "))
        self.assertEqual(first.strip(), "- . /usr/local/lib/viaduct/os-baseline.sh && osb_baseline || exit 1")

    def test_cloud_init_does_not_upgrade_before_the_swap(self):
        """package_upgrade would run apt upgrade under uutils, before the baseline."""
        self.assertNotRegex(TPL.read_text(), r"(?m)^package_upgrade:\s*true")


if __name__ == "__main__":
    unittest.main()
