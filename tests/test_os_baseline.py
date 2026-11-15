"""The Ubuntu baseline every node's boot applies, defined once in scripts/lib/os-baseline.sh.

Ubuntu 26.04 broke the boot four ways, each found on a live rebuild: apt refused the
coreutils swap (an essential package), plain `upgrade` held the new kernel back, nothing
rebooted into an installed kernel fix, and the `wg` AppArmor profile blocked WireGuard.
These run the real library under `sh` with apt, dpkg and ls stubbed, and hold all three
boot scripts to using it rather than carrying their own copy.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LIB = REPO_ROOT / "scripts" / "lib" / "os-baseline.sh"
BOOT_SCRIPTS = {
    "gcp": REPO_ROOT / "gcp" / "scripts" / "startup.sh",
    "aws": REPO_ROOT / "aws" / "scripts" / "startup.sh.tpl",
    "hetzner": REPO_ROOT / "cloud-init.yaml.tpl",
}


class Harness(unittest.TestCase):
    def run_lib(self, call, gnu_installed=False, ls_says="ls (GNU coreutils) 9.7", apt_fails=False):
        """Source the library (system paths redirected into a temp dir) and run `call`."""
        tmp = Path(tempfile.mkdtemp())
        binp = tmp / "bin"; binp.mkdir()
        calls = tmp / "calls.log"
        (binp / "apt-get").write_text(
            f'#!/bin/sh\necho "apt-get $*" >> "{calls}"\n{"exit 1" if apt_fails else "exit 0"}\n')
        (binp / "dpkg-query").write_text(
            "#!/bin/sh\n" + ("printf 'install ok installed'\n" if gnu_installed else "exit 1\n"))
        (binp / "ls").write_text(f'#!/bin/sh\necho "{ls_says}"\n')
        (binp / "apparmor_parser").write_text(f'#!/bin/sh\necho "apparmor_parser $*" >> "{calls}"\n')
        for f in binp.iterdir():
            f.chmod(0o755)
        etc = tmp / "etc"
        (etc / "apt" / "apt.conf.d").mkdir(parents=True)
        (etc / "apparmor.d").mkdir(parents=True)
        (etc / "apparmor.d" / "wg").write_text("profile wg {}\n")
        lib = LIB.read_text().replace("/etc/", f"{etc}/")
        script = tmp / "run.sh"
        script.write_text(lib + "\n" + call + "\n")
        p = subprocess.run(["sh", str(script)], capture_output=True, text=True, timeout=60,
                           stdin=subprocess.DEVNULL,
                           env=dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}"))
        p.calls = calls.read_text().splitlines() if calls.exists() else []
        p.etc = etc
        return p


class GnuCoreutilsTest(Harness):
    def test_the_swap_names_the_removal_and_allows_it(self):
        """apt refuses to drop the essential uutils variant implicitly (seen on GCP)."""
        p = self.run_lib("osb_gnu_coreutils")
        self.assertEqual(p.returncode, 0, p.stderr)
        swap = [c for c in p.calls if "coreutils-from-gnu" in c]
        self.assertTrue(swap, f"no swap was attempted: {p.calls}")
        self.assertIn("--allow-remove-essential", swap[0])
        self.assertIn("coreutils-from-uutils-", swap[0])

    def test_an_installed_swap_is_not_repeated(self):
        """GCP re-runs its boot script on every boot; the swap must be a no-op the second time."""
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
        """Plain `upgrade` held linux-image-<version> back on AWS; the kernel stayed vulnerable."""
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


class WireGuardAppArmorTest(Harness):
    def test_the_interface_listing_is_always_allowed(self):
        """Without it wg-quick down leaves wg0 up and every restart fails (seen on GCP)."""
        p = self.run_lib("osb_wg_apparmor")
        rules = (p.etc / "apparmor.d" / "local" / "wg").read_text().split("\n")
        self.assertIn("/run/wireguard/ r,", rules)
        self.assertTrue(any(c.startswith("apparmor_parser -r") for c in p.calls), p.calls)

    def test_extra_key_paths_are_read_only(self):
        p = self.run_lib('osb_wg_apparmor "/run/wireguard/wg0.key"')
        rules = (p.etc / "apparmor.d" / "local" / "wg").read_text().split("\n")
        self.assertIn("/run/wireguard/wg0.key r,", rules)
        self.assertFalse([r for r in rules if r.endswith("w,") or " rw" in r], rules)


class SingleSourceTest(unittest.TestCase):
    """Every boot uses the library; none keeps its own copy of what it does."""

    def test_the_library_is_posix_sh(self):
        """cloud-init runs runcmd under dash."""
        body = LIB.read_text()
        self.assertEqual(subprocess.run(["sh", "-n", str(LIB)]).returncode, 0)
        for bashism in (r"\[\[", r"^\s*function\s", r"\$'", r"\bdeclare\b", r"\blocal\s+-[an]"):
            with self.subTest(bashism=bashism):
                self.assertNotRegex(body, re.compile(bashism, re.M))

    def test_every_boot_applies_the_baseline(self):
        for node, path in BOOT_SCRIPTS.items():
            with self.subTest(node=node):
                body = path.read_text()
                self.assertIn("os-baseline.sh", body, f"{node} does not load the shared baseline")
                self.assertRegex(body, r"osb_baseline", f"{node} does not apply the baseline")
                self.assertRegex(body, r"osb_wg_apparmor", f"{node} does not allow wg past AppArmor")

    def test_no_boot_keeps_its_own_copy(self):
        for node, path in BOOT_SCRIPTS.items():
            body = path.read_text()
            for marker in ("coreutils-from-uutils-", "52viaduct-auto-reboot", "apparmor_parser", "Automatic-Reboot"):
                with self.subTest(node=node, marker=marker):
                    self.assertNotIn(marker, body, f"{node} re-implements part of os-baseline.sh ({marker})")

    def test_the_library_reaches_every_node(self):
        self.assertIn('os-baseline-lib = file("${path.module}/../scripts/lib/os-baseline.sh")',
                      (REPO_ROOT / "gcp" / "main.tf").read_text())
        self.assertIn('os_baseline_lib = file("${path.module}/../scripts/lib/os-baseline.sh")',
                      (REPO_ROOT / "aws" / "main.tf").read_text())
        self.assertIn('os_baseline_lib       = replace(file("${path.module}/scripts/lib/os-baseline.sh")',
                      (REPO_ROOT / "main.tf").read_text())

    def test_a_failed_baseline_stops_the_hetzner_boot(self):
        """cloud-init's runcmd carries on past a failing command unless it exits."""
        body = BOOT_SCRIPTS["hetzner"].read_text()
        self.assertRegex(body, r"(?m)^\s*- \. /usr/local/lib/viaduct/os-baseline\.sh && osb_baseline \|\| exit 1$")


if __name__ == "__main__":
    unittest.main()
