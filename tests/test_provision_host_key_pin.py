"""Security test: VULN-047 — the Hetzner host-key pin must survive an ordinary apply.

CWE-322. scripts/provision.sh deleted the recorded host key on every provisioning
run, so the SSH that follows (StrictHostKeyChecking=accept-new) re-trusted whatever
key answered for SERVER_IP. Removing the pin is only legitimate when the operator
is knowingly rebuilding the box.

These tests drive the real production helper in scripts/lib/provision-guards.sh.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GUARDS = REPO_ROOT / "scripts" / "lib" / "provision-guards.sh"
PROVISION = REPO_ROOT / "scripts" / "provision.sh"

SERVER_IP = "203.0.113.77"


def call_guard(known_hosts: Path, env_extra: dict) -> subprocess.CompletedProcess:
    """Source the production helper and invoke the host-key-pin guard."""
    script = (
        f'set -euo pipefail\n'
        f'. "{GUARDS}"\n'
        f'vh_reset_host_key_pin_if_requested "{SERVER_IP}" "{known_hosts}"\n'
    )
    env = dict(os.environ)
    env.pop("VIADUCT_HOST_KEY_RESET", None)
    env.update(env_extra)
    return subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=env
    )


def seeded_known_hosts(tmp: str) -> Path:
    """A known_hosts carrying a genuine pin from a previous provision."""
    kh = Path(tmp) / "known_hosts"
    kh.write_text(f"{SERVER_IP} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGenuineKeyMaterialHere\n")
    return kh


class HostKeyPinTest(unittest.TestCase):
    def test_pin_survives_an_ordinary_apply(self):
        """No rebuild signalled -> the recorded host key must NOT be removed."""
        with tempfile.TemporaryDirectory() as tmp:
            kh = seeded_known_hosts(tmp)
            proc = call_guard(kh, {})
            self.assertEqual(proc.returncode, 0, f"guard failed: {proc.stderr}")
            self.assertIn(
                SERVER_IP,
                kh.read_text(),
                "host-key pin was deleted on an ordinary apply: the next SSH will "
                "accept-new whatever key answers, so an on-path attacker is trusted "
                "silently instead of being rejected on mismatch",
            )

    def test_explicit_reset_still_clears_the_pin(self):
        """VIADUCT_HOST_KEY_RESET=1 -> the terraform -replace path still works."""
        with tempfile.TemporaryDirectory() as tmp:
            kh = seeded_known_hosts(tmp)
            proc = call_guard(kh, {"VIADUCT_HOST_KEY_RESET": "1"})
            self.assertEqual(proc.returncode, 0, f"guard failed: {proc.stderr}")
            self.assertNotIn(
                SERVER_IP,
                kh.read_text(),
                "explicit reset must still clear the stale pin so a genuine rebuild "
                "can re-pin the new host key",
            )

    def test_provision_does_not_clear_the_pin_unconditionally(self):
        """The guard must actually be wired in: no bare ssh-keygen -R in provision.sh."""
        body = PROVISION.read_text()
        offenders = [
            line.strip()
            for line in body.splitlines()
            if "ssh-keygen -R" in line
            and not line.lstrip().startswith("#")
            and "log " not in line
        ]
        self.assertEqual(
            offenders,
            [],
            "provision.sh still removes the host-key pin directly; the call must go "
            f"through vh_reset_host_key_pin_if_requested. Offending lines: {offenders}",
        )


if __name__ == "__main__":
    unittest.main()
