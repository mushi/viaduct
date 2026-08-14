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


def call_guard(
    known_hosts: Path,
    env_extra: dict,
    server_id: str | None = None,
    serverid_file: Path | None = None,
) -> subprocess.CompletedProcess:
    """Source the production helper and invoke the host-key-pin guard.

    With server_id/serverid_file supplied, exercises the auto-detect path; without
    them, the original two-argument call (an apply with no id available).
    """
    args = f'"{SERVER_IP}" "{known_hosts}"'
    if server_id is not None or serverid_file is not None:
        args += f' "{server_id or ""}" "{serverid_file or ""}"'
    script = (
        f'set -euo pipefail\n'
        f'. "{GUARDS}"\n'
        f'vh_reset_host_key_pin_if_requested {args}\n'
    )
    env = dict(os.environ)
    env.pop("VIADUCT_HOST_KEY_RESET", None)
    env.update(env_extra)
    return subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=env
    )


def call_rebuilt(server_id: str, serverid_file: Path | None) -> subprocess.CompletedProcess:
    """Invoke the rebuild predicate; returncode 0 means 'rebuilt'."""
    script = (
        f'set -uo pipefail\n'
        f'. "{GUARDS}"\n'
        f'vh_server_was_rebuilt "{server_id}" "{serverid_file or ""}"\n'
    )
    return subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=dict(os.environ)
    )


def call_record(server_id: str, serverid_file: Path) -> subprocess.CompletedProcess:
    """Invoke the production recorder helper."""
    script = (
        f'set -euo pipefail\n'
        f'. "{GUARDS}"\n'
        f'vh_record_server_id "{server_id}" "{serverid_file}"\n'
    )
    return subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=dict(os.environ)
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

    def test_changed_server_id_auto_clears_the_pin(self):
        """A genuine rebuild (new hcloud id) clears the stale pin without the flag."""
        with tempfile.TemporaryDirectory() as tmp:
            kh = seeded_known_hosts(tmp)
            sid = Path(tmp) / "known_hosts.serverid"
            sid.write_text("hcloud-server-1111\n")  # the pin belongs to the old box
            proc = call_guard(kh, {}, server_id="hcloud-server-2222", serverid_file=sid)
            self.assertEqual(proc.returncode, 0, f"guard failed: {proc.stderr}")
            self.assertNotIn(
                SERVER_IP,
                kh.read_text(),
                "a changed hcloud server id means the box was recreated (new host "
                "keys); the stale pin must be cleared so the new key can be accepted",
            )

    def test_unchanged_server_id_keeps_the_pin(self):
        """An ordinary apply (same hcloud id) must NOT clear the pin."""
        with tempfile.TemporaryDirectory() as tmp:
            kh = seeded_known_hosts(tmp)
            sid = Path(tmp) / "known_hosts.serverid"
            sid.write_text("hcloud-server-1111\n")
            proc = call_guard(kh, {}, server_id="hcloud-server-1111", serverid_file=sid)
            self.assertEqual(proc.returncode, 0, f"guard failed: {proc.stderr}")
            self.assertIn(
                SERVER_IP,
                kh.read_text(),
                "same server id = same box; a key change here has no legitimate cause "
                "(the on-path-attacker case) and must fail closed, not be auto-trusted",
            )

    def test_no_recorded_id_keeps_the_pin(self):
        """First run after adoption (no id recorded yet) must not auto-clear."""
        with tempfile.TemporaryDirectory() as tmp:
            kh = seeded_known_hosts(tmp)
            sid = Path(tmp) / "known_hosts.serverid"  # absent
            proc = call_guard(kh, {}, server_id="hcloud-server-2222", serverid_file=sid)
            self.assertEqual(proc.returncode, 0, f"guard failed: {proc.stderr}")
            self.assertIn(
                SERVER_IP,
                kh.read_text(),
                "with no recorded id there is no evidence of a rebuild; keep the pin "
                "(fail closed) and let the operator use the explicit flag if needed",
            )

    def test_empty_server_id_keeps_the_pin(self):
        """SERVER_ID unavailable (empty) must be a no-op, never a reset."""
        with tempfile.TemporaryDirectory() as tmp:
            kh = seeded_known_hosts(tmp)
            sid = Path(tmp) / "known_hosts.serverid"
            sid.write_text("hcloud-server-1111\n")
            proc = call_guard(kh, {}, server_id="", serverid_file=sid)
            self.assertEqual(proc.returncode, 0, f"guard failed: {proc.stderr}")
            self.assertIn(SERVER_IP, kh.read_text())

    def test_record_server_id_persists_the_id(self):
        """The recorder writes the current id so the next run can compare."""
        with tempfile.TemporaryDirectory() as tmp:
            sid = Path(tmp) / "known_hosts.serverid"
            proc = call_record("hcloud-server-3333", sid)
            self.assertEqual(proc.returncode, 0, f"recorder failed: {proc.stderr}")
            self.assertEqual(sid.read_text().strip(), "hcloud-server-3333")

    def test_rebuilt_predicate_true_only_when_id_changed(self):
        """vh_server_was_rebuilt drives both the pin clear and the WG rotation."""
        with tempfile.TemporaryDirectory() as tmp:
            sid = Path(tmp) / "known_hosts.serverid"
            sid.write_text("id-1\n")
            self.assertEqual(call_rebuilt("id-2", sid).returncode, 0, "changed id must read as rebuilt")
            self.assertNotEqual(call_rebuilt("id-1", sid).returncode, 0, "same id must not read as rebuilt")
            self.assertNotEqual(call_rebuilt("", sid).returncode, 0, "empty id must not read as rebuilt")
            missing = Path(tmp) / "absent.serverid"
            self.assertNotEqual(call_rebuilt("id-2", missing).returncode, 0, "no record must not read as rebuilt")

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
