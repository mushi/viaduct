"""Vault had no audit device of any kind.

Not a scan finding — it surfaced while assessing VULN-006/007, where the question
"what happens if this residual is exercised?" turned out to have the answer
"nothing is recorded, anywhere". Prevention was declined for that finding on
deliberate design grounds (see docs/ACCEPTED-RISKS.md); visibility was not.

The awkward property of Vault audit devices is that they are an availability
dependency: Vault fails a request when EVERY enabled device fails to write. A lone
file device therefore converts a full /var/log into a Vault outage. Two devices
(file + syslog) degrade instead — syslog still succeeds, the request proceeds, and
the file device's failure is the thing to alert on.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = REPO_ROOT / "gcp" / "scripts" / "bootstrap-vault.sh"
STARTUP = REPO_ROOT / "gcp" / "scripts" / "startup.sh"
ACCEPTED = REPO_ROOT / "docs" / "ACCEPTED-RISKS.md"


def uncommented(path: Path) -> str:
    return "\n".join(l for l in path.read_text().splitlines()
                     if not l.lstrip().startswith("#"))


class AuditDeviceTest(unittest.TestCase):
    def setUp(self):
        self.body = uncommented(BOOTSTRAP)

    def test_an_audit_device_is_enabled(self):
        self.assertRegex(
            self.body, r"vault audit enable file file_path=/var/log/vault/audit\.log",
            "Vault records nothing: no file audit device is enabled")

    def test_a_second_device_backs_it(self):
        """One device makes a full disk a Vault outage."""
        self.assertRegex(
            self.body, r"vault audit enable syslog",
            "only one audit device is enabled, so a write failure on it stops Vault "
            "serving requests entirely")

    def test_both_are_idempotent(self):
        """bootstrap-vault.sh is re-runnable; a second enable would error."""
        for dev in ("file/", "syslog/"):
            with self.subTest(device=dev):
                self.assertIn(f'has audit "{dev}"', self.body,
                              f"the {dev} device is enabled unguarded, so a re-run fails")

    def test_auditing_starts_before_anything_else_is_configured(self):
        """Otherwise the root-token operations that set Vault up are off the record."""
        first_audit = self.body.index("vault audit enable")
        for later in ("vault secrets enable", "vault auth enable", "vault policy write"):
            with self.subTest(operation=later):
                self.assertLess(
                    first_audit, self.body.index(later),
                    f"{later!r} runs before auditing is on, so it is never recorded")

    def test_the_root_token_revoke_is_on_the_record(self):
        """Anchor: the most sensitive act in the script must be audited."""
        self.assertLess(self.body.index("vault audit enable"),
                        self.body.index("vault token revoke -self"))


class AuditLogDestinationTest(unittest.TestCase):
    def setUp(self):
        self.body = uncommented(STARTUP)

    def test_the_directory_is_created_for_the_vault_user(self):
        self.assertRegex(
            self.body, r"install -d -o vault -g vault -m 0700 /var/log/vault",
            "the file device's target directory is never created, so Vault would "
            "fail every request once the audit device is enabled")

    def test_it_is_not_world_readable(self):
        """Audit records carry request paths and token accessors."""
        m = re.search(r"install -d -o vault -g vault -m (\d+) /var/log/vault", self.body)
        self.assertIsNotNone(m)
        self.assertEqual(int(m.group(1), 8) & 0o077, 0,
                         f"/var/log/vault is mode {m.group(1)}")

    def test_rotation_exists(self):
        self.assertIn("/etc/logrotate.d/vault-audit", self.body,
                      "nothing rotates the audit log, so it grows until the disk fills "
                      "— which is the condition that makes Vault refuse requests")

    def test_rotation_does_not_truncate_under_the_writer(self):
        """copytruncate races the audit writer and loses records."""
        rot = self.body[self.body.index("/etc/logrotate.d/vault-audit"):]
        rot = rot[: rot.index("ROTATE", rot.index("ROTATE") + 1)]
        self.assertNotIn("copytruncate", rot,
                         "copytruncate can drop audit records mid-write")
        self.assertIn("SIGHUP", rot,
                      "Vault is never told to reopen the file after rotation, so it "
                      "keeps writing to the rotated inode")


class AcceptedRiskRecordTest(unittest.TestCase):
    """The acceptance is conditional; the condition has to survive in the repo."""

    def setUp(self):
        self.text = ACCEPTED.read_text()

    def test_the_findings_are_named(self):
        for vid in ("VULN-006", "VULN-007"):
            self.assertIn(vid, self.text, f"{vid} is not recorded as accepted")

    def test_the_invalidating_condition_is_recorded(self):
        """Without this the acceptance reads as 'this is fine', which it is not."""
        self.assertRegex(
            self.text, r"(?i)what would invalidate",
            "the record does not state what would make the acceptance unsafe")
        self.assertRegex(
            self.text, r"(?i)constrained interactive account",
            "the precondition — that no constrained principal exists on the hub — "
            "is the whole basis of the acceptance and is not written down")


if __name__ == "__main__":
    unittest.main()
