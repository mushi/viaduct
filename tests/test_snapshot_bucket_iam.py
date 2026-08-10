"""Security test: VULN-017 — the control plane must not be able to delete its own backups.

CWE-732. gcp/main.tf granted the control-plane service account roles/storage.objectAdmin
on the vault-snapshots bucket. That role includes storage.objects.delete, so a
compromised control plane could erase the snapshots the bucket exists to preserve —
defeating the bucket's own prevent_destroy and versioning, which are the recovery
control (docs/RUNBOOK.md's automatic recovery path depends on them).

The snapshot writer only ever creates new objects and reads them back on restore.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MAIN_TF = REPO_ROOT / "gcp" / "main.tf"

# Roles that carry storage.objects.delete.
DELETE_BEARING = {"roles/storage.objectAdmin", "roles/storage.admin", "roles/owner",
                  "roles/editor", "roles/storage.legacyBucketOwner"}


def snapshot_bucket_bindings():
    text = MAIN_TF.read_text()
    blocks = re.findall(
        r'resource "google_storage_bucket_iam_member" "([^"]+)" \{(.*?)\n\}', text, re.S)
    out = []
    for name, body in blocks:
        if "vault_snapshots" not in body and "vault_snapshots" not in name:
            continue
        for role in re.findall(r'role\s*=\s*"([^"]+)"', body):
            out.append((name, role))
    return out


class SnapshotBucketIamTest(unittest.TestCase):
    def setUp(self):
        self.bindings = snapshot_bucket_bindings()
        self.assertTrue(self.bindings, "no IAM binding found for the vault-snapshots bucket")

    def test_no_delete_bearing_role(self):
        for name, role in self.bindings:
            self.assertNotIn(
                role, DELETE_BEARING,
                f'binding {name!r} grants {role!r}, which includes storage.objects.delete: '
                f'a compromised control plane could erase the snapshots that are the '
                f'documented recovery path',
            )

    def test_can_still_write_snapshots(self):
        roles = {r for _, r in self.bindings}
        self.assertTrue(
            roles & {"roles/storage.objectCreator", "roles/storage.objectUser"},
            "nothing grants object creation; vault-snapshot.sh could not upload backups",
        )

    def test_can_still_read_for_restore(self):
        roles = {r for _, r in self.bindings}
        self.assertTrue(
            roles & {"roles/storage.objectViewer", "roles/storage.objectUser"},
            "nothing grants object read; the rebuild restore path could not fetch "
            "vault.snap or the SPIRE archive",
        )


if __name__ == "__main__":
    unittest.main()
