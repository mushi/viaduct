"""Security test: VULN-016 — the SPIRE archive must not reach GCS in the clear.

CWE-522. gcp/scripts/startup.sh tars the SPIRE datastore together with keys.json — the
viaduct.gcp CA private keys — and uploaded it to the snapshot bucket unencrypted. Anyone
who could read that bucket obtained the CA and could mint SVIDs for the entire trust
domain, with no further access required.

The instance already holds cryptoKeyEncrypterDecrypter on the Vault unseal key
(gcp/main.tf:109-113) and reads the keyring/cryptokey from metadata, so encrypting needs
no new IAM. The restore path must decrypt, and must still handle buckets written before
this change or a rebuild would silently come up with no SPIRE state.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
STARTUP = REPO_ROOT / "gcp" / "scripts" / "startup.sh"


def snapshot_script(text: str) -> str:
    m = re.search(r"cat > /usr/local/bin/vault-snapshot\.sh <<'SNAP'\n(.*?)^SNAP$", text, re.S | re.M)
    if not m:
        raise AssertionError("could not locate the vault-snapshot.sh heredoc")
    return m.group(1)


class ArchiveEncryptionTest(unittest.TestCase):
    def setUp(self):
        self.text = STARTUP.read_text()
        self.snap = snapshot_script(self.text)

    def test_archive_is_encrypted_before_upload(self):
        self.assertIn(
            "gcloud kms encrypt", self.snap,
            "the SPIRE archive is uploaded without encryption; keys.json holds the "
            "viaduct.gcp CA private keys and bucket read alone would recover them",
        )

    def test_plaintext_archive_is_not_uploaded(self):
        uploads = re.findall(r'gcloud storage cp "([^"]+)" "gs://\$BUCKET/([^"]+)"', self.snap)
        for src, dst in uploads:
            if "spire-data" in dst:
                self.assertTrue(
                    dst.endswith(".enc"),
                    f"spire archive is uploaded to {dst!r} — the unencrypted tarball still "
                    f"reaches the bucket",
                )

    def test_encryption_precedes_the_upload(self):
        enc = self.snap.index("gcloud kms encrypt")
        up = self.snap.index("spire-data.tar.gz.enc\" \"gs://$BUCKET")
        self.assertLess(enc, up, "the upload happens before encryption")

    def test_restore_decrypts_the_current_format(self):
        self.assertIn(
            "gcloud kms decrypt", self.text,
            "nothing decrypts the archive on restore, so a rebuilt node could not "
            "recover SPIRE state",
        )

    def test_restore_still_handles_a_pre_change_backup(self):
        """A bucket written before this change must remain restorable."""
        self.assertRegex(
            self.text, r'elif gcloud storage ls "gs://\$BUCKET/spire-data\.tar\.gz"',
            "no fallback for an existing unencrypted backup: a rebuild against an older "
            "bucket would silently come up with no SPIRE state",
        )


if __name__ == "__main__":
    unittest.main()
