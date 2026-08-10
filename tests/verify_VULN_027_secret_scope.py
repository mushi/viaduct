"""Security tests: VULN-027 and VULN-045 — secret scope and predictable restore paths.

VULN-027 (CWE-732): a single `chmod 0640` covered both rendered secret files, so the
alloy group held the Cloudflare DNS API token — a token that can create records for the
zone. Alloy has no use for it; only certbot does, as root.

VULN-045 (CWE-377): the GCP startup script used fixed /tmp names for Vault and SPIRE
restore material. Running as root, a predictable name invites a pre-created symlink
redirecting the write, and the decrypted SPIRE archive holds the viaduct.gcp CA keys.

Both sinks are shell, so these read the emitted scripts and additionally exercise the
mode idiom behaviourally.
"""

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FETCH = REPO_ROOT / "scripts" / "fetch-hetzner-secrets.sh"
GCP = REPO_ROOT / "gcp" / "scripts" / "startup.sh"


def uncommented(path: Path) -> str:
    return "\n".join(l for l in path.read_text().splitlines() if not l.lstrip().startswith("#"))


class CloudflareTokenScopeTest(unittest.TestCase):
    def setUp(self):
        self.body = uncommented(FETCH)

    def test_cloudflare_ini_is_not_group_readable(self):
        m = re.search(r'chmod (\d+) "\$RUN/cloudflare\.ini"', self.body)
        self.assertIsNotNone(m, "no explicit mode is set on cloudflare.ini")
        self.assertEqual(
            m.group(1), "0600",
            f"cloudflare.ini is mode {m.group(1)}, so the alloy group holds a DNS API "
            f"token that can create records for the zone",
        )

    def test_the_two_files_are_no_longer_chmod_ed_together(self):
        self.assertNotRegex(
            self.body, r'chmod \d+ "\$RUN/grafana\.env" "\$RUN/cloudflare\.ini"',
            "both secrets still receive the same mode, so narrowing one narrows neither",
        )

    def test_grafana_env_keeps_the_alloy_group(self):
        """Alloy must still be able to read its own credentials."""
        m = re.search(r'chmod (\d+) "\$RUN/grafana\.env"', self.body)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "0640",
                         "grafana.env lost its group read, so Alloy cannot read its credentials")


class GcpRestorePathTest(unittest.TestCase):
    def setUp(self):
        self.body = uncommented(GCP)

    def test_no_fixed_vault_snapshot_path(self):
        """Both directions matter: the snapshot is written here and restored here."""
        fixed = re.findall(r"/tmp/vault\.snap(?!\.X)\S*", self.body)
        self.assertEqual(
            fixed, [],
            f"the Vault snapshot still uses a fixed /tmp path {fixed}; the whole "
            f"datastore is written there by root under a name any local account "
            f"can pre-create as a symlink",
        )

    def test_the_snapshot_writer_uses_mktemp(self):
        """Anchor for the above: a snapshot must still be taken and uploaded."""
        writer = self.body[self.body.rindex('VSNAP="'):]
        writer = writer[: writer.index("spdir=")]
        self.assertIn("mktemp", writer,
                      f"the snapshot writer no longer allocates a temp name: {writer!r}")
        self.assertRegex(writer, r'gcloud storage cp "\$VSNAP" "gs://\$BUCKET/vault\.snap"',
                         "the snapshot is no longer uploaded to the bucket")

    def test_no_fixed_spire_archive_path(self):
        for fixed in ("/tmp/spire-data.tar.gz.enc", "/tmp/spire-data.tar.gz"):
            self.assertNotIn(
                f'"{fixed}"', self.body,
                f"the SPIRE archive still uses the fixed path {fixed}, which holds the "
                f"viaduct.gcp CA keys once decrypted",
            )

    def test_restore_paths_use_mktemp(self):
        restore = self.body[self.body.index("Rebuilt instance with a backup present"):]
        restore = restore[:restore.index("spire-agent") if "spire-agent" in restore else len(restore)]
        self.assertGreaterEqual(
            restore.count("mktemp"), 2,
            "the Vault snapshot and SPIRE archive restore paths are not both mktemp-based",
        )

    def test_mktemp_dir_idiom_yields_a_private_directory(self):
        """Behavioural: the decrypted CA archive must land in a directory others cannot enter."""
        with tempfile.TemporaryDirectory() as tmp:
            p = subprocess.run(
                ["bash", "-c", 'd="$(umask 077; mktemp -d)"; '
                               'stat -f %Lp "$d" 2>/dev/null || stat -c %a "$d"; rmdir "$d"'],
                capture_output=True, text=True, cwd=tmp, timeout=30)
            self.assertEqual(p.stdout.strip(), "700",
                             f"umask 077 + mktemp -d did not yield 0700: {p.stdout!r}")


if __name__ == "__main__":
    unittest.main()
