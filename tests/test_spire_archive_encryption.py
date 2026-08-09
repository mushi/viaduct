"""Security test: VULN-016 — the SPIRE archive must not reach GCS in the clear.

CWE-522. gcp/scripts/startup.sh tars the SPIRE datastore together with keys.json — the
viaduct.gcp CA private keys — and uploaded it to the snapshot bucket unencrypted. Anyone
who could read that bucket obtained the CA and could mint SVIDs for the entire trust
domain, with no further access required.

These tests extract the real vault-snapshot.sh heredoc and EXECUTE it against stubbed
gcloud/vault/sqlite3, then assert on what actually reached the stubbed uploader. A
source-text check cannot tell whether the encrypt call succeeded, referenced the right
file, or was bypassed by a second upload — so the bytes that reach `gcloud storage cp`
are the assertion target.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
STARTUP = REPO_ROOT / "gcp" / "scripts" / "startup.sh"

PLAINTEXT_MARKER = "SPIRE-CA-PRIVATE-KEY-MATERIAL"
CIPHER_PREFIX = "ENCRYPTED:"


def snapshot_script() -> str:
    text = STARTUP.read_text()
    m = re.search(r"cat > /usr/local/bin/vault-snapshot\.sh <<'SNAP'\n(.*?)^SNAP$", text, re.S | re.M)
    if not m:
        raise AssertionError("could not locate the vault-snapshot.sh heredoc")
    return m.group(1)


def run_snapshot(tmp: str):
    """Execute the real snapshot script with every external command stubbed."""
    tmpp = Path(tmp)
    binp = tmpp / "bin"; binp.mkdir()
    uploads = tmpp / "uploads"; uploads.mkdir()
    log = tmpp / "calls.log"

    # Stand-in SPIRE state; keys.json carries a recognisable marker so we can prove
    # whether the CA material itself ever reaches the uploader in the clear.
    spire = tmpp / "spire"; spire.mkdir()
    (spire / "keys.json").write_text(PLAINTEXT_MARKER)

    (binp / "curl").write_text(
        "#!/usr/bin/env bash\n"
        'case "$*" in\n'
        '  *snapshot-approle-role-id*) echo role-id ;;\n'
        '  *snapshot-bucket*) echo test-bucket ;;\n'
        '  *attributes/region*) echo europe-west2 ;;\n'
        '  *kms-keyring*) echo viaduct-vault ;;\n'
        '  *kms-cryptokey*) echo vault-unseal ;;\n'
        '  *) echo stub ;;\n'
        'esac\n')
    (binp / "vault").write_text("#!/usr/bin/env bash\ntouch /tmp/vault.snap 2>/dev/null; echo tok\n")
    # `sqlite3 <db> ".backup '<path>'"` — create the file the script expects.
    (binp / "sqlite3").write_text(
        "#!/usr/bin/env bash\n"
        "arg=\"$2\"\n"
        "path=\"${arg#*\\'}\"; path=\"${path%\\'*}\"\n"
        "[ -n \"$path\" ] && : > \"$path\"\n"
        "exit 0\n")
    # gcloud: record uploads verbatim; kms encrypt actually transforms the bytes.
    (binp / "gcloud").write_text(f"""#!/usr/bin/env bash
if [ "$1" = "kms" ] && [ "$2" = "encrypt" ]; then
  pt=""; ct=""
  while [ $# -gt 0 ]; do
    case "$1" in --plaintext-file) pt="$2"; shift 2 ;; --ciphertext-file) ct="$2"; shift 2 ;; *) shift ;; esac
  done
  {{ printf '{CIPHER_PREFIX}'; cat "$pt"; }} > "$ct"
  exit 0
fi
if [ "$1" = "storage" ] && [ "$2" = "cp" ]; then
  src="$3"; dst="$4"
  name="${{dst##*/}}"
  cp "$src" "{uploads}/$name" 2>/dev/null || true
  echo "UPLOAD $name" >> "{log}"
  exit 0
fi
exit 0
""")
    for f in binp.iterdir():
        f.chmod(0o755)

    script = snapshot_script()
    script = script.replace("/opt/vault-snapshot/secret-id", str(tmpp / "secret-id"))
    script = script.replace("/opt/spire/data/server/keys.json", str(spire / "keys.json"))
    script = script.replace("/opt/spire/data/server/datastore.sqlite3", str(spire / "datastore.sqlite3"))
    (tmpp / "secret-id").write_text("x")
    (spire / "datastore.sqlite3").write_text("db")

    env = dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}")
    proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=60)
    proc.uploads = {p.name: p.read_text(errors="replace") for p in uploads.iterdir()}
    return proc


class ArchiveEncryptionTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.proc = run_snapshot(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _spire_uploads(self):
        return {n: c for n, c in self.proc.uploads.items() if "spire-data" in n}

    def test_the_snapshot_runs(self):
        self.assertTrue(
            self._spire_uploads(),
            f"no spire archive was uploaded at all — the harness or script failed "
            f"(rc={self.proc.returncode}, stderr={self.proc.stderr[:300]})",
        )

    def test_ca_material_never_reaches_the_bucket_in_the_clear(self):
        """The decisive assertion: no uploaded object contains the raw key material."""
        for name, content in self.proc.uploads.items():
            self.assertNotIn(
                PLAINTEXT_MARKER, content.replace(CIPHER_PREFIX, "", 1) if content.startswith(CIPHER_PREFIX) else content,
                f"object {name!r} carries the SPIRE CA key material unencrypted; bucket "
                f"read alone recovers the viaduct.gcp CA",
            ) if not content.startswith(CIPHER_PREFIX) else None

    def test_uploaded_spire_object_is_ciphertext(self):
        for name, content in self._spire_uploads().items():
            self.assertTrue(
                content.startswith(CIPHER_PREFIX),
                f"object {name!r} was uploaded without passing through gcloud kms encrypt",
            )

    def test_no_plaintext_tarball_is_also_uploaded(self):
        """A second, unencrypted upload would defeat the control silently."""
        for name, content in self.proc.uploads.items():
            if "spire-data" in name and not name.endswith(".enc"):
                self.fail(f"a plaintext spire archive was uploaded as {name!r} alongside the ciphertext")


class RestorePathTest(unittest.TestCase):
    """The restore side must decrypt, and must still accept a pre-change backup."""

    def setUp(self):
        self.text = STARTUP.read_text()

    def test_restore_decrypts_the_current_format(self):
        self.assertIn("gcloud kms decrypt", self.text,
                      "nothing decrypts the archive on restore; a rebuilt node could not recover SPIRE state")

    def test_restore_still_handles_a_pre_change_backup(self):
        self.assertRegex(
            self.text, r'elif gcloud storage ls "gs://\$BUCKET/spire-data\.tar\.gz"',
            "no fallback for an existing unencrypted backup: a rebuild against an older "
            "bucket would silently come up with no SPIRE state",
        )


if __name__ == "__main__":
    unittest.main()
