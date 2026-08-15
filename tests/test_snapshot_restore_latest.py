"""Regression: the restore path must pick the NEWEST timestamped snapshot.

Snapshots moved from a fixed key (vault.snap) to unique, timestamped keys
(vault-<UTC>.snap) so the create-only instance never has to overwrite — a fixed key
would need storage.objects.delete, which is deliberately withheld, so a fixed-key writer
succeeds once and then fails AccessDenied forever (this broke DR: rebuilds restored stale
state). The restore side must therefore select the newest object, and still fall back to
the legacy fixed key for a bucket written before the change.

This extracts the real pick_latest_snapshot() from startup.sh and executes it against a
stubbed gcloud, rather than grepping the source — the selection logic is the contract.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
STARTUP = REPO_ROOT / "gcp" / "scripts" / "startup.sh"


def pick_latest_fn() -> str:
    text = STARTUP.read_text()
    m = re.search(r"(pick_latest_snapshot\(\)\s*\{.*?\n\})", text, re.S)
    if not m:
        raise AssertionError("could not locate pick_latest_snapshot() in startup.sh")
    return m.group(1)


def run_pick(tmp: str, listing: dict[str, list[str]], glob: str, legacy: str):
    """listing maps an object name/glob to the lines `gcloud storage ls` returns for it."""
    binp = Path(tmp) / "bin"; binp.mkdir()
    # Stub gcloud: match the requested gs:// path (last arg) against the listing keys.
    cases = "\n".join(
        f'  "gs://test-bucket/{k}") printf "%s\\n" {" ".join(repr(v) for v in vs)} ;;'
        for k, vs in listing.items()
    )
    (binp / "gcloud").write_text(
        "#!/usr/bin/env bash\n"
        'for a in "$@"; do last="$a"; done\n'
        'case "$last" in\n'
        f"{cases}\n"
        '  *) exit 1 ;;\n'
        "esac\n")
    (binp / "gcloud").chmod(0o755)

    harness = f'BUCKET=test-bucket\n{pick_latest_fn()}\npick_latest_snapshot {glob!r} {legacy!r}\n'
    env = dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}")
    return subprocess.run(["bash", "-c", harness], capture_output=True, text=True, env=env, timeout=30)


class PickLatestTest(unittest.TestCase):
    def test_picks_the_newest_timestamped_object(self):
        listing = {"vault-*.snap": [
            "gs://test-bucket/vault-20260101T000000Z.snap",
            "gs://test-bucket/vault-20260815T120000Z.snap",   # newest
            "gs://test-bucket/vault-20260430T090000Z.snap",
        ]}
        p = run_pick(self.tmpdir(), listing, "vault-*.snap", "vault.snap")
        self.assertEqual(p.stdout.strip(), "gs://test-bucket/vault-20260815T120000Z.snap",
                         f"did not select the newest snapshot (stderr={p.stderr[:200]})")

    def test_falls_back_to_legacy_fixed_key(self):
        # No timestamped objects exist; the legacy fixed key does.
        listing = {"vault.snap": ["gs://test-bucket/vault.snap"]}
        p = run_pick(self.tmpdir(), listing, "vault-*.snap", "vault.snap")
        self.assertEqual(p.stdout.strip(), "gs://test-bucket/vault.snap",
                         "did not fall back to the legacy fixed key for a pre-change bucket")

    def test_empty_when_no_backup_exists(self):
        p = run_pick(self.tmpdir(), {}, "vault-*.snap", "vault.snap")
        self.assertEqual(p.stdout.strip(), "",
                         "returned a path when the bucket holds no snapshot; the restore "
                         "gate would then try to restore from nothing")

    def tmpdir(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        return d.name


if __name__ == "__main__":
    unittest.main()
