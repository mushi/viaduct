"""Security test: VULN-037 — a PSK left in SSM by a hard kill must not survive the next run.

CWE-459. wg-mesh-join.sh stages the mesh preshared key in an SSM SecureString and removes
it with `trap ... EXIT`.

The finding as filed said an EXIT-only trap leaks the PSK on abnormal exit. That premise
does not hold: bash runs the EXIT trap on SIGTERM, SIGINT and SIGHUP alike (verified on
bash 5.3), so every trappable termination already cleans up. Adding `INT TERM HUP` to the
trap would change nothing.

The residual that IS real is SIGKILL — untrappable by definition, so no trap can cover it.
After a hard kill the PSK stays resident until someone notices. The remediation is
therefore not a bigger trap but a reaper: delete any stale parameter before staging a new
one, so residue cannot outlive the next run.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
JOIN = REPO_ROOT / "aws" / "scripts" / "wg-mesh-join.sh"


def staging_region() -> str:
    """The lines from the PSK staging call to the end of the remote write."""
    body = JOIN.read_text()
    start = body.index("put-parameter")
    return body[max(0, start - 1500):start + 200]


def uncommented(text: str) -> str:
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


class PskResidueTest(unittest.TestCase):
    def test_stale_parameter_is_reaped_before_staging(self):
        """SIGKILL cannot be trapped, so residue must be cleared on the next run."""
        region = uncommented(staging_region())
        self.assertIn(
            "delete-parameter", region,
            "nothing removes a pre-existing PSK parameter before staging a new one. "
            "SIGKILL cannot be trapped, so a hard-killed run leaves the mesh preshared "
            "key resident in Parameter Store indefinitely",
        )
        delete_at = region.index("delete-parameter")
        put_at = region.index("put-parameter")
        self.assertLess(
            delete_at, put_at,
            "the stale-parameter delete does not precede the put, so residue from a "
            "previous killed run is not cleared before the new value is staged",
        )

    def test_normal_cleanup_trap_is_retained(self):
        """The EXIT trap must stay — it covers every trappable termination."""
        body = JOIN.read_text()
        self.assertRegex(
            body, r"trap\s+'.*delete-parameter.*'\s+EXIT",
            "the EXIT cleanup trap was removed; the PSK would then persist after every "
            "normal run, which is strictly worse than the filed finding",
        )

    def test_parameter_remains_a_securestring(self):
        body = JOIN.read_text()
        self.assertIn("--type SecureString", body,
                      "the PSK is no longer staged as a SecureString")


if __name__ == "__main__":
    unittest.main()
