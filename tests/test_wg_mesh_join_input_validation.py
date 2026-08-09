"""Security test: VULN-002 — AWS_PUB must be allowlisted before it reaches the hub.

CWE-78. aws/scripts/wg-mesh-join.sh reads /etc/wireguard/wg0.pub off the AWS node
over SSM and interpolates it into the string `gcloud compute ssh --command` runs as
a root shell on the GCP hub.

The pre-existing `tr -d '[:space:]'` was never a security control: it deletes
literal whitespace but leaves ';', '&', '|', backticks and command substitution
intact, and ${IFS} — which contains no literal whitespace — expands back to a space
in the hub's shell, restoring word separation.

Drives the real validator in scripts/lib/provision-guards.sh.
"""

import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GUARDS = REPO_ROOT / "scripts" / "lib" / "provision-guards.sh"
JOIN = REPO_ROOT / "aws" / "scripts" / "wg-mesh-join.sh"

VALID_KEY = "kOtkkR2VfEHFN0m3ES0BJ0BpKbXPQ8YvvKZ5RRSXSHQ="


def accepts(value: str) -> bool:
    script = f'. "{GUARDS}"\nvh_is_wg_key "$1"\n'
    return subprocess.run(
        ["bash", "-c", script, "_", value], capture_output=True, text=True
    ).returncode == 0


def after_tr(value: str) -> str:
    """What the old sanitizer at :69 would have produced."""
    return subprocess.run(
        ["bash", "-c", 'printf "%s" "$1" | tr -d "[:space:]"', "_", value],
        capture_output=True, text=True,
    ).stdout


class AwsPubAllowlistTest(unittest.TestCase):
    def test_accepts_a_genuine_key(self):
        self.assertTrue(accepts(VALID_KEY))

    def test_rejects_the_ifs_bypass_that_defeats_tr(self):
        """The payload that survives `tr -d '[:space:]'` unchanged."""
        payload = "x;touch${IFS}/tmp/pwned;#"
        self.assertEqual(
            after_tr(payload), payload,
            "precondition: this payload must pass through the old tr sanitizer unchanged",
        )
        self.assertFalse(
            accepts(payload),
            "validator accepted the ${IFS} payload: it reaches a root shell on the hub",
        )

    def test_rejects_metacharacters_that_tr_never_removed(self):
        for p in ["x;id", "x&&id", "x`id`", "x$(id)", "x|id", "x\nid", VALID_KEY + ";id", ""]:
            with self.subTest(payload=p):
                self.assertFalse(accepts(p))


class JoinScriptWiringTest(unittest.TestCase):
    def test_aws_pub_validated_before_the_hub_call(self):
        lines = JOIN.read_text().splitlines()
        try:
            sink = next(
                i for i, l in enumerate(lines)
                if "wg-register-peer.sh" in l and "AWS_PUB" in l
            )
        except StopIteration:
            self.fail("could not locate the wg-register-peer.sh call site for AWS_PUB")

        preceding = "\n".join(lines[:sink])
        self.assertIn(
            "provision-guards.sh", preceding,
            "wg-mesh-join.sh must source the shared guard library",
        )
        self.assertRegex(
            preceding, r"vh_require\s+vh_is_wg_key.*AWS_PUB",
            "AWS_PUB reaches the hub command string without an allowlist check",
        )


if __name__ == "__main__":
    unittest.main()
