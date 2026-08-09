"""Security test: VULN-004 — the hub reply must not reach the root-executed remote script.

CWE-78. aws/scripts/wg-mesh-join.sh interpolates HUB_PUB into the REMOTE heredoc,
base64-encodes it, and has the AWS box run `base64 -d | bash` as root. A reply
containing a newline plus `CONF` closes the inner config heredoc and everything
after it becomes root shell commands on the spoke.

Drives the real validator in scripts/lib/provision-guards.sh.
"""

import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GUARDS = REPO_ROOT / "scripts" / "lib" / "provision-guards.sh"
JOIN = REPO_ROOT / "aws" / "scripts" / "wg-mesh-join.sh"

VALID_KEY = "kOtkkR2VfEHFN0m3ES0BJ0BpKbXPQ8YvvKZ5RRSXSHQ="
HEREDOC_BREAKOUT = VALID_KEY + "\nCONF\ntouch /tmp/spoke_pwned\ncat > /dev/null <<CONF"


def accepts(value: str) -> bool:
    script = f'. "{GUARDS}"\nvh_is_wg_key "$1"\n'
    return subprocess.run(
        ["bash", "-c", script, "_", value], capture_output=True, text=True
    ).returncode == 0


class HubReplyToRootShellTest(unittest.TestCase):
    def test_rejects_the_heredoc_breakout(self):
        self.assertFalse(
            accepts(HEREDOC_BREAKOUT),
            "validator accepted a reply that closes the CONF heredoc: everything after "
            "it is executed as root on the AWS spoke via `base64 -d | bash`",
        )

    def test_rejects_any_newline_bearing_reply(self):
        for p in [VALID_KEY + "\nid", "\n" + VALID_KEY, VALID_KEY + "\r\nCONF"]:
            with self.subTest(payload=repr(p)):
                self.assertFalse(accepts(p))

    def test_accepts_a_genuine_reply(self):
        self.assertTrue(accepts(VALID_KEY))


class JoinScriptWiringTest(unittest.TestCase):
    def test_hub_pub_and_psk_validated_before_the_remote_heredoc(self):
        lines = JOIN.read_text().splitlines()
        try:
            sink = next(i for i, l in enumerate(lines) if "PublicKey = ${HUB_PUB}" in l)
        except StopIteration:
            self.fail("could not locate the REMOTE heredoc interpolating HUB_PUB")

        preceding = "\n".join(lines[:sink])
        self.assertRegex(
            preceding, r"vh_require\s+vh_is_wg_key.*HUB_PUB",
            "HUB_PUB reaches the root-executed remote script without an allowlist check",
        )
        self.assertRegex(
            preceding, r"vh_require\s+vh_is_wg_key.*WG_PSK",
            "WG_PSK reaches SSM Parameter Store without an allowlist check",
        )


if __name__ == "__main__":
    unittest.main()
