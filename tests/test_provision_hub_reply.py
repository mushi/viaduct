"""Security test: VULN-033 — the hub registration reply must not inject wg0.conf directives.

CWE-78 / CWE-74. scripts/provision.sh awks hub_public_key and psk out of the hub's
reply and interpolates both into an unquoted heredoc that becomes wg0.conf. A reply
carrying a newline turns one config value into extra WireGuard directives — e.g. an
AllowedIPs = 0.0.0.0/0 plus an attacker Endpoint, which routes the node's traffic.

Drives the real validators in scripts/lib/provision-guards.sh.
"""

import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GUARDS = REPO_ROOT / "scripts" / "lib" / "provision-guards.sh"
PROVISION = REPO_ROOT / "scripts" / "provision.sh"

VALID_KEY = "kOtkkR2VfEHFN0m3ES0BJ0BpKbXPQ8YvvKZ5RRSXSHQ="


def validates(value: str) -> bool:
    script = f'. "{GUARDS}"\nvh_is_wg_key "$1"\n'
    return subprocess.run(
        ["bash", "-c", script, "_", value], capture_output=True, text=True
    ).returncode == 0


class HubReplyAllowlistTest(unittest.TestCase):
    def test_rejects_a_key_carrying_extra_directives(self):
        payload = VALID_KEY + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = attacker.example:51820"
        self.assertFalse(
            validates(payload),
            "a hub reply with an embedded newline must be rejected: it becomes extra "
            "wg0.conf directives that can route all traffic to an attacker endpoint",
        )

    def test_rejects_bare_newline_and_carriage_return(self):
        for payload in [VALID_KEY + "\n", "\n" + VALID_KEY, VALID_KEY + "\r\nAllowedIPs = 0.0.0.0/0"]:
            with self.subTest(payload=repr(payload)):
                self.assertFalse(validates(payload))

    def test_accepts_a_genuine_reply(self):
        self.assertTrue(validates(VALID_KEY), "a real hub reply must still be accepted")


class ProvisionWiringTest(unittest.TestCase):
    def test_hub_pub_and_psk_validated_before_the_heredoc(self):
        lines = PROVISION.read_text().splitlines()
        try:
            heredoc = next(i for i, l in enumerate(lines) if "PublicKey = ${HUB_PUB}" in l)
        except StopIteration:
            self.fail("could not locate the wg0.conf heredoc that interpolates HUB_PUB")

        preceding = "\n".join(lines[:heredoc])
        self.assertRegex(
            preceding, r"vh_require\s+vh_is_wg_key.*HUB_PUB",
            "HUB_PUB reaches the wg0.conf heredoc without an allowlist check",
        )
        self.assertRegex(
            preceding, r"vh_require\s+vh_is_wg_key.*WG_PSK",
            "WG_PSK reaches the wg0.conf heredoc without an allowlist check",
        )


if __name__ == "__main__":
    unittest.main()
