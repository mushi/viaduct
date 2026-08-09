"""Security test: VULN-001 — HZ_PUB must be allowlisted before it reaches the hub.

CWE-78. scripts/provision.sh reads /etc/wireguard/wg0.pub from the Hetzner node and
interpolates it into a command string that `gcloud compute ssh --command` evaluates
as a shell on the GCP hub, under sudo. The only guard was a non-empty check, so root
on the Hetzner box could execute arbitrary commands as root on the control plane.

Drives the real validators in scripts/lib/provision-guards.sh.
"""

import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GUARDS = REPO_ROOT / "scripts" / "lib" / "provision-guards.sh"
PROVISION = REPO_ROOT / "scripts" / "provision.sh"

# A real WireGuard public key: base64 of 32 bytes.
VALID_KEY = "kOtkkR2VfEHFN0m3ES0BJ0BpKbXPQ8YvvKZ5RRSXSHQ="

# Payloads root on the spoke could place in wg0.pub. Each ends the intended word
# and starts a new command in the string the hub's shell evaluates.
INJECTIONS = [
    "x; touch /tmp/pwned #",
    "x && id",
    "x`id`",
    "x$(id)",
    "x | id",
    "x\nid",
    "x'; id; '",
    '"; id; "',
    "../../etc/passwd",
    "",
]


def run_validator(fn: str, value: str) -> int:
    """Invoke a production validator; return its exit status."""
    script = f'. "{GUARDS}"\n{fn} "$1"\n'
    return subprocess.run(
        ["bash", "-c", script, "_", value], capture_output=True, text=True
    ).returncode


def uncommented(lines):
    """Source lines with comment-only lines dropped.

    The wiring assertions must not be satisfied by a guard that has been
    commented out — that would pass while the vulnerability is live again.
    """
    return "\n".join(l for l in lines if not l.lstrip().startswith("#"))


class WireGuardKeyAllowlistTest(unittest.TestCase):
    def test_accepts_a_genuine_wireguard_key(self):
        self.assertEqual(
            run_validator("vh_is_wg_key", VALID_KEY), 0,
            "a real 32-byte base64 WireGuard key must be accepted, or provisioning breaks",
        )

    def test_rejects_every_injection_payload(self):
        for payload in INJECTIONS:
            with self.subTest(payload=payload):
                self.assertNotEqual(
                    run_validator("vh_is_wg_key", payload), 0,
                    f"validator accepted {payload!r}: this value reaches a string "
                    f"evaluated as a root shell on the GCP hub",
                )

    def test_rejects_a_key_with_trailing_command(self):
        """The common shape: a valid-looking key with a command appended."""
        self.assertNotEqual(
            run_validator("vh_is_wg_key", f"{VALID_KEY}; id"), 0,
            "a well-formed key with an appended command must still be rejected",
        )

    def test_mesh_ip_allowlist(self):
        self.assertEqual(run_validator("vh_is_mesh_ip", "10.99.0.2"), 0)
        for bad in ["10.99.0.2; id", "10.99.0.0", "10.99.0.255", "192.168.1.1", "10.99.0.999"]:
            with self.subTest(bad=bad):
                self.assertNotEqual(run_validator("vh_is_mesh_ip", bad), 0)


class ProvisionWiringTest(unittest.TestCase):
    def test_hz_pub_is_validated_before_the_hub_call(self):
        """The guard must be wired in ahead of the wg-register-peer.sh call."""
        lines = PROVISION.read_text().splitlines()
        try:
            sink = next(
                i for i, l in enumerate(lines)
                if "wg-register-peer.sh" in l and "HZ_PUB" in l
            )
        except StopIteration:
            self.fail("could not locate the wg-register-peer.sh call site for HZ_PUB")

        preceding = uncommented(lines[:sink])
        self.assertIn(
            "vh_require", preceding,
            "HZ_PUB reaches the hub command string without passing a vh_require "
            "allowlist check first",
        )
        self.assertRegex(
            preceding, r"vh_require\s+vh_is_wg_key.*HZ_PUB",
            "HZ_PUB must specifically be validated with vh_is_wg_key before the sink",
        )


if __name__ == "__main__":
    unittest.main()
