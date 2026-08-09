"""Security test: VULN-003 — SECRETS_UID must be numeric before it reaches the hub.

CWE-78. scripts/provision.sh takes `id -u viaduct-secrets` from the Hetzner node and
interpolates it into a `spire-server entry create` command string that runs as root
on the GCP hub. The guard was a non-empty check, so root on the spoke could return
"0 -x; <command> #" and execute it on the control plane.

Drives the real validator in scripts/lib/provision-guards.sh.
"""

import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GUARDS = REPO_ROOT / "scripts" / "lib" / "provision-guards.sh"
PROVISION = REPO_ROOT / "scripts" / "provision.sh"


def accepts(value: str) -> bool:
    script = f'. "{GUARDS}"\nvh_is_uid "$1"\n'
    return subprocess.run(
        ["bash", "-c", script, "_", value], capture_output=True, text=True
    ).returncode == 0


class UidAllowlistTest(unittest.TestCase):
    def test_accepts_a_real_uid(self):
        for uid in ["0", "999", "1000", "4294967294"]:
            with self.subTest(uid=uid):
                self.assertTrue(accepts(uid), f"a genuine uid {uid!r} must be accepted")

    def test_rejects_injection_payloads(self):
        payloads = [
            "0 -x; touch /tmp/pwned #",
            "1000; id",
            "1000 && id",
            "1000`id`",
            "1000$(id)",
            "1000\nid",
            "-1",
            "+1000",
            "1000 ",
            " 1000",
            "",
            "root",
        ]
        for p in payloads:
            with self.subTest(payload=p):
                self.assertFalse(
                    accepts(p),
                    f"validator accepted {p!r}: this value is interpolated into a "
                    f"spire-server command executed as root on the GCP hub",
                )


class ProvisionWiringTest(unittest.TestCase):
    def test_secrets_uid_validated_before_the_spire_call(self):
        lines = PROVISION.read_text().splitlines()
        try:
            sink = next(i for i, l in enumerate(lines) if "unix:uid:${SECRETS_UID}" in l)
        except StopIteration:
            self.fail("could not locate the spire-server entry create call using SECRETS_UID")

        preceding = "\n".join(lines[:sink])
        self.assertRegex(
            preceding, r"vh_require\s+vh_is_uid.*SECRETS_UID",
            "SECRETS_UID reaches the root-executed spire-server command without a "
            "numeric allowlist check",
        )


if __name__ == "__main__":
    unittest.main()
