"""Security test: VULN-013 / VULN-005 / VULN-011 / VULN-014 — the WireGuard peer registry.

The hub's peer scripts are emitted as heredocs by gcp/scripts/startup.sh and run from
/usr/local/bin on the GCP box. gcp/main.tf:243 loads that file with `file()`, not
`templatefile()`, and the script is full of shell ${VAR} references — so the repo-level
scripts/lib/provision-guards.sh cannot be passed through as a template variable. The
validators are therefore emitted once to /usr/local/bin/lib/wg-validate.sh and sourced
by both peer scripts.

These tests extract the emitted library and the emitted reconcile script and execute
them, so they exercise what actually runs on the hub.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
STARTUP = REPO_ROOT / "gcp" / "scripts" / "startup.sh"

VALID_KEY = "kOtkkR2VfEHFN0m3ES0BJ0BpKbXPQ8YvvKZ5RRSXSHQ="
OTHER_KEY = "aB3dEfGhIjKlMnOpQrStUvWxYz0123456789+/ABCc="
HUB_IP = "10.99.0.1"


def heredoc(name: str, delim: str) -> str:
    text = STARTUP.read_text()
    m = re.search(rf"cat > {re.escape(name)} <<'{delim}'\n(.*?)^{delim}$", text, re.S | re.M)
    if not m:
        raise AssertionError(f"could not locate the {name} heredoc")
    return m.group(1)


def wg_validate_lib() -> str:
    return heredoc("/usr/local/bin/lib/wg-validate.sh", "WGVAL")


def call(fn: str, value: str) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        lib = Path(tmp) / "lib.sh"; lib.write_text(wg_validate_lib())
        script = f'. "{lib}"\n{fn} "$1"\n'
        return subprocess.run(["bash", "-c", script, "_", value],
                              capture_output=True, text=True).returncode


class EmittedValidatorTest(unittest.TestCase):
    def test_key_allowlist_accepts_a_real_key(self):
        self.assertEqual(call("vh_is_wg_key", VALID_KEY), 0,
                         "a genuine WireGuard key must be accepted or peer sync breaks")

    def test_key_allowlist_rejects_injection_and_malformed(self):
        for bad in ["x; touch /tmp/pwned #", "x$(id)", VALID_KEY + "; id", "", "notakey",
                    VALID_KEY + "\nAllowedIPs = 0.0.0.0/0"]:
            with self.subTest(bad=bad):
                self.assertNotEqual(call("vh_is_wg_key", bad), 0,
                                    f"validator accepted {bad!r}, which reaches `wg set`")

    def test_mesh_ip_allowlist(self):
        self.assertEqual(call("vh_is_mesh_ip", "10.99.0.2"), 0)
        for bad in ["10.99.0.2; id", "192.168.1.1", "10.99.0.0", "10.99.0.255", "10.99.0.999"]:
            with self.subTest(bad=bad):
                self.assertNotEqual(call("vh_is_mesh_ip", bad), 0)

    def test_hub_address_is_not_claimable_by_a_peer(self):
        """A peer claiming 10.99.0.1 would intercept everything addressed to the hub."""
        self.assertNotEqual(
            call("vh_is_peer_mesh_ip", HUB_IP), 0,
            "a peer was allowed to claim the hub's own mesh address",
        )
        self.assertEqual(call("vh_is_peer_mesh_ip", "10.99.0.2"), 0,
                         "an ordinary peer address must still be accepted")


class SyncWiringTest(unittest.TestCase):
    """The emitted reconcile script must actually use the validators."""

    def setUp(self):
        self.sync = heredoc("/usr/local/bin/wg-sync-peers.sh", "SYNC")

    def _uncommented(self):
        return "\n".join(l for l in self.sync.splitlines() if not l.lstrip().startswith("#"))

    def test_sync_sources_the_validators(self):
        self.assertIn("/usr/local/bin/lib/wg-validate.sh", self._uncommented(),
                      "wg-sync-peers.sh does not source the emitted validator library")

    def test_key_and_ip_validated_before_wg_set(self):
        body = self._uncommented()
        idx = body.index("wg set wg0 peer")
        before = body[:idx]
        self.assertIn("vh_is_wg_key", before,
                      "the registry public_key reaches `wg set` unvalidated")
        self.assertIn("vh_is_peer_mesh_ip", before,
                      "the registry mesh_ip reaches allowed-ips unvalidated")

    def test_no_peer_is_configured_without_a_preshared_key(self):
        """VULN-014: the else-branch that dropped the PSK must be gone.

        Only lines that CONFIGURE a peer are in scope — `wg set ... remove` takes no
        preshared key and is the VULN-015 convergence path.
        """
        configuring = [
            l for l in self._uncommented().splitlines()
            if "wg set wg0 peer" in l and " remove" not in l
        ]
        self.assertTrue(configuring, "no peer-configuring call found at all")
        for line in configuring:
            self.assertIn(
                "preshared-key", line,
                f"a peer is configured without a preshared key: {line.strip()!r} — "
                f"an entry with psk removed silently loses the mesh's second factor",
            )

    def test_revoked_peers_are_removed(self):
        """VULN-015: the reconcile must converge, not merely upsert."""
        body = self._uncommented()
        self.assertIn("wg show wg0 peers", body,
                      "the reconcile never enumerates configured peers, so a registry "
                      "deletion cannot revoke anything until reboot")
        self.assertRegex(body, r"wg set wg0 peer .* remove",
                         "peers absent from the registry are never removed")


if __name__ == "__main__":
    unittest.main()
