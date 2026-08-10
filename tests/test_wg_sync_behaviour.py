"""Behavioural tests for the WireGuard peer reconcile — VULN-011, VULN-014, VULN-015.

These replace text-and-ordering assertions that an independent review correctly rejected:
a check that the guards *appear* before `wg set` would still pass if the duplicate-IP
guard, the missing-PSK refusal, or the convergence pass were deleted outright.

Here the real wg-sync-peers.sh heredoc is extracted from gcp/scripts/startup.sh and
EXECUTED against a stubbed `vault` (serving a synthetic peer registry) and a stubbed `wg`
that records every invocation. The assertions are made against what wg was actually asked
to do.
"""

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
STARTUP = REPO_ROOT / "gcp" / "scripts" / "startup.sh"

KEY_A = "kOtkkR2VfEHFN0m3ES0BJ0BpKbXPQ8YvvKZ5RRSXSHQ="
KEY_B = "aB3dEfGhIjKlMnOpQrStUvWxYz0123456789+/ABCDA="
KEY_STALE = "STALEKEYSTALEKEYSTALEKEYSTALEKEYSTALEKEYA24="
PSK = "PSKPSKPSKPSKPSKPSKPSKPSKPSKPSKPSKPSKPSKPSKA="


def sync_script() -> str:
    body = STARTUP.read_text()
    m = re.search(r"cat > /usr/local/bin/wg-sync-peers\.sh <<'SYNC'\n(.*?)^SYNC$", body, re.S | re.M)
    if not m:
        raise AssertionError("could not locate the wg-sync-peers.sh heredoc")
    return m.group(1)


def validate_lib() -> str:
    body = STARTUP.read_text()
    m = re.search(r"cat > /usr/local/bin/lib/wg-validate\.sh <<'WGVAL'\n(.*?)^WGVAL$", body, re.S | re.M)
    if not m:
        raise AssertionError("could not locate the wg-validate.sh heredoc")
    return m.group(1)


def run_sync(tmp: str, registry: dict, configured: list):
    """Execute the real reconcile. `registry` is name -> field dict; `configured` is the
    set of peer keys already present on wg0."""
    tmpp = Path(tmp)
    binp = tmpp / "bin"; binp.mkdir()
    calls = tmpp / "wg_calls.log"
    reg = tmpp / "registry.json"; reg.write_text(json.dumps(registry))

    lib = tmpp / "wg-validate.sh"; lib.write_text(validate_lib())

    (binp / "vault").write_text(f"""#!/usr/bin/env bash
REG="{reg}"
if [ "$1" = "login" ]; then echo stub-token; exit 0; fi
if [ "$1" = "kv" ] && [ "$2" = "list" ]; then
  jq -c '[keys[]]' "$REG"; exit 0
fi
if [ "$1" = "kv" ] && [ "$2" = "get" ]; then
  name="${{@: -1}}"; name="${{name##*/}}"
  jq -c --arg n "$name" 'if has($n) then {{data:{{data:.[$n]}}}} else empty end' "$REG"
  exit 0
fi
exit 0
""")
    (binp / "wg").write_text(f"""#!/usr/bin/env bash
echo "$*" >> "{calls}"
if [ "$1" = "show" ] && [ "$3" = "peers" ]; then
  printf '%s\\n' {" ".join(repr(c) for c in configured) or "''"}
fi
exit 0
""")
    for f in binp.iterdir():
        f.chmod(0o755)

    script = sync_script().replace("/usr/local/bin/lib/wg-validate.sh", str(lib))
    env = dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}")
    proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=60)
    proc.calls = calls.read_text().splitlines() if calls.exists() else []
    proc.set_calls = [c for c in proc.calls if c.startswith("set wg0 peer") and " remove" not in c]
    proc.remove_calls = [c for c in proc.calls if c.startswith("set wg0 peer") and c.endswith(" remove")]
    return proc


def peer(pub, ip, psk=PSK):
    return {"public_key": pub, "mesh_ip": ip, "psk": psk}


class SanityTest(unittest.TestCase):
    def test_a_valid_peer_is_configured(self):
        """Anchor: without this, every 'nothing happened' assertion below passes vacuously."""
        with tempfile.TemporaryDirectory() as tmp:
            p = run_sync(tmp, {"hetzner": peer(KEY_A, "10.99.0.2")}, [])
            self.assertTrue(
                p.set_calls,
                f"the reconcile configured no peer at all — harness or script failure "
                f"(rc={p.returncode}, stderr={p.stderr[:300]})",
            )
            self.assertIn(KEY_A, p.set_calls[0])
            self.assertIn("preshared-key", p.set_calls[0])


class DuplicateMeshIpTest(unittest.TestCase):
    """VULN-011 — two entries claiming one address."""

    def test_only_one_peer_gets_a_contested_address(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_sync(tmp, {
                "alpha": peer(KEY_A, "10.99.0.2"),
                "beta":  peer(KEY_B, "10.99.0.2"),
            }, [])
            claiming = [c for c in p.set_calls if "10.99.0.2/32" in c]
            self.assertEqual(
                len(claiming), 1,
                f"both peers were configured with 10.99.0.2/32, so the later `wg set` "
                f"silently displaced the earlier peer's routing: {claiming}",
            )

    def test_the_collision_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_sync(tmp, {
                "alpha": peer(KEY_A, "10.99.0.2"),
                "beta":  peer(KEY_B, "10.99.0.2"),
            }, [])
            self.assertIn("already claimed", p.stderr,
                          "the duplicate-address collision was silently dropped rather than reported")

    def test_distinct_addresses_both_apply(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_sync(tmp, {
                "alpha": peer(KEY_A, "10.99.0.2"),
                "beta":  peer(KEY_B, "10.99.0.3"),
            }, [])
            self.assertEqual(len(p.set_calls), 2,
                             f"legitimate distinct peers were not both configured: {p.set_calls}")


class MissingPskTest(unittest.TestCase):
    """VULN-014 — an entry with no psk must be skipped, not configured without one."""

    def test_peer_without_psk_is_not_configured_at_all(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_sync(tmp, {"nopsk": peer(KEY_A, "10.99.0.2", psk="")}, [])
            configured = [c for c in p.set_calls if KEY_A in c]
            self.assertEqual(
                configured, [],
                f"a peer with no preshared key was configured anyway, silently dropping "
                f"the mesh's second factor: {configured}",
            )

    def test_the_refusal_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_sync(tmp, {"nopsk": peer(KEY_A, "10.99.0.2", psk="")}, [])
            self.assertIn("no psk", p.stderr.lower(),
                          "the missing preshared key was not reported")


class ConvergenceTest(unittest.TestCase):
    """VULN-015 — the reconcile must remove peers the registry no longer lists."""

    def test_stale_peer_is_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_sync(tmp, {"alpha": peer(KEY_A, "10.99.0.2")},
                         configured=[KEY_A, KEY_STALE])
            removed = [c for c in p.remove_calls if KEY_STALE in c]
            self.assertTrue(
                removed,
                f"a peer present on wg0 but absent from the registry was not removed, so "
                f"deleting a registry entry revokes nothing: {p.calls}",
            )

    def test_registered_peer_is_not_removed(self):
        """The dangerous failure mode: converging by deleting everything."""
        with tempfile.TemporaryDirectory() as tmp:
            p = run_sync(tmp, {"alpha": peer(KEY_A, "10.99.0.2")},
                         configured=[KEY_A, KEY_STALE])
            wrongly = [c for c in p.remove_calls if KEY_A in c]
            self.assertEqual(
                wrongly, [],
                f"a still-registered peer was removed from the interface: {wrongly}",
            )


if __name__ == "__main__":
    unittest.main()
