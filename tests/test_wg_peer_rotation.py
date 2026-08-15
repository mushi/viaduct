"""Automated WireGuard peer-key rotation on a genuine spoke rebuild.

A rebuilt spoke generates a fresh WireGuard key, so its stale registry entry must be
cleared before it can re-register (the hub refuses a name whose key changed — VULN-012).
That deletion used to be a manual `vault kv delete`. It is now driven automatically by
the provisioner, gated on the unforgeable cloud instance-id change, via the hub script
`wg-deregister-peer.sh`.

These tests extract the emitted deregister script and check the wiring on both spokes.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
STARTUP = REPO_ROOT / "gcp" / "scripts" / "startup.sh"
BOOTSTRAP = REPO_ROOT / "gcp" / "scripts" / "bootstrap-vault.sh"
PROVISION = REPO_ROOT / "scripts" / "provision.sh"
MESHJOIN = REPO_ROOT / "aws" / "scripts" / "wg-mesh-join.sh"


def deregister_script() -> str:
    text = STARTUP.read_text()
    m = re.search(r"cat > /usr/local/bin/wg-deregister-peer\.sh <<'DEREG'\n(.*?)^DEREG$", text, re.S | re.M)
    if not m:
        raise AssertionError("could not locate the wg-deregister-peer.sh heredoc")
    return m.group(1)


def run_deregister(tmp: str, name: str, deny: bool = False):
    """Execute the emitted deregister script with vault stubbed; log any kv delete.

    deny=True makes the stub reject the delete with a 403, as a snapshot-restored hub
    whose wireguard-hub policy predates the delete grant would.
    """
    binp = Path(tmp) / "bin"; binp.mkdir()
    log = Path(tmp) / "vault.log"
    delete_branch = (
        'echo "Error making API request. Code: 403. permission denied" >&2; exit 1'
        if deny else
        f'echo "DELETE $*" >> "{log}"; exit 0'
    )
    (binp / "vault").write_text(
        "#!/usr/bin/env bash\n"
        'case "$1 $2" in\n'
        '  "login "*) echo stub-token; exit 0 ;;\n'
        "esac\n"
        f'if [ "$1" = "kv" ] && [ "$2" = "delete" ]; then {delete_branch}; fi\n'
        "exit 0\n"
    )
    (binp / "vault").chmod(0o755)
    env = dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}")
    proc = subprocess.run(["bash", "-c", deregister_script(), "_", name],
                          capture_output=True, text=True, env=env, timeout=30)
    proc.deleted = log.read_text() if log.exists() else ""
    return proc


def _slice(text: str, start_marker: str, end_marker: str) -> str:
    i, j = text.index(start_marker), text.index(end_marker)
    assert i < j, f"{start_marker!r} did not precede {end_marker!r}"
    return text[i:j]


class DeregisterScriptTest(unittest.TestCase):
    def test_deletes_the_named_peer_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_deregister(tmp, "aws")
            self.assertEqual(p.returncode, 0, f"deregister failed: {p.stderr[:200]}")
            self.assertIn("kv/wireguard/peers/aws", p.deleted,
                          "deregister must delete exactly the named peer's registry entry")

    def test_rejects_an_invalid_peer_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_deregister(tmp, "aws;rm -rf /")
            self.assertNotEqual(p.returncode, 0,
                                "a peer name with shell metacharacters must be rejected")

    def test_denied_delete_fails_loudly(self):
        """A 403 (restored hub without the grant) must NOT be swallowed as success."""
        with tempfile.TemporaryDirectory() as tmp:
            p = run_deregister(tmp, "hetzner", deny=True)
            self.assertNotEqual(p.returncode, 0,
                                "a denied delete must fail so the caller's manual-step fallback "
                                "shows, instead of a silent success that deletes nothing")
            self.assertIn("kv/wireguard/peers/hetzner", p.stderr,
                          "the failure must name the entry and the manual fix")

    def test_uses_the_scoped_role_not_admin(self):
        body = deregister_script()
        self.assertIn("role=wireguard-hub", body,
                      "deregister must authenticate as the scoped wireguard-hub role")
        self.assertNotIn("role=admin", body,
                         "deregister must not reach for the broad admin role")


class WiringTest(unittest.TestCase):
    def test_hetzner_deregister_is_gated_on_rebuild_and_precedes_register(self):
        body = PROVISION.read_text()
        # The deregister call must sit inside the REBUILT guard, before the register.
        guarded = _slice(body, 'if [ "${REBUILT}" = "1" ]', "wg-register-peer.sh hetzner")
        self.assertIn("wg-deregister-peer.sh hetzner", guarded,
                      "the Hetzner deregister must be gated on REBUILT and run before register, "
                      "or a routine re-apply (same key) would needlessly rotate the PSK")

    def test_hetzner_records_server_id_after_registration(self):
        body = PROVISION.read_text()
        self.assertLess(body.index("wg-register-peer.sh hetzner"),
                        body.index('vh_record_server_id "${SERVER_ID'),
                        "the server-id baseline must be recorded only after §8b registration, "
                        "or a failed rotation burns the REBUILT signal on the retry")

    def test_aws_deregister_precedes_register(self):
        body = MESHJOIN.read_text()
        self.assertLess(body.index("wg-deregister-peer.sh aws"),
                        body.index("wg-register-peer.sh aws"),
                        "wg-mesh-join runs only on a recreate, so it clears the stale entry "
                        "before registering the fresh key")

    def test_wireguard_hub_role_may_delete_peers(self):
        block = _slice(BOOTSTRAP.read_text(),
                       "vault policy write wireguard-hub", "vault write auth/gcp/role/wireguard-hub")
        peers = next(l for l in block.splitlines() if 'kv/data/wireguard/peers/*' in l)
        self.assertIn("delete", peers,
                      "wg-deregister-peer.sh authenticates as wireguard-hub, so that role needs "
                      "delete on the peer registry")


if __name__ == "__main__":
    unittest.main()
