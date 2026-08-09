"""Security test: VULN-007 — the wireguard-hub policy must not allow overwriting the hub key.

CWE-863. The wireguard-hub policy granted create/read/update across all of
kv/data/wireguard/*, which includes kv/wireguard/hub — the hub's own WireGuard private
key. The role is bound to the instance service account, so a token minted through it
could replace the hub key and take over the mesh, not merely register peers.

startup.sh:400 documents that the hub key is "generated once on the first bootstrapped
boot, then fetched", and the write at :477 only runs when it is absent — so `update` on
that path is not needed for normal operation.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = REPO_ROOT / "gcp" / "scripts" / "bootstrap-vault.sh"


def policy_stanzas(name: str):
    text = BOOTSTRAP.read_text()
    m = re.search(rf"vault policy write {re.escape(name)} - <<'EOF'\n(.*?)\nEOF", text, re.S)
    if not m:
        raise AssertionError(f"could not locate the {name!r} policy")
    return dict(
        (p, {c.strip().strip('"') for c in caps.split(",")})
        for p, caps in re.findall(r'path\s+"([^"]+)"\s*\{[^\[]*\[([^\]]*)\]', m.group(1))
    )


class WireguardHubPolicyTest(unittest.TestCase):
    def setUp(self):
        self.stanzas = policy_stanzas("wireguard-hub")

    def test_hub_key_path_is_separated_from_peers(self):
        self.assertNotIn(
            "kv/data/wireguard/*", self.stanzas,
            "the policy still grants a blanket kv/data/wireguard/* — that covers the "
            "hub's own private key as well as the peer registry",
        )

    def test_hub_key_cannot_be_overwritten(self):
        hub = [p for p in self.stanzas if p.rstrip("*").endswith("wireguard/hub")]
        self.assertTrue(hub, "no stanza covers kv/data/wireguard/hub; the hub could not "
                             "read its own key on boot")
        for p in hub:
            self.assertNotIn(
                "update", self.stanzas[p],
                f'"{p}" still grants update: a token from this role could replace the '
                f'hub WireGuard key and take over the mesh',
            )
            self.assertNotIn("delete", self.stanzas[p], f'"{p}" grants delete on the hub key')

    def test_peer_registry_still_writable(self):
        """wg-register-peer.sh must still be able to register a spoke."""
        peers = [p for p in self.stanzas if "peers" in p]
        self.assertTrue(peers, "no stanza covers the peer registry; registration would break")
        caps = set().union(*(self.stanzas[p] for p in peers))
        for needed in ("create", "read", "update"):
            self.assertIn(needed, caps,
                          f"peer registry lost {needed!r}; wg-register-peer.sh would fail")

    def test_metadata_list_retained(self):
        """wg-sync-peers.sh lists the registry on every reconcile."""
        meta = [p for p in self.stanzas if "metadata" in p]
        self.assertTrue(meta, "metadata list grant was dropped; wg-sync-peers.sh could not "
                              "enumerate peers")


if __name__ == "__main__":
    unittest.main()
