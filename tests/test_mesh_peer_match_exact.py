"""The mesh handshake gate matched the wrong peer.

`vh_wait_for_mesh_handshake` maps a peer IP to a public key so it can check that
peer's handshake age. It did so with `awk -v ip="$peer_ip" '$0 ~ ip'` — an
unanchored regex over the whole line. Three ways that picks the wrong peer:

  * substring — asking about 10.99.0.3 matches a peer holding 10.99.0.30/32
  * regex metacharacters — the dots are wildcards
  * ordering — it takes whichever peer `wg show` prints first and exits

This matters more than it looks. The independent verification passed VULN-019 and
VULN-020 specifically *because* this gate establishes provenance ("the response's
origin is established by WireGuard peer authentication rather than by TOFU"), and
the acceptance recorded for VULN-008/009 rests on the same premise. A gate that
can attribute a handshake to the wrong peer undermines all of it.

The same expression was inlined into aws/scripts/push-bundle-to-gcp.sh, so both
copies are covered here.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

def uncommented(path: Path) -> str:
    """Source with comments stripped — the fix documents the old expression."""
    return "\n".join(l for l in path.read_text().splitlines()
                      if not l.lstrip().startswith("#"))


REPO_ROOT = Path(__file__).resolve().parents[1]
MESH_TRUST = REPO_ROOT / "scripts" / "lib" / "mesh-trust.sh"
PUSH_BUNDLE = REPO_ROOT / "aws" / "scripts" / "push-bundle-to-gcp.sh"

HUB = "10.99.0.1"
TARGET = "10.99.0.3"
HUB_KEY = "hubkeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
GOOD_KEY = "goodkeyBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
DECOY_KEY = "decoykeyCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="


def run_gate(allowed_ips, handshakes, peer_ip=TARGET, timeout=2):
    """Source mesh-trust.sh with a stubbed `wg` and call the gate once.

    allowed_ips: [(pubkey, "10.99.0.3/32 10.99.0.4/32"), ...]
    handshakes:  {pubkey: age_seconds_ago}
    """
    tmp = Path(tempfile.mkdtemp())
    aip = "\n".join(f"{k}\t{v}" for k, v in allowed_ips)
    now = int(subprocess.run(["date", "+%s"], capture_output=True, text=True).stdout)
    hs = "\n".join(f"{k}\t{now - age}" for k, age in handshakes.items())

    # Write the fixtures to files and cat them. Interpolating them into the stub
    # escapes the tabs, which collapses each line to one awk field and makes the
    # matcher look broken when it is not.
    (tmp / "allowed-ips").write_text(aip + "\n")
    (tmp / "handshakes").write_text(hs + "\n")
    wg = tmp / "wg"
    wg.write_text(
        "#!/usr/bin/env bash\n"
        'case "$3" in\n'
        f'  allowed-ips)       cat "{tmp}/allowed-ips" ;;\n'
        f'  latest-handshakes) cat "{tmp}/handshakes" ;;\n'
        "esac\nexit 0\n")
    wg.chmod(0o755)

    script = (f'WG_BIN="{wg}"\n. "{MESH_TRUST}"\n'
              f'vh_wait_for_mesh_handshake "{peer_ip}" wg0 {timeout}\n'
              'echo "RC=$?"\n')
    p = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                       timeout=60, stdin=subprocess.DEVNULL)
    p.gate_passed = "RC=0" in p.stdout
    return p


class PeerMatchTest(unittest.TestCase):
    def test_a_live_peer_passes(self):
        """Anchor: without this every rejection below could be an unconditional fail."""
        p = run_gate([(GOOD_KEY, f"{TARGET}/32")], {GOOD_KEY: 10})
        self.assertTrue(p.gate_passed,
                        f"a genuine live peer was rejected: {p.stdout} {p.stderr[-200:]}")

    def test_a_stale_handshake_fails(self):
        """Anchor: the gate must still be capable of refusing."""
        p = run_gate([(GOOD_KEY, f"{TARGET}/32")], {GOOD_KEY: 9999})
        self.assertFalse(p.gate_passed, "a stale handshake satisfied the gate")

    def test_a_longer_address_does_not_satisfy_a_shorter_one(self):
        """10.99.0.30 must not answer for 10.99.0.3 — the filed substring defect."""
        p = run_gate([(DECOY_KEY, f"{TARGET}0/32")], {DECOY_KEY: 10})
        self.assertFalse(
            p.gate_passed,
            "a peer holding 10.99.0.30/32 satisfied the gate for 10.99.0.3, so the "
            "handshake of the wrong peer is being used to establish provenance")

    def test_a_decoy_listed_first_does_not_win(self):
        """The matcher exits on the first hit, so ordering must not decide."""
        p = run_gate(
            [(DECOY_KEY, f"{TARGET}0/32"), (GOOD_KEY, f"{TARGET}/32")],
            {DECOY_KEY: 9999, GOOD_KEY: 10})
        self.assertTrue(
            p.gate_passed,
            "a decoy peer listed first shadowed the real one, so the real peer's "
            "live handshake was never consulted")

    def test_a_decoy_first_cannot_lend_its_handshake(self):
        """The inverse: a live decoy must not vouch for a stale real peer."""
        p = run_gate(
            [(DECOY_KEY, f"{TARGET}0/32"), (GOOD_KEY, f"{TARGET}/32")],
            {DECOY_KEY: 10, GOOD_KEY: 9999})
        self.assertFalse(
            p.gate_passed,
            "a live peer at 10.99.0.30 lent its handshake to a stale 10.99.0.3")

    def test_dots_are_not_wildcards(self):
        p = run_gate([(DECOY_KEY, "10299203/32")], {DECOY_KEY: 10}, peer_ip="10.99.0.3")
        self.assertFalse(p.gate_passed,
                         "the address was treated as a regex, so unrelated peers match")

    def test_a_spoke_hub_route_slash24_is_matched(self):
        """Regression: on a spoke the hub peer carries the whole mesh as 10.99.0.0/24,
        so asking for the hub 10.99.0.1 must find it by prefix containment. Exact /32
        matching missed it and the Vault/bundle fetch failed closed on a healthy tunnel."""
        p = run_gate([(HUB_KEY, "10.99.0.0/24")], {HUB_KEY: 10}, peer_ip=HUB)
        self.assertTrue(
            p.gate_passed,
            "the hub peer's /24 mesh route did not satisfy the gate for the hub IP")

    def test_a_noncovering_slash24_does_not_match(self):
        """Containment is real: a /24 that does not contain the target must not match."""
        p = run_gate([(DECOY_KEY, "10.99.1.0/24")], {DECOY_KEY: 10}, peer_ip=HUB)
        self.assertFalse(
            p.gate_passed, "a /24 that does not contain the target satisfied the gate")

    def test_a_peer_with_several_addresses_is_still_found(self):
        """allowed-ips carries multiple entries; the match scans them all."""
        p = run_gate([(GOOD_KEY, f"{HUB}/32 {TARGET}/32")], {GOOD_KEY: 10})
        self.assertTrue(p.gate_passed,
                        "a peer holding several addresses was not matched on the second")

    def test_an_unknown_peer_fails(self):
        p = run_gate([(GOOD_KEY, "10.99.0.9/32")], {GOOD_KEY: 10})
        self.assertFalse(p.gate_passed, "an address no peer holds satisfied the gate")


class InlineCopyTest(unittest.TestCase):
    """push-bundle-to-gcp.sh inlines the same expression into a remote heredoc."""

    def test_the_inline_copy_is_not_an_unanchored_regex(self):
        body = uncommented(PUSH_BUNDLE)
        self.assertNotIn(
            "$0 ~ ip", body,
            "the inlined matcher still uses an unanchored whole-line regex, so the "
            "AWS-side bundle push can attribute a handshake to the wrong peer")

    def test_the_inline_copy_matches_a_slash_32_field(self):
        body = uncommented(PUSH_BUNDLE)
        self.assertIn('/32"', body,
                      "the inlined matcher does not compare against a /32 entry")
        self.assertRegex(
            body, r'for \(i = 2; i <= NF; i\+\+\)',
            "the inlined matcher does not scan the allowed-ips fields")

    def test_both_copies_agree(self):
        """Anchor: they drifted once already — the inline copy is easy to forget."""
        for path in (MESH_TRUST, PUSH_BUNDLE):
            with self.subTest(file=path.name):
                self.assertNotIn("$0 ~ ip", uncommented(path))


if __name__ == "__main__":
    unittest.main()
