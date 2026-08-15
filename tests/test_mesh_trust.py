"""The mesh-trust library: peer-match provenance, the handshake gate, and cert verify.

Consolidates the two halves of scripts/lib/mesh-trust.sh (VULN-019/020/021 and the
peer-match correctness the acceptance of VULN-008/009 rests on). Both halves drive the
real helpers against stubbed `wg`/`openssl`:

  * PeerMatch / InlineCopy   — vh_wait_for_mesh_handshake maps a peer IP to a key by
                               CIDR containment, not an unanchored regex, so a handshake
                               is attributed to the right peer (and the inlined copy in
                               push-bundle-to-gcp.sh agrees).
  * HandshakeGate / CertSan  — the fetch precondition (a live handshake must exist) and
                               the captured Vault cert must carry the hub IP SAN.
  * LibraryDeployment / Wiring — the helper is deployed where the boot script sources it,
                               and the fetch verifies the cert while deferring the
                               root-only handshake gate upstream.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MESH_TRUST = REPO_ROOT / "scripts" / "lib" / "mesh-trust.sh"
PUSH_BUNDLE = REPO_ROOT / "aws" / "scripts" / "push-bundle-to-gcp.sh"
FETCH = REPO_ROOT / "scripts" / "fetch-hetzner-secrets.sh"

HUB = HUB_IP = "10.99.0.1"
TARGET = "10.99.0.3"
HUB_KEY = HUB_PUBKEY = "kOtkkR2VfEHFN0m3ES0BJ0BpKbXPQ8YvvKZ5RRSXSHQ="
GOOD_KEY = "goodkeyBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
DECOY_KEY = "decoykeyCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="


def uncommented(src) -> str:
    """Source with comment-only lines dropped, so a commented-out guard can't satisfy a
    wiring assertion. Accepts a Path, a full string, or a list of lines."""
    if isinstance(src, Path):
        src = src.read_text().splitlines()
    elif isinstance(src, str):
        src = src.splitlines()
    return "\n".join(l for l in src if not l.lstrip().startswith("#"))


# ── Peer match: attributing a handshake to the correct peer ───────────────────

def run_gate(allowed_ips, handshakes, peer_ip=TARGET, timeout=2):
    """Source mesh-trust.sh with a stubbed `wg` and call the gate once.

    allowed_ips: [(pubkey, "10.99.0.3/32 10.99.0.4/32"), ...]; handshakes: {pubkey: age_s}.
    """
    tmp = Path(tempfile.mkdtemp())
    aip = "\n".join(f"{k}\t{v}" for k, v in allowed_ips)
    now = int(subprocess.run(["date", "+%s"], capture_output=True, text=True).stdout)
    hs = "\n".join(f"{k}\t{now - age}" for k, age in handshakes.items())
    # Write fixtures to files and cat them; interpolating escapes the tabs and collapses
    # each line to one awk field, making the matcher look broken when it is not.
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
              f'vh_wait_for_mesh_handshake "{peer_ip}" wg0 {timeout}\necho "RC=$?"\n')
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
        p = run_gate([(GOOD_KEY, f"{TARGET}/32")], {GOOD_KEY: 9999})
        self.assertFalse(p.gate_passed, "a stale handshake satisfied the gate")

    def test_a_longer_address_does_not_satisfy_a_shorter_one(self):
        """10.99.0.30 must not answer for 10.99.0.3 — the filed substring defect."""
        p = run_gate([(DECOY_KEY, f"{TARGET}0/32")], {DECOY_KEY: 10})
        self.assertFalse(p.gate_passed,
                         "a peer holding 10.99.0.30/32 satisfied the gate for 10.99.0.3")

    def test_a_decoy_listed_first_does_not_win(self):
        """The matcher exits on the first hit, so ordering must not decide."""
        p = run_gate([(DECOY_KEY, f"{TARGET}0/32"), (GOOD_KEY, f"{TARGET}/32")],
                     {DECOY_KEY: 9999, GOOD_KEY: 10})
        self.assertTrue(p.gate_passed,
                        "a decoy peer listed first shadowed the real one")

    def test_a_decoy_first_cannot_lend_its_handshake(self):
        p = run_gate([(DECOY_KEY, f"{TARGET}0/32"), (GOOD_KEY, f"{TARGET}/32")],
                     {DECOY_KEY: 10, GOOD_KEY: 9999})
        self.assertFalse(p.gate_passed,
                         "a live peer at 10.99.0.30 lent its handshake to a stale 10.99.0.3")

    def test_dots_are_not_wildcards(self):
        p = run_gate([(DECOY_KEY, "10299203/32")], {DECOY_KEY: 10}, peer_ip="10.99.0.3")
        self.assertFalse(p.gate_passed,
                         "the address was treated as a regex, so unrelated peers match")

    def test_a_spoke_hub_route_slash24_is_matched(self):
        """On a spoke the hub peer carries the whole mesh as 10.99.0.0/24, so asking for
        10.99.0.1 must find it by prefix containment (exact /32 missed it)."""
        p = run_gate([(HUB_KEY, "10.99.0.0/24")], {HUB_KEY: 10}, peer_ip=HUB)
        self.assertTrue(p.gate_passed,
                        "the hub peer's /24 mesh route did not satisfy the gate for the hub IP")

    def test_a_noncovering_slash24_does_not_match(self):
        p = run_gate([(DECOY_KEY, "10.99.1.0/24")], {DECOY_KEY: 10}, peer_ip=HUB)
        self.assertFalse(p.gate_passed,
                         "a /24 that does not contain the target satisfied the gate")

    def test_a_peer_with_several_addresses_is_still_found(self):
        p = run_gate([(GOOD_KEY, f"{HUB}/32 {TARGET}/32")], {GOOD_KEY: 10})
        self.assertTrue(p.gate_passed,
                        "a peer holding several addresses was not matched on the second")

    def test_an_unknown_peer_fails(self):
        p = run_gate([(GOOD_KEY, "10.99.0.9/32")], {GOOD_KEY: 10})
        self.assertFalse(p.gate_passed, "an address no peer holds satisfied the gate")


class InlineCopyTest(unittest.TestCase):
    """push-bundle-to-gcp.sh inlines the same expression into a remote heredoc."""

    def test_the_inline_copy_is_not_an_unanchored_regex(self):
        self.assertNotIn("$0 ~ ip", uncommented(PUSH_BUNDLE),
                         "the inlined matcher still uses an unanchored whole-line regex")

    def test_the_inline_copy_matches_a_slash_32_field(self):
        body = uncommented(PUSH_BUNDLE)
        self.assertIn('/32"', body, "the inlined matcher does not compare against a /32 entry")
        self.assertRegex(body, r'for \(i = 2; i <= NF; i\+\+\)',
                         "the inlined matcher does not scan the allowed-ips fields")

    def test_both_copies_agree(self):
        """Anchor: they drifted once already — the inline copy is easy to forget."""
        for path in (MESH_TRUST, PUSH_BUNDLE):
            with self.subTest(file=path.name):
                self.assertNotIn("$0 ~ ip", uncommented(path))


# ── Handshake precondition + captured-cert verification ───────────────────────

def make_wg_stub(tmp: str, handshake_epoch: str) -> str:
    stub = Path(tmp) / "wg"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'case "$2 $3" in\n'
        f'  "wg0 allowed-ips") printf "%s\\t%s/32\\n" "{HUB_PUBKEY}" "{HUB_IP}" ;;\n'
        f'  "wg0 latest-handshakes") printf "%s\\t{handshake_epoch}\\n" "{HUB_PUBKEY}" ;;\n'
        "esac\n")
    stub.chmod(0o755)
    return str(stub)


def call_wait(tmp: str, handshake_epoch: str, timeout: str = "1") -> int:
    wg = make_wg_stub(tmp, handshake_epoch)
    script = f'. "{MESH_TRUST}"\nWG_BIN="{wg}" vh_wait_for_mesh_handshake "{HUB_IP}" wg0 {timeout}\n'
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True).returncode


def make_cert(tmp: str, name: str, san_ip: str, days: str = "1") -> Path:
    crt = Path(tmp) / f"{name}.crt"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(Path(tmp) / f"{name}.key"), "-out", str(crt),
         "-days", days, "-subj", f"/CN={name}", "-addext", f"subjectAltName=IP:{san_ip}"],
        capture_output=True)
    return crt


def call_verify(cert: Path, expected_ip: str) -> int:
    script = f'. "{MESH_TRUST}"\nvh_verify_cert_san "{cert}" "{expected_ip}"\n'
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True).returncode


class HandshakeGateTest(unittest.TestCase):
    def test_rejects_when_no_handshake_has_occurred(self):
        """latest-handshakes == 0 means the interface is up but nobody is authenticated."""
        with tempfile.TemporaryDirectory() as tmp:
            self.assertNotEqual(call_wait(tmp, "0"), 0,
                                "helper returned success with zero handshakes: the TOFU fetch "
                                "would run while the mesh authenticates nobody")

    def test_accepts_a_recent_handshake(self):
        import time
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(call_wait(tmp, str(int(time.time()))), 0,
                             "a live handshake with the hub peer must satisfy the precondition")

    def test_rejects_a_stale_handshake(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertNotEqual(call_wait(tmp, "1000000000"), 0,
                                "a handshake from 2001 must not count as a live mesh peer")


class CertSanGateTest(unittest.TestCase):
    def test_rejects_a_cert_without_the_hub_ip(self):
        with tempfile.TemporaryDirectory() as tmp:
            rogue = make_cert(tmp, "rogue", "203.0.113.99")
            self.assertNotEqual(call_verify(rogue, HUB_IP), 0,
                                "a responder's cert with no 10.99.0.1 SAN was accepted as the Vault CA")

    def test_accepts_the_hub_cert(self):
        with tempfile.TemporaryDirectory() as tmp:
            hub = make_cert(tmp, "hub", HUB_IP)
            self.assertEqual(call_verify(hub, HUB_IP), 0,
                             "the genuine hub cert must be accepted or secrets fetch breaks")

    def test_rejects_an_empty_capture(self):
        """`openssl s_client ... 2>/dev/null` yields an empty file when the peer is absent."""
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty.crt"; empty.write_text("")
            self.assertNotEqual(call_verify(empty, HUB_IP), 0,
                                "an empty capture must not be accepted as the CA")

    def test_rejects_an_expired_cert(self):
        with tempfile.TemporaryDirectory() as tmp:
            crt = Path(tmp) / "old.crt"
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", str(Path(tmp) / "old.key"), "-out", str(crt),
                 "-days", "1", "-not_before", "20200101000000Z", "-not_after", "20200102000000Z",
                 "-subj", "/CN=old", "-addext", f"subjectAltName=IP:{HUB_IP}"],
                capture_output=True)
            if not crt.exists() or crt.stat().st_size == 0:
                self.skipTest("openssl build does not support -not_before/-not_after")
            self.assertNotEqual(call_verify(crt, HUB_IP), 0, "an expired cert must be rejected")


class LibraryDeploymentTest(unittest.TestCase):
    """The helper must exist at the path the DEPLOYED script sources (it runs from
    /usr/local/bin, not the repo), or the unit fails at boot while repo tests pass."""

    def test_lib_is_deployed_next_to_the_script(self):
        cloud_init = (REPO_ROOT / "cloud-init.yaml.tpl").read_text()
        main_tf = (REPO_ROOT / "main.tf").read_text()
        self.assertIn("mesh_trust_lib", main_tf,
                      "main.tf does not pass the mesh-trust library into the cloud-init template")
        self.assertIn("/usr/local/bin/lib/mesh-trust.sh", cloud_init,
                      "cloud-init does not write the mesh-trust library to the sourced path")

    def test_source_path_matches_the_deployed_path(self):
        self.assertRegex(
            uncommented(FETCH),
            r"\.\s+\"\$\(cd \"\$\(dirname .*\)\" && pwd\)/lib/mesh-trust\.sh\"",
            "the source line no longer resolves to <script dir>/lib/mesh-trust.sh")


class FetchScriptWiringTest(unittest.TestCase):
    def test_fetch_verifies_cert_and_defers_the_handshake_gate_to_root(self):
        """The captured cert is verified here; the handshake precondition is enforced
        UPSTREAM by the service's root ExecStartPre (see test_hetzner_secrets_self_heal),
        because `wg show` needs CAP_NET_ADMIN this unprivileged fetch lacks."""
        lines = FETCH.read_text().splitlines()
        self.assertNotIn("vh_wait_for_mesh_handshake", uncommented(lines),
                         "the handshake gate is back in the unprivileged fetch, where `wg show` "
                         "returns nothing so the secrets never render")
        try:
            capture = next(i for i, l in enumerate(lines) if "openssl s_client" in l)
        except StopIteration:
            self.fail("could not locate the openssl s_client capture in fetch-hetzner-secrets.sh")
        self.assertIn("vh_verify_cert_san", uncommented(lines[capture:]),
                      "the captured cert is never verified against the expected hub IP")


if __name__ == "__main__":
    unittest.main()
