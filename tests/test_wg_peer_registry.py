"""The WireGuard hub peer registry: validators, reconcile, register, deregister.

Consolidates the hub-side peer-registry lifecycle (VULN-005/011/012/013/014/015). The
scripts are emitted as heredocs by gcp/scripts/startup.sh and run from /usr/local/bin on
the GCP box; each test extracts the real heredoc and EXECUTES it against stubbed
vault/wg, so it exercises what actually runs on the hub. Four sections:

  * EmittedValidatorTest      — the emitted wg-validate.sh allowlists.
  * reconcile (wg-sync-peers) — behavioural: run the reconcile, assert on what `wg` was
                                actually asked to do (VULN-011 dup-IP, VULN-014 missing
                                PSK, VULN-015 convergence). These replaced the earlier
                                text/ordering greps, which an independent review rejected
                                because a deleted guard would still pass them.
  * RegisterIdempotencyTest   — wg-register-peer (VULN-012 takeover / PSK disclosure).
  * deregister + wiring       — wg-deregister-peer and its rebuild-gated call sites.
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
BOOTSTRAP = REPO_ROOT / "gcp" / "scripts" / "bootstrap-vault.sh"
PROVISION = REPO_ROOT / "scripts" / "provision.sh"
MESHJOIN = REPO_ROOT / "aws" / "scripts" / "wg-mesh-join.sh"

VALID_KEY = "kOtkkR2VfEHFN0m3ES0BJ0BpKbXPQ8YvvKZ5RRSXSHQ="
KEY_A = EXISTING_KEY = VALID_KEY          # same canonical key under each section's name
OTHER_KEY = ATTACKER_KEY = "aB3dEfGhIjKlMnOpQrStUvWxYz0123456789+/ABCc="
KEY_B = "aB3dEfGhIjKlMnOpQrStUvWxYz0123456789+/ABCDA="
KEY_STALE = "STALEKEYSTALEKEYSTALEKEYSTALEKEYSTALEKEYA24="
# Canonical 32-byte keys whose 43rd char is '0'/'8' (base64 value % 4 == 0). The earlier
# allowlist omitted these, rejecting ~1 in 8 real keys — KEY_ENDING_0 is the AWS key that
# surfaced the bug.
KEY_ENDING_0 = "HJjVF0HZcIAoq5sE2tYGEmCNq3uOQRlTPeqg753/6S0="
KEY_ENDING_8 = "wLMJVam4KktCmyDFw3mjqSA4BiNfIFJlWDd8xOA6T68="
HUB_IP = "10.99.0.1"
PSK = STORED_PSK = "PSKPSKPSKPSKPSKPSKPSKPSKPSKPSKPSKPSKPSKPSKA="
HUB_PUB = "HUBHUBHUBHUBHUBHUBHUBHUBHUBHUBHUBHUBHUBHUBA="


def heredoc(name: str, delim: str) -> str:
    text = STARTUP.read_text()
    m = re.search(rf"cat > {re.escape(name)} <<'{delim}'\n(.*?)^{delim}$", text, re.S | re.M)
    if not m:
        raise AssertionError(f"could not locate the {name} heredoc")
    return m.group(1)


def validate_lib() -> str:
    return heredoc("/usr/local/bin/lib/wg-validate.sh", "WGVAL")


def sync_script() -> str:
    return heredoc("/usr/local/bin/wg-sync-peers.sh", "SYNC")


def register_script() -> str:
    return heredoc("/usr/local/bin/wg-register-peer.sh", "REG")


def deregister_script() -> str:
    return heredoc("/usr/local/bin/wg-deregister-peer.sh", "DEREG")


# ── The emitted validator library ────────────────────────────────────────────

def call(fn: str, value: str) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        lib = Path(tmp) / "lib.sh"; lib.write_text(validate_lib())
        script = f'. "{lib}"\n{fn} "$1"\n'
        return subprocess.run(["bash", "-c", script, "_", value],
                              capture_output=True, text=True).returncode


class EmittedValidatorTest(unittest.TestCase):
    def test_key_allowlist_accepts_a_real_key(self):
        self.assertEqual(call("vh_is_wg_key", VALID_KEY), 0,
                         "a genuine WireGuard key must be accepted or peer sync breaks")

    def test_key_allowlist_accepts_valid_keys_ending_0_or_8(self):
        for k in (KEY_ENDING_0, KEY_ENDING_8):
            with self.subTest(key=k):
                self.assertEqual(call("vh_is_wg_key", k), 0,
                                 f"a canonical 32-byte WireGuard key was rejected: {k}")

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
        self.assertNotEqual(call("vh_is_peer_mesh_ip", HUB_IP), 0,
                            "a peer was allowed to claim the hub's own mesh address")
        self.assertEqual(call("vh_is_peer_mesh_ip", "10.99.0.2"), 0,
                         "an ordinary peer address must still be accepted")


# ── The reconcile (wg-sync-peers.sh), executed against a stub registry ────────

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


class ReconcileSanityTest(unittest.TestCase):
    def test_a_valid_peer_is_configured(self):
        """Anchor: without this, every 'nothing happened' assertion below passes vacuously."""
        with tempfile.TemporaryDirectory() as tmp:
            p = run_sync(tmp, {"hetzner": peer(KEY_A, "10.99.0.2")}, [])
            self.assertTrue(p.set_calls,
                            f"the reconcile configured no peer at all (rc={p.returncode}, "
                            f"stderr={p.stderr[:300]})")
            self.assertIn(KEY_A, p.set_calls[0])
            self.assertIn("preshared-key", p.set_calls[0])

    def test_a_malformed_key_peer_is_not_configured(self):
        """The registry public_key reaches `wg set`, so a malformed one must be skipped —
        the behavioural counterpart of the retired 'validated before wg set' grep."""
        with tempfile.TemporaryDirectory() as tmp:
            p = run_sync(tmp, {"bad": peer("not-a-key; id", "10.99.0.2")}, [])
            self.assertEqual(p.set_calls, [],
                             f"a peer with a malformed public_key was sent to wg set: {p.set_calls}")


class DuplicateMeshIpTest(unittest.TestCase):
    """VULN-011 — two entries claiming one address."""

    def test_only_one_peer_gets_a_contested_address(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_sync(tmp, {"alpha": peer(KEY_A, "10.99.0.2"),
                               "beta":  peer(KEY_B, "10.99.0.2")}, [])
            claiming = [c for c in p.set_calls if "10.99.0.2/32" in c]
            self.assertEqual(len(claiming), 1,
                             f"both peers were configured with 10.99.0.2/32, so the later "
                             f"`wg set` silently displaced the earlier peer's routing: {claiming}")

    def test_the_collision_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_sync(tmp, {"alpha": peer(KEY_A, "10.99.0.2"),
                               "beta":  peer(KEY_B, "10.99.0.2")}, [])
            self.assertIn("already claimed", p.stderr,
                          "the duplicate-address collision was silently dropped rather than reported")

    def test_distinct_addresses_both_apply(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_sync(tmp, {"alpha": peer(KEY_A, "10.99.0.2"),
                               "beta":  peer(KEY_B, "10.99.0.3")}, [])
            self.assertEqual(len(p.set_calls), 2,
                             f"legitimate distinct peers were not both configured: {p.set_calls}")


class MissingPskTest(unittest.TestCase):
    """VULN-014 — an entry with no psk must be skipped, not configured without one."""

    def test_peer_without_psk_is_not_configured_at_all(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_sync(tmp, {"nopsk": peer(KEY_A, "10.99.0.2", psk="")}, [])
            configured = [c for c in p.set_calls if KEY_A in c]
            self.assertEqual(configured, [],
                             f"a peer with no preshared key was configured anyway, silently "
                             f"dropping the mesh's second factor: {configured}")

    def test_the_refusal_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_sync(tmp, {"nopsk": peer(KEY_A, "10.99.0.2", psk="")}, [])
            self.assertIn("no psk", p.stderr.lower(), "the missing preshared key was not reported")


class ConvergenceTest(unittest.TestCase):
    """VULN-015 — the reconcile must remove peers the registry no longer lists."""

    def test_stale_peer_is_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_sync(tmp, {"alpha": peer(KEY_A, "10.99.0.2")}, configured=[KEY_A, KEY_STALE])
            self.assertTrue([c for c in p.remove_calls if KEY_STALE in c],
                            f"a peer present on wg0 but absent from the registry was not removed, "
                            f"so deleting a registry entry revokes nothing: {p.calls}")

    def test_registered_peer_is_not_removed(self):
        """The dangerous failure mode: converging by deleting everything."""
        with tempfile.TemporaryDirectory() as tmp:
            p = run_sync(tmp, {"alpha": peer(KEY_A, "10.99.0.2")}, configured=[KEY_A, KEY_STALE])
            self.assertEqual([c for c in p.remove_calls if KEY_A in c], [],
                             "a still-registered peer was removed from the interface")


# ── Registration idempotency / takeover (wg-register-peer.sh) ─────────────────

def run_register(tmp: str, name: str, pub: str, ip: str, existing: bool):
    """Execute the emitted register script with vault and wg stubbed."""
    binp = Path(tmp) / "bin"; binp.mkdir()
    puts = Path(tmp) / "puts.log"
    (binp / "vault").write_text(f"""#!/usr/bin/env bash
case "$1 $2" in
  "login -method=gcp"*|"login"*) echo stub-token; exit 0 ;;
esac
if [ "$1" = "kv" ] && [ "$2" = "get" ]; then
  case "$*" in
    *"kv/wireguard/hub"*) echo "{HUB_PUB}"; exit 0 ;;
    *-field=psk*)        {'echo ' + STORED_PSK if existing else 'exit 1'} ;;
    *-field=public_key*) {'echo ' + EXISTING_KEY if existing else 'exit 1'} ;;
  esac
  exit 1
fi
if [ "$1" = "kv" ] && [ "$2" = "put" ]; then
  echo "PUT $*" >> "{puts}"; exit 0
fi
exit 0
""")
    (binp / "wg").write_text(f"#!/usr/bin/env bash\n[ \"$1\" = genpsk ] && echo {STORED_PSK}\nexit 0\n")
    (binp / "wg-sync-peers.sh").write_text("#!/usr/bin/env bash\nexit 0\n")
    for f in binp.iterdir():
        f.chmod(0o755)

    script = register_script().replace("/usr/local/bin/wg-sync-peers.sh", str(binp / "wg-sync-peers.sh"))
    script = script.replace("/usr/local/bin/lib/wg-validate.sh", str(REPO_ROOT / "tests" / "_wgval.sh"))
    env = dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}")
    proc = subprocess.run(["bash", "-c", script, "_", name, pub, ip],
                          capture_output=True, text=True, env=env, timeout=60)
    proc.puts = puts.read_text() if puts.exists() else ""
    return proc


class RegisterIdempotencyTest(unittest.TestCase):
    """VULN-012 — re-registering a peer must not disclose its PSK or replace its key.

    Idempotent for an IDENTICAL key (provision.sh re-registers 'hetzner' on any probe/ or
    users.txt change with an unchanged key); a different key for an existing name is refused.
    """

    @classmethod
    def setUpClass(cls):
        m = re.search(r"cat > /usr/local/bin/lib/wg-validate\.sh <<'WGVAL'\n(.*?)^WGVAL$",
                      STARTUP.read_text(), re.S | re.M)
        cls.shim = REPO_ROOT / "tests" / "_wgval.sh"
        cls.shim.write_text(m.group(1) if m else "")

    @classmethod
    def tearDownClass(cls):
        cls.shim.unlink(missing_ok=True)

    def test_new_peer_registers(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_register(tmp, "aws", EXISTING_KEY, "10.99.0.3", existing=False)
            self.assertIn("PUT", p.puts,
                          f"a brand-new peer must still register (rc={p.returncode}, {p.stderr[:200]})")

    def test_identical_key_is_idempotent_and_returns_the_psk(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_register(tmp, "hetzner", EXISTING_KEY, "10.99.0.2", existing=True)
            self.assertEqual(p.returncode, 0,
                             f"the routine re-apply path must keep working (stderr={p.stderr[:200]})")
            self.assertIn(STORED_PSK, p.stdout,
                          "the existing PSK must be returned for an unchanged key, or the "
                          "spoke cannot rebuild its wg0.conf on re-apply")

    def test_different_key_is_refused_and_psk_not_disclosed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_register(tmp, "hetzner", ATTACKER_KEY, "10.99.0.2", existing=True)
            self.assertNotEqual(p.returncode, 0,
                                "re-registering an existing name with a different key was accepted")
            self.assertNotIn(STORED_PSK, p.stdout,
                             "the stored PSK was disclosed to a caller presenting a different key")
            self.assertNotIn("PUT", p.puts,
                             "the registry entry was overwritten with the attacker's key")


# ── Deregistration on rebuild (wg-deregister-peer.sh) + call-site wiring ──────

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
                                "a denied delete must fail so the caller's manual-step fallback shows")
            self.assertIn("kv/wireguard/peers/hetzner", p.stderr,
                          "the failure must name the entry and the manual fix")

    def test_uses_the_scoped_role_not_admin(self):
        body = deregister_script()
        self.assertIn("role=wireguard-hub", body,
                      "deregister must authenticate as the scoped wireguard-hub role")
        self.assertNotIn("role=admin", body,
                         "deregister must not reach for the broad admin role")


class DeregisterWiringTest(unittest.TestCase):
    def test_hetzner_deregister_is_gated_on_rebuild_and_precedes_register(self):
        guarded = _slice(PROVISION.read_text(),
                         'if [ "${REBUILT}" = "1" ]', "wg-register-peer.sh hetzner")
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
