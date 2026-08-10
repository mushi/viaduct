"""Security test: VULN-012 — re-registering a peer must not disclose its PSK or replace its key.

CWE-862. wg-register-peer.sh read the stored PSK for a name, then unconditionally
`vault kv put` the caller's public_key over it and printed the PSK on stdout. Anyone able
to invoke the script for an existing name therefore both stole that peer's PSK and
replaced its key — a full takeover of an established peer. The only guard was the
[!a-z0-9-] charset check on the name.

Operator decision: registration stays idempotent for an IDENTICAL key (provision.sh
re-registers 'hetzner' on any probe/ or users.txt change with an unchanged key), but a
different key for an existing name is refused.

The script is emitted as a heredoc by gcp/scripts/startup.sh; these tests extract and
execute it against a stubbed vault.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
STARTUP = REPO_ROOT / "gcp" / "scripts" / "startup.sh"

EXISTING_KEY = "kOtkkR2VfEHFN0m3ES0BJ0BpKbXPQ8YvvKZ5RRSXSHQ="
ATTACKER_KEY = "aB3dEfGhIjKlMnOpQrStUvWxYz0123456789+/ABCc="
STORED_PSK = "PSKPSKPSKPSKPSKPSKPSKPSKPSKPSKPSKPSKPSKPSKA="
HUB_PUB = "HUBHUBHUBHUBHUBHUBHUBHUBHUBHUBHUBHUBHUBHUBA="


def register_script() -> str:
    text = STARTUP.read_text()
    m = re.search(r"cat > /usr/local/bin/wg-register-peer\.sh <<'REG'\n(.*?)^REG$", text, re.S | re.M)
    if not m:
        raise AssertionError("could not locate the wg-register-peer.sh heredoc")
    return m.group(1)


def run_register(tmp: str, name: str, pub: str, ip: str, existing: bool):
    """Execute the emitted script with vault and wg stubbed."""
    binp = Path(tmp) / "bin"; binp.mkdir()
    puts = Path(tmp) / "puts.log"

    stored = f"public_key={EXISTING_KEY}" if existing else ""
    (binp / "vault").write_text(f"""#!/usr/bin/env bash
case "$1 $2" in
  "login -method=gcp"*|"login"*) echo stub-token; exit 0 ;;
esac
if [ "$1" = "kv" ] && [ "$2" = "get" ]; then
  # -field=psk / -field=public_key against an existing or absent entry
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


def _write_val_shim():
    """The emitted validator library, extracted so the register script can source it."""
    text = STARTUP.read_text()
    m = re.search(r"cat > /usr/local/bin/lib/wg-validate\.sh <<'WGVAL'\n(.*?)^WGVAL$", text, re.S | re.M)
    shim = REPO_ROOT / "tests" / "_wgval.sh"
    shim.write_text(m.group(1) if m else "")
    return shim


class RegisterIdempotencyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shim = _write_val_shim()

    @classmethod
    def tearDownClass(cls):
        cls.shim.unlink(missing_ok=True)

    def test_new_peer_registers(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_register(tmp, "aws", EXISTING_KEY, "10.99.0.3", existing=False)
            self.assertIn("PUT", p.puts,
                          f"a brand-new peer must still register (rc={p.returncode}, {p.stderr[:200]})")

    def test_identical_key_is_idempotent_and_returns_the_psk(self):
        """provision.sh re-registers 'hetzner' on routine changes with an unchanged key."""
        with tempfile.TemporaryDirectory() as tmp:
            p = run_register(tmp, "hetzner", EXISTING_KEY, "10.99.0.2", existing=True)
            self.assertEqual(p.returncode, 0,
                             f"the routine re-apply path must keep working (stderr={p.stderr[:200]})")
            self.assertIn(STORED_PSK, p.stdout,
                          "the existing PSK must be returned for an unchanged key, or the "
                          "spoke cannot rebuild its wg0.conf on re-apply")

    def test_different_key_is_refused_and_psk_not_disclosed(self):
        """The takeover path: same name, attacker's key."""
        with tempfile.TemporaryDirectory() as tmp:
            p = run_register(tmp, "hetzner", ATTACKER_KEY, "10.99.0.2", existing=True)
            self.assertNotEqual(p.returncode, 0,
                                "re-registering an existing name with a different key was accepted")
            self.assertNotIn(STORED_PSK, p.stdout,
                             "the stored PSK was disclosed to a caller presenting a different key")
            self.assertNotIn("PUT", p.puts,
                             "the registry entry was overwritten with the attacker's key")


if __name__ == "__main__":
    unittest.main()
