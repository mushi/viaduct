"""Security test: VULN-032 — the third-party IP lookup must be validated at source.

CWE-94. xray-setup.sh takes the node's public address from api4.my-ip.io, an
unauthenticated third party, and interpolates it into a JSON config literal
(`"address": "$SERVER_IP"`) and into the generated client URIs. A hostile or MITM'd
response therefore injects into the rendered configuration.

The previous cluster's VULN-038 fix guarded only the routing-rule interpolation.
Validating once at the assignment covers every consumer.

The fragment is extracted from cloud-init.yaml.tpl and executed.
"""

import re
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TPL = REPO_ROOT / "cloud-init.yaml.tpl"


def render(body: str) -> str:
    """Undo Terraform's template escaping, as templatefile() does at apply time.

    The node runs the *rendered* script, so `$${x}` reaches bash as `${x}`. Extracting
    the raw template instead would hand bash a literal `$$` (its own PID) and test a
    script that is never deployed.
    """
    return body.replace("$${", "${").replace("%%{", "%{")


def dedent(block: str) -> str:
    lines = block.splitlines()
    indent = min((len(l) - len(l.lstrip()) for l in lines if l.strip()), default=0)
    return "\n".join(l[indent:] for l in lines)


def resolve_fragment() -> str:
    """The shell from the SERVER_IP assignment up to (not including) the routing rule."""
    body = render(TPL.read_text())
    # Start at the validator definition when present (post-fix), otherwise at the
    # assignment itself (pre-fix), so the same extraction works either side.
    start = body.index("vh_is_ipv4()") if "vh_is_ipv4()" in body else body.index("SERVER_IP=$(")
    end = body.index("Per-user UUIDs", start)
    return dedent(body[start:end])


def run_with(curl_output: str, hostname_output: str = "10.0.0.5"):
    """Execute the resolution fragment with curl/jq/hostname stubbed."""
    import os
    import tempfile
    tmp = tempfile.mkdtemp()
    binp = Path(tmp) / "bin"; binp.mkdir()
    (binp / "curl").write_text(f"#!/usr/bin/env bash\nprintf '%s' {curl_output!r}\nexit 0\n")
    (binp / "jq").write_text("#!/usr/bin/env bash\ncat\nexit 0\n")
    (binp / "hostname").write_text(f"#!/usr/bin/env bash\nprintf '%s\\n' {hostname_output!r}\nexit 0\n")
    for f in binp.iterdir():
        f.chmod(0o755)
    script = resolve_fragment() + '\nprintf "RESOLVED=%s" "$SERVER_IP"\n'
    env = dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}")
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=30)


class ServerIpValidationTest(unittest.TestCase):
    def test_a_genuine_address_resolves(self):
        """Anchor: without this, every rejection assertion below passes vacuously."""
        p = run_with("203.0.113.10")
        self.assertIn("RESOLVED=203.0.113.10", p.stdout,
                      f"a valid public address was not resolved (rc={p.returncode}, {p.stderr[:200]})")

    def test_injection_payload_is_not_accepted(self):
        """A hostile third-party response must never reach the rendered config."""
        for payload in ['1.2.3.4","evil":"x', "1.2.3.4\ninjected", '$(id)', '1.2.3.4;id']:
            with self.subTest(payload=payload):
                p = run_with(payload)
                self.assertNotIn(
                    f"RESOLVED={payload}", p.stdout,
                    f"the raw third-party value {payload!r} became SERVER_IP and would be "
                    f"interpolated into config.json and the client URIs",
                )

    def test_malformed_response_does_not_yield_a_malformed_address(self):
        p = run_with("not-an-ip")
        m = re.search(r"RESOLVED=(.*)$", p.stdout, re.S)
        resolved = m.group(1).strip() if m else ""
        if resolved:
            self.assertRegex(
                resolved, r"^\d{1,3}(\.\d{1,3}){3}$",
                f"SERVER_IP resolved to a non-IPv4 value {resolved!r}",
            )

    def test_public_host_fallback_skips_the_mesh_address(self):
        """When every lookup is down, fall back to a PUBLIC host address, never the
        wg0 mesh IP (which would render a dead server address into the client URIs)."""
        p = run_with("no-usable-ip", hostname_output="10.99.0.2 203.0.113.7 fe80::1")
        self.assertIn("RESOLVED=203.0.113.7", p.stdout,
                      f"the public host address was not chosen (rc={p.returncode}, {p.stderr[:200]})")

    def test_private_only_host_yields_no_address(self):
        """A host with only private/mesh addresses must fail closed, not hand out one."""
        p = run_with("no-usable-ip", hostname_output="10.99.0.2 192.168.1.5")
        self.assertNotIn("RESOLVED=10.99.0.2", p.stdout)
        self.assertNotIn("RESOLVED=192.168.1.5", p.stdout)

    def test_every_consumer_is_downstream_of_the_guard(self):
        """The validation must dominate the config literal and the client URI."""
        body = render(TPL.read_text())
        lines = body.splitlines()
        guard = next(i for i, l in enumerate(lines)
                     if "SERVER_IP" in l and ("grep -qE" in l or "vh_is_ipv4" in l))
        for needle in ('"address": "$SERVER_IP"', "vless://$USER_UUID@$SERVER_IP"):
            idx = next(i for i, l in enumerate(lines) if needle in l)
            self.assertLess(
                guard, idx,
                f"the consumer at line {idx+1} ({needle}) precedes the validation at "
                f"line {guard+1}, so it receives the unvalidated value",
            )


if __name__ == "__main__":
    unittest.main()
