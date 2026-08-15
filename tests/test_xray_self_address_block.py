"""Security test: VULN-038 — the Xray routing blocklist must include the node's own address.

CWE-441. The blocklist denies RFC-1918, loopback and link-local, so the intent is that
proxied traffic must not reach this node's own surfaces. The public address was the one
route back in that the list missed: an authenticated client could dial it and reach the
node's :80 / :8443 as though from outside, using the proxy as a confused deputy.

The rule is emitted by xray-setup.sh at runtime, since the public address is discovered
there. These tests execute the emitted fragment to confirm both the success and the
lookup-failure paths.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TPL = REPO_ROOT / "cloud-init.yaml.tpl"


def render(body: str) -> str:
    return body.replace("$${", "${").replace("%%{", "%{")


def self_rule_fragment() -> str:
    """The shell that builds SELF_IP_RULE, dedented for execution."""
    body = TPL.read_text()
    start = body.index('SELF_IP_RULE=""')
    end = body.index("fi", body.index("else", start)) + 2
    frag = body[start:end]
    lines = [l for l in frag.splitlines()]
    indent = min((len(l) - len(l.lstrip()) for l in lines if l.strip()), default=0)
    return "\n".join(l[indent:] for l in lines)


def ipv6_rule_fragment() -> str:
    """The shell that discovers the node's global IPv6 and builds SELF_IP6_RULE."""
    lines = render(TPL.read_text()).splitlines()
    start = next(i for i, l in enumerate(lines) if "SERVER_IPV6=$(ip -6" in l)
    end = next(i for i in range(start, len(lines)) if lines[i].strip() == "fi")
    frag = lines[start:end + 1]
    indent = min(len(l) - len(l.lstrip()) for l in frag if l.strip())
    return "\n".join(l[indent:] for l in frag)


def build_rule(server_ip: str) -> str:
    script = f'SERVER_IP={server_ip!r}\n' + self_rule_fragment() + '\nprintf "%s" "$SELF_IP_RULE"\n'
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True).stdout


def build_ipv6_rule(ip_show_output: str) -> str:
    """Run the real fragment with a stubbed `ip` emitting the given `ip -6 addr show`."""
    with tempfile.TemporaryDirectory() as tmp:
        binp = Path(tmp) / "bin"; binp.mkdir()
        (binp / "ip").write_text("#!/usr/bin/env bash\ncat <<'OUT'\n" + ip_show_output + "\nOUT\n")
        (binp / "ip").chmod(0o755)
        env = dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}")
        script = ipv6_rule_fragment() + '\nprintf "%s" "$SELF_IP6_RULE"\n'
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env).stdout


class SelfAddressBlockTest(unittest.TestCase):
    def test_public_address_is_blocked(self):
        out = build_rule("203.0.113.10")
        self.assertIn("203.0.113.10/32", out,
                      "the node's own public address is not added to the routing blocklist")
        self.assertIn('"outboundTag": "block"', out,
                      "the self-address rule does not route to the block outbound")

    def test_rule_is_placed_in_the_routing_rules(self):
        body = TPL.read_text()
        routing = body[body.index('"routing"'):]
        self.assertIn("$SELF_IP_RULE", routing[:800],
                      "the self-address rule is never interpolated into the routing rules")

    def test_failed_lookup_emits_no_rule_rather_than_a_broken_one(self):
        """An empty SERVER_IP must not render "/32" and break Xray's config parse."""
        for bad in ["", "not-an-ip", "1.2.3"]:
            with self.subTest(bad=bad):
                out = build_rule(bad)
                self.assertEqual(out.strip(), "",
                                 f"a malformed SERVER_IP {bad!r} produced a routing rule: {out!r}")
                self.assertNotIn("/32", out)

    def test_existing_private_blocks_are_retained(self):
        body = TPL.read_text()
        self.assertIn('"10.0.0.0/8"', body, "the RFC-1918 block was lost")
        self.assertIn('"127.0.0.0/8"', body, "the loopback block was lost")


class SelfAddressIpv6BlockTest(unittest.TestCase):
    """VULN-038 (IPv6 half): Hetzner assigns a routable global v6 by default, so the
    node's own v6 must be blocked too, or a VLESS user could dial [<node-v6>]:22."""

    def test_global_ipv6_is_blocked_as_a_128(self):
        out = build_ipv6_rule("    inet6 2a01:4f8:1:2::3/64 scope global\n"
                              "    inet6 fe80::1/64 scope link")
        self.assertIn("2a01:4f8:1:2::3/128", out,
                      "the node's own global IPv6 is not added to the routing blocklist")
        self.assertIn('"outboundTag": "block"', out,
                      "the self-IPv6 rule does not route to the block outbound")

    def test_no_global_ipv6_emits_no_rule(self):
        """A node with no global v6: `ip -6 addr show scope global` returns nothing, so no
        rule must render (not a broken "/128")."""
        out = build_ipv6_rule("")
        self.assertEqual(out.strip(), "",
                         f"a node without a global IPv6 still produced a rule: {out!r}")
        self.assertNotIn("/128", out)

    def test_rule_is_interpolated_into_the_routing_rules(self):
        routing = TPL.read_text()
        routing = routing[routing.index('"routing"'):]
        self.assertIn("$SELF_IP6_RULE", routing[:2000],
                      "the self-IPv6 rule is never interpolated into the routing rules")


if __name__ == "__main__":
    unittest.main()
