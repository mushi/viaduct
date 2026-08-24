"""The nginx :8443 TLS suite must be ECDHE-only, and the /api path must NOT impose
per-client limits.

`ssl_ciphers HIGH:!aNULL:!MD5` still admits static-RSA key exchange (no forward secrecy)
and CBC suites. Naming the ECDHE AEAD suites explicitly removes those; TLS 1.3 selection
is unaffected (ssl_ciphers governs only TLS <= 1.2), and every client the deployment
issues links for (XHTTP with fp=chrome) offers one of these.

Deliberately NOT hardened: per-IP connection/request limits. This is the
censorship-circumvention data path, and its users are commonly behind carrier-grade NAT
(many users share one source IP), so a per-`$binary_remote_addr` limit would throttle
legitimate traffic rather than only abuse. This file pins that decision so it is not
silently reversed.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TPL = REPO_ROOT / "cloud-init.yaml.tpl"

# Suites that provide no forward secrecy, or use CBC.
NO_PFS = re.compile(r"\b(AES\d+-(GCM-)?SHA|DES-CBC3|RC4|NULL)\b")


def nginx_conf() -> str:
    body = TPL.read_text()
    m = re.search(r"cat > /etc/nginx/conf\.d/site\.conf <<'NGINX_CONF'\n(.*?)^\s*NGINX_CONF\s*$",
                  body, re.S | re.M)
    if not m:
        raise AssertionError("could not locate the nginx site.conf heredoc")
    return m.group(1)


def api_location() -> str:
    conf = nginx_conf()
    start = conf.index("location /api")
    depth, i = 0, start
    while i < len(conf):
        if conf[i] == "{":
            depth += 1
        elif conf[i] == "}":
            depth -= 1
            if depth == 0:
                return conf[start:i + 1]
        i += 1
    raise AssertionError("unterminated /api location block")


class TlsSuiteTest(unittest.TestCase):
    def setUp(self):
        self.conf = nginx_conf()
        m = re.search(r"ssl_ciphers\s+([^;]+);", self.conf)
        self.assertIsNotNone(m, "ssl_ciphers is no longer set")
        self.ciphers = m.group(1).strip()

    def test_not_the_blanket_high_alias(self):
        self.assertNotIn(
            "HIGH", self.ciphers,
            "ssl_ciphers still uses the HIGH alias, which admits static-RSA (no forward "
            "secrecy) and CBC suites")

    def test_every_suite_is_ecdhe(self):
        for suite in self.ciphers.split(":"):
            suite = suite.strip()
            if not suite or suite.startswith("!"):
                continue
            self.assertTrue(suite.startswith("ECDHE-"),
                            f"suite {suite!r} does not use ephemeral key exchange (no PFS)")

    def test_no_non_pfs_or_cbc_suite_named(self):
        self.assertIsNone(NO_PFS.search(self.ciphers),
                          f"a non-PFS or CBC suite is named: {self.ciphers}")

    def test_server_cipher_preference_is_enforced(self):
        self.assertRegex(self.conf, r"ssl_prefer_server_ciphers\s+on;",
                         "without server preference the client chooses the suite")

    def test_tls_versions_unchanged(self):
        self.assertRegex(self.conf, r"ssl_protocols\s+TLSv1\.2\s+TLSv1\.3;",
                         "the TLS version set changed; that is a client-compatibility "
                         "decision, not part of this change")


class NoPerClientLimitsTest(unittest.TestCase):
    """The data path must not throttle legitimate CGNAT users. Pin the deliberate absence
    of per-IP limits so a well-meaning change does not reintroduce them."""

    def test_no_connection_or_request_rate_limits(self):
        conf = nginx_conf()
        for directive in ("limit_conn", "limit_req", "limit_conn_zone", "limit_req_zone"):
            self.assertNotIn(
                directive, conf,
                f"{directive} is back on the :8443 data path: per-$binary_remote_addr "
                f"limits collateral-damage users sharing a carrier-grade-NAT egress IP")

    def test_long_poll_upstream_timeout_is_retained(self):
        """XHTTP is a long-poll transport; cutting proxy_read_timeout breaks real sessions."""
        self.assertIn("proxy_read_timeout", api_location(),
                      "the long-poll upstream timeout was dropped from /api")


if __name__ == "__main__":
    unittest.main()
