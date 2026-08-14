"""Security tests: VULN-039 and VULN-046 — the unauthenticated nginx :8443 surface.

VULN-039 (CWE-400): the /api location had no per-client connection or request limits and
no finite client header/body timeouts, while proxy_read_timeout was 86400s — so one
unauthenticated client could hold a worker for 24 hours, unboundedly many times.

VULN-046 (CWE-326): `ssl_ciphers HIGH:!aNULL:!MD5` still admits static-RSA key exchange
(no forward secrecy) and CBC suites.

The sink is the rendered nginx configuration, so these assertions parse the emitted
config block.
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


class ApiLimitsTest(unittest.TestCase):
    def setUp(self):
        self.conf = nginx_conf()
        self.loc = api_location()

    def test_zones_are_declared_in_http_context(self):
        """limit_*_zone must be at http level; conf.d is included there."""
        for directive in ("limit_conn_zone", "limit_req_zone"):
            self.assertIn(directive, self.conf,
                          f"{directive} is not declared, so the limits below cannot work")
            self.assertLess(
                self.conf.index(directive), self.conf.index("server {"),
                f"{directive} is declared inside a server block; nginx requires http context",
            )

    def test_per_client_connection_and_rate_limits_applied(self):
        self.assertIn("limit_conn ", self.loc,
                      "no per-client connection limit on the unauthenticated /api location")
        self.assertIn("limit_req ", self.loc,
                      "no per-client request-rate limit on the unauthenticated /api location")

    def test_finite_client_timeouts(self):
        # These are server-scope directives — nginx forbids them inside a location (doing so
        # makes `nginx -t` fail and nginx never starts), so they live in the server block and
        # cover the /api listener from there. Assert present and finite.
        conf = nginx_conf()
        for directive in ("client_header_timeout", "client_body_timeout"):
            m = re.search(rf"^\s*{directive}\s+(\S+?);", conf, re.M)
            self.assertIsNotNone(
                m, f"no {directive}: a slow-header or slow-body client can pin a worker")
            self.assertNotEqual(m.group(1), "0", f"{directive} is 0 (infinite)")

    def test_long_poll_upstream_timeout_is_retained_deliberately(self):
        """XHTTP is a long-poll transport; cutting this would break legitimate sessions."""
        self.assertIn("proxy_read_timeout", self.loc)


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
            "secrecy) and CBC suites",
        )

    def test_every_suite_is_ecdhe(self):
        for suite in self.ciphers.split(":"):
            suite = suite.strip()
            if not suite or suite.startswith("!"):
                continue
            self.assertTrue(
                suite.startswith("ECDHE-"),
                f"suite {suite!r} does not use ephemeral key exchange, so it provides no "
                f"forward secrecy",
            )

    def test_no_non_pfs_or_cbc_suite_named(self):
        self.assertIsNone(NO_PFS.search(self.ciphers),
                          f"a non-PFS or CBC suite is named: {self.ciphers}")

    def test_server_cipher_preference_is_enforced(self):
        self.assertRegex(
            self.conf, r"ssl_prefer_server_ciphers\s+on;",
            "without server preference the client chooses the suite, so the ordering "
            "above is advisory",
        )

    def test_tls_versions_unchanged(self):
        self.assertRegex(self.conf, r"ssl_protocols\s+TLSv1\.2\s+TLSv1\.3;",
                         "the TLS version set changed; that is a client-compatibility "
                         "decision, not part of this fix")


if __name__ == "__main__":
    unittest.main()
