"""nginx server-scope directives must not sit inside a `location` block.

`client_header_timeout` / `client_body_timeout` are valid only in http/server context.
Placed in a location, `nginx -t` fails with "directive is not allowed here" and nginx never
starts — which stranded the Hetzner node after the cert was already obtained (2026-08-14).
This tracks the block context of each such directive in the emitted site.conf.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TPL = (REPO_ROOT / "cloud-init.yaml.tpl").read_text()

# Directives nginx only allows in http/server context (not location).
SERVER_ONLY = ("client_header_timeout", "client_body_timeout")


def site_conf() -> str:
    m = re.search(r"cat > /etc/nginx/conf\.d/site\.conf <<'NGINX_CONF'\n(.*?)^\s*NGINX_CONF\s*$",
                  TPL, re.S | re.M)
    if not m:
        raise AssertionError("could not locate the site.conf heredoc in cloud-init.yaml.tpl")
    return m.group(1)


def directive_contexts(conf: str):
    """Yield (directive_line, innermost_block_keyword) for each directive line.

    Heuristic tuned to this well-formatted config: a block opener is a line ending in '{'
    (its first word is the block type), a closer is a bare '}'. `${...}` only appears on
    directive lines, so no brace-counting is needed.
    """
    stack = []
    for raw in conf.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == "}":
            if stack:
                stack.pop()
            continue
        opener = re.match(r"(\w+)[^{}]*\{$", line)
        if opener:
            stack.append(opener.group(1))
            continue
        yield line, (stack[-1] if stack else None)


class NginxContextTest(unittest.TestCase):
    def test_server_only_directives_are_not_in_a_location(self):
        found = {d: [] for d in SERVER_ONLY}
        for line, ctx in directive_contexts(site_conf()):
            for d in SERVER_ONLY:
                if line.split()[0] == d:
                    found[d].append(ctx)
                    self.assertNotEqual(
                        ctx, "location",
                        f"{d!r} is inside a location block — `nginx -t` rejects it and nginx "
                        f"will not start (context stack innermost = {ctx})")
        # Anchor: they must actually be present (and thus in server/http), or the test is vacuous.
        for d in SERVER_ONLY:
            self.assertTrue(found[d], f"{d!r} not found in site.conf at all")
            self.assertIn("server", found[d], f"{d!r} is not applied at server scope")


if __name__ == "__main__":
    unittest.main()
