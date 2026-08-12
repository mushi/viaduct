"""cloud-init.yaml.tpl must still be a parseable cloud-config document.

Three lines shipped to the main line sitting at column 0 inside `- |` literal
block scalars whose content indent is 4 (`$SELF_IP_RULE` from the VULN-038 fix,
and the two `limit_*_zone` directives from the VULN-039 fix). A line less indented
than the block terminates it, so the whole `#cloud-config` document stopped
parsing — a node booting that user-data installs no packages, writes no files and
registers no services. That is strictly worse than the findings being fixed, and
it reached main green because nothing in the suite ever parsed the YAML:
test_cloud_init_template_renders.py checks Terraform interpolation only.

Two layers here on purpose:

  * a structural check with no third-party dependency, which catches exactly this
    failure mode and therefore always runs; and
  * a real parse with PyYAML when it is importable (CI installs it via
    requirements.txt), which catches everything else.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TPL = REPO_ROOT / "cloud-init.yaml.tpl"

# Keys cloud-init reads at the document root. Any other line starting in column 0
# is inside some block scalar and silently ends it.
TOP_LEVEL = re.compile(r"^(#cloud-config$|[a-z_]+:)")


def rendered() -> str:
    """The template as templatefile() would render it, structurally speaking.

    Terraform escapes are undone and each `${var}` is replaced by a scalar-safe
    placeholder, so only the YAML structure is under test — not the values.
    """
    body = TPL.read_text().replace("$${", "${").replace("%%{", "%{")
    return re.sub(r"(?<!\$)\$\{[^}]*\}", "PLACEHOLDER", body)


def column_zero_offenders(text: str):
    """Lines at column 0 that are neither a comment nor a top-level key."""
    return [
        (n, line)
        for n, line in enumerate(text.splitlines(), 1)
        if line and not line[0].isspace()
        and not line.startswith("#")
        and not TOP_LEVEL.match(line)
    ]


class StructuralTest(unittest.TestCase):
    """No dependency, so this layer can never be skipped."""

    def test_no_line_terminates_its_block_scalar(self):
        offenders = column_zero_offenders(TPL.read_text())
        self.assertEqual(
            offenders, [],
            "these lines start in column 0 inside a block scalar, which ends it and "
            "breaks the whole cloud-config document — indent them to the enclosing "
            f"block's content indent: {[(n, l[:60]) for n, l in offenders]}")

    def test_the_check_can_actually_fail(self):
        """Anchor: a checker that never fires would have passed on the broken file."""
        broken = TPL.read_text().replace(
            '            $SELF_IP_RULE', '$SELF_IP_RULE', 1)
        self.assertNotEqual(
            column_zero_offenders(broken), [],
            "the structural check did not flag a deliberately de-indented line, so "
            "it would not have caught the bug it exists for")


class ParseTest(unittest.TestCase):
    """Full parse — the authoritative check when PyYAML is available."""

    @classmethod
    def setUpClass(cls):
        try:
            import yaml  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("PyYAML not installed (see requirements.txt)")
        cls.yaml = yaml
        cls.doc = yaml.safe_load(rendered())

    def test_document_is_a_cloud_config_mapping(self):
        self.assertIsInstance(self.doc, dict)
        for key in ("packages", "users", "write_files", "runcmd"):
            self.assertIn(key, self.doc, f"cloud-config lost its {key!r} section")

    def test_the_nginx_rate_limits_reach_the_node(self):
        """VULN-039's controls are inert if they do not survive into runcmd."""
        blocks = [r for r in self.doc["runcmd"] if isinstance(r, str)]
        site = next((b for b in blocks if "nginx/conf.d/site.conf" in b), None)
        self.assertIsNotNone(site, "the nginx site.conf runcmd block is gone")
        for directive in ("limit_conn_zone", "limit_req_zone", "limit_conn ", "limit_req "):
            self.assertIn(directive, site,
                          f"{directive.strip()} is not in the rendered site.conf")
        self.assertIn("NGINX_CONF", site.splitlines(),
                      "the heredoc terminator is not at column 0 of the rendered "
                      "script, so the config would swallow the rest of the block")

    def test_the_self_ip_rule_stays_inside_the_xray_config(self):
        """VULN-038's rule must land in the config.json heredoc, not at root."""
        setup = next(
            (w["content"] for w in self.doc["write_files"]
             if w.get("path", "").endswith("xray-setup.sh") and w.get("content")), None)
        self.assertIsNotNone(setup, "xray-setup.sh is no longer written")
        self.assertIn("$SELF_IP_RULE", setup,
                      "the self-address block rule left xray-setup.sh")


if __name__ == "__main__":
    unittest.main()
