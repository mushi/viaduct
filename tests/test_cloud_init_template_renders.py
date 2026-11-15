"""cloud-init.yaml.tpl must stay renderable by templatefile().

The file is two languages at once: Terraform template syntax on the outside, bash on
the inside. Both spell expansion `${...}`, and Terraform wins — an unescaped shell
expansion like `${1:-}` or `${line#PREFIX=}` is read as an HCL expression and fails
the render, which takes down `terraform apply` for the whole module rather than
producing a bad node.

Escaping (`$${...}`) is easy to forget when editing the embedded scripts, and nothing
else in the test suite would catch it: every other test reads the template as text,
where an unescaped expansion looks perfectly fine. So assert directly that every
interpolation the template performs names a variable the call site actually passes.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TPL = REPO_ROOT / "cloud-init.yaml.tpl"
MAIN = REPO_ROOT / "main.tf"

# `${ ... }` not preceded by a second `$` — i.e. what Terraform will interpolate.
INTERPOLATION = re.compile(r"(?<!\$)\$\{([^}]*)\}")


def declared_template_vars() -> set:
    """The keys of the templatefile() map in main.tf that renders this template."""
    body = MAIN.read_text()
    start = body.index('templatefile("${path.module}/cloud-init.yaml.tpl", {')
    block = body[start:]
    block = block[: block.index("\n    })")]
    return set(re.findall(r"^\s*([a-z0-9_]+)\s*=", block, re.M))


class CloudInitTemplateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.body = TPL.read_text()
        cls.declared = declared_template_vars()

    def test_the_call_site_was_actually_parsed(self):
        """Anchor: an empty variable set would make every check below vacuous."""
        self.assertIn("conduit_version", self.declared)
        self.assertGreater(len(self.declared), 15,
                           f"only parsed {sorted(self.declared)} from main.tf")

    def test_every_interpolation_names_a_declared_variable(self):
        unknown = []
        for m in INTERPOLATION.finditer(self.body):
            expr = m.group(1)
            line = self.body[: m.start()].count("\n") + 1
            name = re.fullmatch(r"base64encode\(([a-z0-9_]+)\)", expr)
            name = name.group(1) if name else expr
            if name not in self.declared:
                unknown.append((line, expr))
        self.assertEqual(
            unknown, [],
            "these interpolations do not name a templatefile() variable, so the "
            "render fails — a shell expansion inside the embedded scripts needs to "
            f"be written $${{...}}: {unknown}",
        )

    def test_shell_expansions_in_embedded_scripts_are_escaped(self):
        """Spot-check the specific idioms that bit us: $${1:-} and $${var#PREFIX}."""
        for idiom in ('$${1:-}', '$${kp_line#PRIVATE_KEY=}'):
            self.assertIn(idiom, self.body,
                          f"{idiom} is no longer escaped in the embedded scripts")


if __name__ == "__main__":
    unittest.main()
