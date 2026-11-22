"""No secret reaches the server through user_data.

user_data is served back verbatim by the metadata service to anything running on the
box, and by the hcloud API to any holder of a project token. Secrets are rendered into
backups/ and uploaded by the provisioner instead. The Cloudflare token is the one that
has to arrive before nginx can start, since certbot needs it for the first certificate.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MAIN = (REPO_ROOT / "main.tf").read_text()
VARIABLES = (REPO_ROOT / "variables.tf").read_text()
TPL = (REPO_ROOT / "cloud-init.yaml.tpl").read_text()
PROVISION = (REPO_ROOT / "scripts" / "provision.sh").read_text()


def block(body: str, header: str) -> str:
    """The brace-balanced block that starts at `header`."""
    start = body.index(header)
    depth = 0
    for i in range(body.index("{", start), len(body)):
        if body[i] == "{":
            depth += 1
        elif body[i] == "}":
            depth -= 1
            if depth == 0:
                return body[start:i + 1]
    raise AssertionError(f"unbalanced block: {header}")


def sensitive_variables() -> set:
    names = set()
    for m in re.finditer(r'^variable "([a-z0-9_]+)" \{', VARIABLES, re.M):
        if re.search(r"^\s*sensitive\s*=\s*true", block(VARIABLES, m.group(0)), re.M):
            names.add(m.group(1))
    return names


def provision_step(title_re: str) -> str:
    m = re.search(rf"^# ── {title_re}.*$", PROVISION, re.M)
    assert m, title_re
    nxt = re.search(r"^# ── ", PROVISION[m.end():], re.M)
    return PROVISION[m.start(): m.end() + (nxt.start() if nxt else len(PROVISION))]


class UserDataTest(unittest.TestCase):
    def test_sensitive_variables_found(self):
        self.assertIn("cloudflare_api_token", sensitive_variables())

    def test_no_sensitive_variable_rendered_into_user_data(self):
        cloudinit = block(MAIN, 'data "cloudinit_config" "conduit"')
        for name in sorted(sensitive_variables()):
            self.assertNotIn(f"var.{name}", cloudinit,
                             f"{name} is sensitive but is rendered into user_data")

    def test_template_holds_no_cloudflare_credential(self):
        self.assertNotIn("cloudflare_api_token", TPL)
        self.assertNotIn("/etc/cloudflare-certbot.ini", TPL)

    def test_boot_does_not_need_the_certificate(self):
        # Without the token at boot there is no certificate yet: issuing one, or an
        # `nginx -t` against the 8443 server block, belongs to the provisioner.
        self.assertNotIn("certbot certonly", TPL)
        self.assertNotRegex(TPL, r"(?m)^\s*-\s*nginx -t\s*$")


class ProvisionerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.step = provision_step(r"6b\. Cloudflare credentials")

    def test_credentials_rendered_as_private_local_file(self):
        res = block(MAIN, 'resource "local_sensitive_file" "cloudflare_ini"')
        self.assertIn('file_permission = "0600"', res)
        self.assertIn("var.cloudflare_api_token", res)
        self.assertIn("/backups/", res)

    def test_token_change_reprovisions(self):
        triggers = block(block(MAIN, 'resource "null_resource" "provision"'), "triggers")
        self.assertIn("local_sensitive_file.cloudflare_ini", triggers)

    def test_provisioner_gets_path_not_token(self):
        env = block(block(MAIN, 'resource "null_resource" "provision"'), "environment")
        self.assertIn("CF_INI", env)
        self.assertNotIn("cloudflare_api_token", env)

    def test_credentials_uploaded_root_only(self):
        self.assertRegex(self.step, r'upload "\$CF_INI" "/etc/cloudflare-certbot\.ini" "600"')

    def test_certificate_issued_only_when_missing(self):
        guard = self.step.index('if ! remote test -d "/etc/letsencrypt/live/${VLESS_DOMAIN}"')
        issue = self.step.index("remote certbot certonly --dns-cloudflare")
        self.assertLess(guard, issue)
        self.assertIn("--dns-cloudflare-credentials /etc/cloudflare-certbot.ini", self.step)

    def test_nginx_config_checked_after_certificate(self):
        self.assertLess(self.step.index("certbot certonly"), self.step.index("remote nginx -t"))

    def test_step_runs_before_services_start(self):
        self.assertLess(PROVISION.index(self.step), PROVISION.index("# ── 8. Start / restart all services"))


if __name__ == "__main__":
    unittest.main()
