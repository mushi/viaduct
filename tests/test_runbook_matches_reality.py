"""The runbook has to stay executable without looking anything up.

It now carries the operational consequences of the 46-finding remediation: the
commands that unstick a fail-closed apply, the pins to refresh, the gauges to alert
on, and the two wrapped commands the `ops` account has left. Every one of those is
a claim about code elsewhere in the repo, and a runbook whose commands have quietly
stopped matching is worse than no runbook — an operator follows it under pressure.

These assert the claims against their sources. They are cheap and they fail loudly
the moment a rename drifts.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNBOOK = REPO_ROOT / "docs" / "RUNBOOK.md"
TPL = REPO_ROOT / "cloud-init.yaml.tpl"
GUARDRAIL = REPO_ROOT / "aws" / "scripts" / "egress-guardrail.sh"
GUARDS = REPO_ROOT / "scripts" / "lib" / "provision-guards.sh"
PROVISION = REPO_ROOT / "scripts" / "provision.sh"
CHECKSUMS = REPO_ROOT / "scripts" / "get-checksums.sh"
ALLOY = REPO_ROOT / "aws" / "k8s" / "20-alloy.yaml"
GCP_STARTUP = REPO_ROOT / "gcp" / "scripts" / "startup.sh"
ROOT_VARS = REPO_ROOT / "variables.tf"
AWS_VARS = REPO_ROOT / "aws" / "variables.tf"


class RunbookTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = RUNBOOK.read_text()

    def test_it_was_read(self):
        """Anchor: an empty file would satisfy every assertNotIn below."""
        self.assertGreater(len(self.text), 5000)
        for heading in ("## If an apply or boot stops", "## Routine maintenance",
                        "## Alerts to configure", "## Day-to-day on the Hetzner node"):
            self.assertIn(heading, self.text, f"{heading} is missing")

    def test_the_host_key_reset_variable_exists(self):
        self.assertIn("VIADUCT_HOST_KEY_RESET=1", self.text)
        self.assertIn("VIADUCT_HOST_KEY_RESET",
                      PROVISION.read_text() + GUARDS.read_text(),
                      "the runbook names an env var no script reads")

    def test_every_alert_gauge_is_actually_emitted(self):
        body = GUARDRAIL.read_text()
        for gauge in re.findall(r"`(aws_[a-z_]+)\s*==", self.text):
            with self.subTest(gauge=gauge):
                self.assertIn(gauge, body,
                              f"the runbook tells the operator to alert on {gauge}, "
                              f"which the guardrail never publishes")

    def test_every_pin_named_is_a_real_variable_in_the_file_it_names(self):
        root_block = self.text[self.text.index("## Routine maintenance"):]
        root_block = root_block[: root_block.index("## Alerts")]
        aws_pins = ("k3s_installer_sha256", "awscli_zip_sha256", "awscli_version")
        for pin in re.findall(r"`([a-z0-9_]+_(?:sha256|version))`", root_block):
            with self.subTest(pin=pin):
                src = AWS_VARS if pin in aws_pins else ROOT_VARS
                self.assertIn(f'variable "{pin}"', src.read_text(),
                              f"{pin} is not declared in {src.name}")

    def test_get_checksums_prints_every_pin_the_runbook_promises(self):
        """The runbook says the script prints them all; make that true."""
        printed = CHECKSUMS.read_text()
        block = self.text[self.text.index("## Routine maintenance"):]
        block = block[: block.index("## Alerts")]
        for pin in re.findall(r"`([a-z0-9_]+_(?:sha256|version))`", block):
            with self.subTest(pin=pin):
                self.assertRegex(printed, rf'echo "{pin}\s*=',
                                 f"get-checksums.sh does not print {pin}")

    def test_the_ops_unit_allowlist_matches_the_wrapper(self):
        m = re.search(r'ALLOWED="([^"]+)"', TPL.read_text())
        self.assertIsNotNone(m, "the ops-journal allowlist vanished")
        for unit in m.group(1).split():
            with self.subTest(unit=unit):
                self.assertIn(unit, self.text,
                              f"unit {unit} is accepted by ops-journal but the runbook "
                              f"does not list it, so an operator cannot know to use it")

    def test_the_ops_commands_exist(self):
        tpl = TPL.read_text()
        for cmd in ("ops-journal", "ops-wg-status"):
            with self.subTest(cmd=cmd):
                self.assertIn(f"sudo {cmd}", self.text)
                self.assertIn(f"- path: /usr/local/bin/{cmd}", tpl,
                              f"the runbook documents {cmd}, which is never installed")

    def test_the_port_forward_target_matches_the_manifest(self):
        self.assertIn("port-forward deploy/alloy 12345:12345", self.text)
        self.assertRegex(ALLOY.read_text(), r"metadata: \{ name: alloy, namespace: viaduct \}",
                         "the runbook port-forwards deploy/alloy in namespace viaduct")
        self.assertIn("--server.http.listen-addr=127.0.0.1:12345", ALLOY.read_text(),
                      "the runbook says the UI is loopback-only; the manifest disagrees")

    def test_the_audit_log_path_matches(self):
        self.assertIn("/var/log/vault/audit.log", self.text)
        self.assertIn("/var/log/vault/audit.log", GCP_STARTUP.read_text())

    def test_the_fail_closed_messages_are_real_strings(self):
        """Each row tells the operator to match a message. It has to be emitted."""
        sources = "".join(p.read_text() for p in
                          (TPL, GCP_STARTUP, PROVISION, GUARDS,
                           REPO_ROOT / "scripts" / "fetch-hetzner-secrets.sh"))
        for phrase in ("already registered with a different public key",
                       "already registered to peer",
                       "does not contain a UUID",
                       "could not determine a public IPv4"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, self.text, f"{phrase!r} left the runbook")
                self.assertIn(phrase, sources,
                              f"the runbook tells the operator to match {phrase!r}, "
                              f"which nothing emits any more")


if __name__ == "__main__":
    unittest.main()
