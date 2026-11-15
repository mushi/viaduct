"""The Grafana alert rules in grafana/ must alert on series that actually exist.

A rule on a renamed or never-published gauge evaluates to no data, which every rule here
treats as healthy (no_data_state = OK). It would therefore stay silent forever rather than
fail, so the names are checked against their sources.
"""

import json
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GRAFANA = REPO_ROOT / "grafana"
RULES = GRAFANA / "main.tf"
GUARDRAIL = REPO_ROOT / "aws" / "scripts" / "egress-guardrail.sh"


class GrafanaAlertRulesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = RULES.read_text()

    def test_every_aws_gauge_is_published_by_the_guardrail(self):
        gauges = set(re.findall(r"\b(aws_[a-z_]+)\{", self.text))
        self.assertGreaterEqual(len(gauges), 5, "anchor: the rules were not parsed")
        body = GUARDRAIL.read_text()
        for g in sorted(gauges):
            with self.subTest(gauge=g):
                self.assertRegex(body, rf"(?m)^{g} ", f"{g} is alerted on but never published")

    def test_aws_rules_are_scoped_to_the_aws_node(self):
        exprs = re.findall(r'(?m)^\s*expr\s*=\s*"(.*)"\s*$', self.text)
        selectors = [m for e in exprs for m in re.findall(r"\baws_[a-z_]+(\{[^}]*\})?", e)]
        self.assertGreaterEqual(len(selectors), 5, "anchor: no aws_* selectors found")
        for sel in selectors:
            self.assertEqual(sel, '{node=\\"aws\\"}', "an aws_* selector is missing node=\"aws\"")

    def test_rule_group_names_are_unique(self):
        """A rule group is written whole: two definitions of one name overwrite each other."""
        text = "\n".join(f.read_text() for f in sorted(GRAFANA.glob("*.tf")))
        names = re.findall(r'name = "([^"]+)", interval', text)
        names += re.findall(r'resource "grafana_rule_group"[^{]*\{\s*name\s*=\s*"([^"]+)"', text)
        self.assertGreaterEqual(len(names), 3, f"anchor: rule group names not found: {names}")
        self.assertEqual(len(names), len(set(names)), f"duplicate rule group names: {names}")

    def test_a_rule_that_alerts_on_no_data_queries_unfiltered(self):
        """NoData = Alerting plus a comparison inside the PromQL is an inverted alarm.

        The filter returns nothing while healthy, which NoData then reports as an outage:
        the dead man's switch fired continuously from 2026-07-06 for exactly this reason.
        The threshold belongs in the condition expression instead.
        """
        text = (GRAFANA / "alerting.tf").read_text()
        rules = re.split(r"(?m)^\s*rule \{", text)[1:]
        nodata_alerting = [r for r in rules if re.search(r'no_data_state\s*=\s*"Alerting"', r)]
        self.assertTrue(nodata_alerting, "anchor: the dead man's switch was not found")
        for r in nodata_alerting:
            for expr in re.findall(r'(?m)^\s*expr\s*=\s*"(.*)"\s*$', r):
                with self.subTest(expr=expr):
                    self.assertNotRegex(expr, r"(>|<|==|!=)(?!=)",
                                        "comparison inside the query of a NoData=Alerting rule")

    def test_only_the_dead_mans_switch_reports_query_errors(self):
        """A datasource timeout must not page once per rule.

        With exec_err_state = Error on every rule, a flaky Grafana Cloud datasource sent a
        DatasourceError per rule and re-fired a standing alert on each timeout (2026-10-20/21).
        Everything else keeps its last state; the dead man's switch alone reports blindness.
        """
        text = "\n".join(f.read_text() for f in sorted(GRAFANA.glob("*.tf")))
        states = re.findall(r'exec_err_state\s*=\s*"([^"]+)"', text)
        self.assertGreaterEqual(len(states), 2, "anchor: exec_err_state not found")
        self.assertEqual(states.count("Error"), 1, f"exactly one rule may report query errors: {states}")
        self.assertTrue(set(states) <= {"Error", "KeepLast"}, f"unexpected exec_err_state: {states}")
        dms = (GRAFANA / "alerting.tf").read_text()
        self.assertRegex(dms, r'exec_err_state\s*=\s*"Error"', "the dead man's switch must keep Error")

    def test_every_managed_dashboard_file_exists_and_is_classic_json(self):
        files = re.findall(r'=\s*"([a-z0-9-]+\.json)"', (GRAFANA / "dashboards.tf").read_text())
        self.assertGreaterEqual(len(files), 6, "anchor: dashboard map not parsed")
        for name in files:
            with self.subTest(dashboard=name):
                d = json.loads((GRAFANA / "dashboards" / name).read_text())
                self.assertIn("uid", d, "no uid: the import and URLs are keyed on it")
                self.assertNotIn("apiVersion", d, "v2 resource format; grafana_dashboard needs the classic model")
                self.assertNotIn("id", d, "instance-specific id left in; it causes perpetual drift")


if __name__ == "__main__":
    unittest.main()
