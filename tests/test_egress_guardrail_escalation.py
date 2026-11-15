"""VULN-036 — the guardrail's action at the cap is reachable by an outsider.

Egress through the Conduit proxy is unauthenticated, so the guardrail's action at the cap
is an availability control an external party can aim at the node. It used to end in
`ec2 stop-instances`, taking SPIRE, the mesh and monitoring down with Conduit and leaving
nothing on the box to bring them back. Conduit is ~95% of the node's egress, so the action
at the cap is now to pause Conduit alone, and the guardrail resumes it itself:

    below WARN           release any throttle
    WARN..CAP            shape the interface, alert, keep serving
    above CAP once       shape and alert — one reading is not a trend
    above CAP twice      pause Conduit (scale to 0, marked as the guardrail's)
    valid and under CAP  resume Conduit, but only a pause the guardrail made

These run the real script with the AWS CLI, IMDS, `tc` and `k3s kubectl` stubbed, and
assert on the commands actually issued.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GUARDRAIL = REPO_ROOT / "aws" / "scripts" / "egress-guardrail.sh"

GB = 1_000_000_000
OWNER = "egress-guardrail"


class GuardrailHarness(unittest.TestCase):
    def run_guardrail(self, mtd, prev=None, already_throttled=False,
                      annotation=None, k3s_up=True):
        """mtd in bytes, or None for an unreadable CloudWatch response.

        `already_throttled` pre-installs the shaper and `annotation` pre-marks the Conduit
        deployment: both are state a run inherits from earlier ones. `k3s_up=False` makes
        every kubectl call fail, as at boot before k3s is ready.
        """
        tmp = Path(tempfile.mkdtemp())
        binp = tmp / "bin"; binp.mkdir()
        calls = tmp / "calls.log"
        ann = tmp / "annotation"
        if annotation is not None:
            ann.write_text(annotation)

        value = "None" if mtd is None else str(mtd)
        (binp / "aws").write_text(
            f'#!/usr/bin/env bash\n'
            f'echo "aws $*" >> "{calls}"\n'
            f'case "$*" in *get-metric-statistics*) printf "%s\\n" "{value}" ;; esac\n'
            f'exit 0\n')
        (binp / "curl").write_text('#!/usr/bin/env bash\nprintf "stub"\nexit 0\n')
        (binp / "ip").write_text(
            '#!/usr/bin/env bash\necho "default via 10.0.0.1 dev eth0 proto dhcp"\nexit 0\n')
        (binp / "tc").write_text(
            f'#!/usr/bin/env bash\n'
            f'echo "tc $*" >> "{calls}"\n'
            f'if [ "$1" = "qdisc" ] && [ "$2" = "show" ]; then\n'
            f'  [ -f "{tmp}/qdisc" ] && echo "qdisc htb 1: root refcnt 2"\n'
            f'  exit 0\n'
            f'fi\n'
            f'[ "$1" = "qdisc" ] && [ "$2" = "replace" ] && touch "{tmp}/qdisc"\n'
            f'[ "$1" = "qdisc" ] && [ "$2" = "del" ] && rm -f "{tmp}/qdisc"\n'
            f'exit 0\n')
        # `k3s kubectl` keeps the deployment's pause annotation in a file, so a run sees
        # the state an earlier run (or a person) left behind.
        (binp / "k3s").write_text(
            f'#!/usr/bin/env bash\n'
            f'echo "k3s $*" >> "{calls}"\n'
            f'{"" if k3s_up else "exit 1"}\n'
            f'case "$*" in\n'
            f'  *" get deploy conduit "*) [ -f "{ann}" ] && cat "{ann}" ;;\n'
            f'  *" annotate "*"viaduct-paused-by-"*) rm -f "{ann}" ;;\n'
            f'  *" annotate "*"viaduct-paused-by="*) printf "%s" "${{@: -1}}" | cut -d= -f2 > "{ann}" ;;\n'
            f'esac\n'
            f'exit 0\n')
        for f in binp.iterdir():
            f.chmod(0o755)

        body = GUARDRAIL.read_text()
        body = body.replace("TXTDIR=/var/lib/viaduct-textfile", f'TXTDIR="{tmp}/txt"')
        body = body.replace("STATEDIR=/var/lib/viaduct-guardrail", f'STATEDIR="{tmp}/state"')

        if already_throttled:
            (tmp / "qdisc").touch()
        if prev is not None:
            (tmp / "state").mkdir(exist_ok=True)
            (tmp / "state" / "last").write_text(f"{prev[0]} {prev[1]}\n")

        p = subprocess.run(["bash", "-c", body], capture_output=True, text=True,
                           timeout=60, stdin=subprocess.DEVNULL,
                           env=dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}"))
        log = calls.read_text() if calls.exists() else ""
        p.calls = log
        p.throttled = "qdisc replace" in log
        p.released = "qdisc del" in log
        p.paused = "--replicas=0" in log
        p.resumed = "--replicas=1" in log
        p.stopped = "stop-instances" in log
        p.annotation = ann.read_text().strip() if ann.exists() else None
        prom = tmp / "txt" / "egress.prom"
        p.metrics = prom.read_text() if prom.exists() else ""
        return p

    def gauge(self, metrics, name):
        for line in metrics.splitlines():
            if line.startswith(name + " "):
                return line.split()[1]
        return None


class EscalationLadderTest(GuardrailHarness):
    def test_normal_usage_neither_throttles_nor_pauses(self):
        """Anchor: the guardrail must be quiet in the ordinary case."""
        p = self.run_guardrail(10 * GB)
        self.assertEqual(p.returncode, 0, p.stderr[-300:])
        self.assertFalse(p.throttled, "throttled at 10 GB")
        self.assertFalse(p.paused, "paused Conduit at 10 GB")
        self.assertEqual(self.gauge(p.metrics, "aws_egress_throttled"), "0")
        self.assertEqual(self.gauge(p.metrics, "aws_conduit_paused"), "0")

    def test_crossing_warn_throttles_instead_of_pausing(self):
        p = self.run_guardrail(70 * GB)
        self.assertTrue(p.throttled, f"no shaper installed at 70 GB: {p.calls}")
        self.assertFalse(p.paused, "paused Conduit before the cap was reached")
        self.assertEqual(self.gauge(p.metrics, "aws_egress_throttled"), "1")

    def test_first_reading_over_the_cap_does_not_pause(self):
        """The filed vector: one aggregate reading must not be an off switch."""
        p = self.run_guardrail(95 * GB, prev=(70 * GB, 0))
        self.assertFalse(p.paused, "a single over-cap reading paused Conduit")
        self.assertTrue(p.throttled, "the over-cap reading did not even throttle")

    def test_two_consecutive_over_cap_readings_pause_conduit(self):
        """Anchor: the guardrail must still protect the budget."""
        p = self.run_guardrail(97 * GB, prev=(95 * GB, 1))
        self.assertTrue(p.paused, f"sustained over-cap egress no longer pauses Conduit: {p.calls}")
        self.assertEqual(p.annotation, OWNER, "the pause was not marked as the guardrail's own")
        self.assertEqual(self.gauge(p.metrics, "aws_conduit_paused"), "1")

    def test_the_instance_is_never_stopped(self):
        """Stopping the instance took SPIRE, the mesh and monitoring down with Conduit."""
        p = self.run_guardrail(97 * GB, prev=(95 * GB, 1))
        self.assertFalse(p.stopped, f"the guardrail still stops the instance: {p.calls}")

    def test_an_existing_pause_is_not_reissued(self):
        p = self.run_guardrail(98 * GB, prev=(97 * GB, 1), annotation=OWNER)
        self.assertFalse(p.paused, "re-scaled an already paused Conduit on every run")
        self.assertEqual(self.gauge(p.metrics, "aws_conduit_paused"), "1")

    def test_falling_back_under_warn_releases_the_throttle(self):
        p = self.run_guardrail(5 * GB, prev=(95 * GB, 1), already_throttled=True)
        self.assertTrue(p.released, f"the shaper was never released: {p.calls}")
        self.assertFalse(p.paused, "paused on a reading well under the cap")


class ResumeTest(GuardrailHarness):
    def test_a_new_month_resumes_a_guardrail_pause(self):
        """The guardrail undoes its own pause; nothing outside the box is needed."""
        p = self.run_guardrail(2 * GB, prev=(97 * GB, 1), annotation=OWNER)
        self.assertTrue(p.resumed, f"Conduit was not resumed under the cap: {p.calls}")
        self.assertIsNone(p.annotation, "the pause marker was left behind after resuming")
        self.assertEqual(self.gauge(p.metrics, "aws_conduit_paused"), "0")

    def test_a_manual_scale_down_is_never_undone(self):
        """Without the guardrail's marker, a scaled-down Conduit is someone's decision."""
        p = self.run_guardrail(2 * GB, prev=(1 * GB, 0))
        self.assertFalse(p.resumed, f"scaled up a Conduit the guardrail did not pause: {p.calls}")

    def test_a_pause_by_someone_else_is_never_undone(self):
        p = self.run_guardrail(2 * GB, prev=(1 * GB, 0), annotation="operator")
        self.assertFalse(p.resumed, "resumed a pause marked as someone else's")


class RateOfChangeTest(GuardrailHarness):
    def test_an_implausible_jump_does_not_pause(self):
        """A 40 GB jump in one window exceeds what this instance can emit."""
        p = self.run_guardrail(95 * GB, prev=(55 * GB, 1))
        self.assertFalse(p.paused, "a single implausible CloudWatch delta paused Conduit")
        self.assertEqual(self.gauge(p.metrics, "aws_mtd_egress_reading_plausible"), "0")

    def test_a_plausible_delta_is_reported_as_such(self):
        p = self.run_guardrail(70 * GB, prev=(65 * GB, 0))
        self.assertEqual(self.gauge(p.metrics, "aws_mtd_egress_reading_plausible"), "1")
        self.assertEqual(self.gauge(p.metrics, "aws_mtd_egress_delta_bytes"), str(5 * GB))

    def test_a_month_rollover_is_not_a_negative_delta(self):
        p = self.run_guardrail(2 * GB, prev=(95 * GB, 1))
        self.assertEqual(self.gauge(p.metrics, "aws_mtd_egress_delta_bytes"), "0")
        self.assertFalse(p.paused)


class Vuln026BehaviourPreservedTest(GuardrailHarness):
    """Anchor: the earlier finding's fix must not regress."""

    def test_an_unreadable_reading_neither_pauses_nor_resumes(self):
        p = self.run_guardrail(None, prev=(95 * GB, 1), annotation=OWNER)
        self.assertFalse(p.paused, "a CloudWatch outage paused Conduit")
        self.assertFalse(p.resumed, "a CloudWatch outage resumed a paused Conduit")
        self.assertEqual(self.gauge(p.metrics, "aws_mtd_egress_reading_valid"), "0")
        self.assertEqual(self.gauge(p.metrics, "aws_mtd_egress_bytes"), "NaN")


class K3sUnavailableTest(GuardrailHarness):
    def test_a_failed_pause_still_publishes_and_exits_cleanly(self):
        """k3s can be down at boot; the gauges must still be written and the run retried."""
        p = self.run_guardrail(97 * GB, prev=(95 * GB, 1), k3s_up=False)
        self.assertEqual(p.returncode, 0, f"a kubectl failure aborted the run: {p.stderr[-300:]}")
        self.assertIn("could not pause Conduit", p.stderr)
        self.assertEqual(self.gauge(p.metrics, "aws_mtd_egress_bytes"), str(97 * GB))
        self.assertEqual(self.gauge(p.metrics, "aws_conduit_paused"), "0")


class MeshExemptionTest(GuardrailHarness):
    def test_wireguard_keeps_the_fast_class(self):
        """Throttling the mesh would trade a bandwidth outage for a control-plane one."""
        p = self.run_guardrail(70 * GB)
        self.assertIn("51820", p.calls,
                      "the shaper has no WireGuard exemption, so SPIRE federation and "
                      f"Vault access over the mesh get shaped too: {p.calls}")
        wg_filters = [l for l in p.calls.splitlines() if "51820" in l]
        self.assertTrue(all("flowid 1:10" in l for l in wg_filters),
                        f"mesh traffic is not directed to the unthrottled class: {wg_filters}")


if __name__ == "__main__":
    unittest.main()
