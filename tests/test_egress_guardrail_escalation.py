"""VULN-036 — the guardrail's terminal action was reachable by an outsider.

Egress through the Conduit proxy is unauthenticated, so anything that ends in
`ec2 stop-instances` is an availability control an external party can aim at the
node. The guardrail read one aggregate month-to-date NetworkOut, compared it to a
fixed threshold, and stopped the instance — no rate-of-change check, no
throttle-first step. The earlier `READING_VALID` work addressed VULN-026 (a
CloudWatch outage silently disabling the cap), which is a different finding; this
one was untouched, and the script's own comment said so.

`stop-instances` is now the last rung of a ladder:

    below WARN        release any throttle
    WARN..CAP         shape the interface, alert, keep serving
    above CAP once    shape and alert — one reading is not a trend
    above CAP twice   stop

These run the real script with the AWS CLI, IMDS and `tc` stubbed, and assert on
the commands actually issued.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GUARDRAIL = REPO_ROOT / "aws" / "scripts" / "egress-guardrail.sh"

GB = 1_000_000_000
CAP = 90 * GB
WARN = 63 * GB


class GuardrailHarness(unittest.TestCase):
    def run_guardrail(self, mtd, prev=None, already_throttled=False):
        """mtd in bytes, or None for an unreadable CloudWatch response.

        `already_throttled` pre-installs the shaper, which is the state a run
        inherits from the previous one — without it there is nothing to release.
        """
        tmp = Path(tempfile.mkdtemp())
        binp = tmp / "bin"; binp.mkdir()
        calls = tmp / "calls.log"

        value = "None" if mtd is None else str(mtd)
        (binp / "aws").write_text(
            f'#!/usr/bin/env bash\n'
            f'echo "aws $*" >> "{calls}"\n'
            f'case "$*" in *get-metric-statistics*) printf "%s\\n" "{value}" ;; esac\n'
            f'exit 0\n')
        (binp / "curl").write_text('#!/usr/bin/env bash\nprintf "stub"\nexit 0\n')
        (binp / "ip").write_text(
            '#!/usr/bin/env bash\necho "default via 10.0.0.1 dev eth0 proto dhcp"\nexit 0\n')
        # `tc` records what it was asked to do, and reports the shaper as present
        # once a qdisc has been installed in this run.
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
        p.stopped = "stop-instances" in log
        p.throttled = "qdisc replace" in log
        p.released = "qdisc del" in log
        p.calls = log
        prom = tmp / "txt" / "egress.prom"
        p.metrics = prom.read_text() if prom.exists() else ""
        return p

    def gauge(self, metrics, name):
        for line in metrics.splitlines():
            if line.startswith(name + " "):
                return line.split()[1]
        return None


class EscalationLadderTest(GuardrailHarness):
    def test_normal_usage_neither_throttles_nor_stops(self):
        """Anchor: the guardrail must be quiet in the ordinary case."""
        p = self.run_guardrail(10 * GB)
        self.assertEqual(p.returncode, 0, p.stderr[-300:])
        self.assertFalse(p.stopped, "stopped the instance at 10 GB")
        self.assertFalse(p.throttled, "throttled at 10 GB")
        self.assertEqual(self.gauge(p.metrics, "aws_egress_throttled"), "0")

    def test_crossing_warn_throttles_instead_of_stopping(self):
        p = self.run_guardrail(70 * GB)
        self.assertTrue(p.throttled, f"no shaper installed at 70 GB: {p.calls}")
        self.assertFalse(p.stopped, "stopped the instance before the cap was reached")
        self.assertEqual(self.gauge(p.metrics, "aws_egress_throttled"), "1")

    def test_first_reading_over_the_cap_does_not_stop(self):
        """The filed vector: one aggregate reading must not be a kill switch."""
        p = self.run_guardrail(95 * GB, prev=(70 * GB, 0))
        self.assertFalse(
            p.stopped,
            "a single over-cap reading still stops the instance, so an outsider can "
            "aim the availability control at the node in one window")
        self.assertTrue(p.throttled, "the over-cap reading did not even throttle")

    def test_two_consecutive_over_cap_readings_do_stop(self):
        """Anchor: the guardrail must still protect the budget."""
        p = self.run_guardrail(97 * GB, prev=(95 * GB, 1))
        self.assertTrue(p.stopped,
                        f"sustained over-cap egress no longer stops the instance: {p.calls}")

    def test_falling_back_under_warn_releases_the_throttle(self):
        p = self.run_guardrail(5 * GB, prev=(95 * GB, 1), already_throttled=True)
        self.assertTrue(p.released, f"the shaper was never released: {p.calls}")
        self.assertFalse(p.stopped, "stopped on a reading well under the cap")


class RateOfChangeTest(GuardrailHarness):
    def test_an_implausible_jump_does_not_stop(self):
        """A 40 GB jump in one window exceeds what this instance can emit."""
        p = self.run_guardrail(95 * GB, prev=(55 * GB, 1))
        self.assertFalse(
            p.stopped,
            "a single implausible CloudWatch delta still triggers the terminal action")
        self.assertEqual(self.gauge(p.metrics, "aws_mtd_egress_reading_plausible"), "0")

    def test_a_plausible_delta_is_reported_as_such(self):
        p = self.run_guardrail(70 * GB, prev=(65 * GB, 0))
        self.assertEqual(self.gauge(p.metrics, "aws_mtd_egress_reading_plausible"), "1")
        self.assertEqual(self.gauge(p.metrics, "aws_mtd_egress_delta_bytes"), str(5 * GB))

    def test_a_month_rollover_is_not_a_negative_delta(self):
        p = self.run_guardrail(2 * GB, prev=(95 * GB, 1))
        self.assertEqual(self.gauge(p.metrics, "aws_mtd_egress_delta_bytes"), "0")
        self.assertFalse(p.stopped)


class Vuln026BehaviourPreservedTest(GuardrailHarness):
    """Anchor: the earlier finding's fix must not regress."""

    def test_an_unreadable_reading_still_alerts_rather_than_stops(self):
        p = self.run_guardrail(None, prev=(95 * GB, 1))
        self.assertFalse(p.stopped, "a CloudWatch outage can stop the instance again")
        self.assertEqual(self.gauge(p.metrics, "aws_mtd_egress_reading_valid"), "0")
        self.assertEqual(self.gauge(p.metrics, "aws_mtd_egress_bytes"), "NaN")


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
