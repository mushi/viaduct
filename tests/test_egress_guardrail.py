"""Security test: VULN-026 / VULN-036 — the egress guardrail must distinguish unknown from zero.

VULN-026 (CWE-636): an unreadable CloudWatch response collapsed to `SUM=0`, so the
comparison against THRESHOLD could never fire and a persistent failure disabled the cap
silently and indefinitely.

VULN-036 (CWE-400): the same guardrail calls `aws ec2 stop-instances`, and egress through
the proxy is unauthenticated — so an attacker can drive the node toward stopping itself.

These pull in opposite directions. Per the operator's decision the guardrail reports an
unknown reading rather than treating it as zero, and does not stop on unknown — the cap
enforcement is unchanged for genuine breaches.

The script is executed against a stubbed aws CLI.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GUARDRAIL = REPO_ROOT / "aws" / "scripts" / "egress-guardrail.sh"

OVER_CAP = "95000000000"     # above the 90 GB threshold
UNDER_CAP = "1000000000"


def run_guardrail(tmp: str, cw_output: str, cw_rc: int = 0):
    binp = Path(tmp) / "bin"; binp.mkdir()
    stopped = Path(tmp) / "stopped"
    txt = Path(tmp) / "textfile"

    (binp / "curl").write_text(
        "#!/usr/bin/env bash\n"
        'case "$*" in\n'
        '  *api/token*) echo TOKEN ;;\n'
        '  *instance-id*) echo i-0123456789 ;;\n'
        '  *placement/region*) echo eu-west-2 ;;\n'
        '  *) echo stub ;;\n'
        'esac\n')
    (binp / "aws").write_text(f"""#!/usr/bin/env bash
if [ "$1" = "cloudwatch" ]; then printf '%s\\n' {cw_output!r}; exit {cw_rc}; fi
if [ "$1" = "ec2" ] && [ "$2" = "stop-instances" ]; then : > "{stopped}"; exit 0; fi
exit 0
""")
    for f in binp.iterdir():
        f.chmod(0o755)

    body = GUARDRAIL.read_text().replace("/var/lib/viaduct-textfile", str(txt))
    env = dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}")
    proc = subprocess.run(["bash", "-c", body], capture_output=True, text=True, env=env, timeout=60)
    proc.stopped = stopped.exists()
    prom = txt / "egress.prom"
    proc.textfile = prom.read_text() if prom.exists() else ""
    return proc


class GuardrailUnknownTest(unittest.TestCase):
    def test_a_genuine_reading_under_cap_does_not_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = run_guardrail(tmp, UNDER_CAP)
            self.assertFalse(p.stopped, "the guardrail stopped the node while under the cap")
            self.assertIn("aws_mtd_egress_bytes", p.textfile,
                          f"no metrics written (rc={p.returncode}, stderr={p.stderr[:200]})")

    def test_a_genuine_reading_over_cap_still_stops(self):
        """The cap must keep working — this is the guardrail's whole purpose."""
        with tempfile.TemporaryDirectory() as tmp:
            p = run_guardrail(tmp, OVER_CAP)
            self.assertTrue(p.stopped,
                            f"a genuine over-cap reading no longer stops the instance "
                            f"(rc={p.returncode}, stderr={p.stderr[:200]})")

    def test_unknown_is_not_reported_as_zero_egress(self):
        """VULN-026: 'None' must not silently become 0 GB."""
        with tempfile.TemporaryDirectory() as tmp:
            p = run_guardrail(tmp, "None")
            self.assertNotRegex(
                p.textfile, r"aws_mtd_egress_bytes 0\b",
                "an unreadable CloudWatch reading was published as 0 bytes of egress, so "
                "the cap can never fire and the failure is invisible",
            )

    def test_unknown_is_observable(self):
        """The blind spot must become an alertable signal."""
        with tempfile.TemporaryDirectory() as tmp:
            p = run_guardrail(tmp, "None")
            self.assertRegex(
                p.textfile, r"aws_mtd_egress_reading_valid 0",
                "nothing in the textfile distinguishes 'could not read' from 'no egress', "
                "so a persistent CloudWatch failure is undetectable",
            )

    def test_unknown_does_not_stop_the_node(self):
        """VULN-036: an unknown reading must not become a remote off-switch."""
        with tempfile.TemporaryDirectory() as tmp:
            p = run_guardrail(tmp, "None")
            self.assertFalse(
                p.stopped,
                "an unreadable reading stopped the instance; a CloudWatch outage would "
                "then take the node down",
            )


if __name__ == "__main__":
    unittest.main()
