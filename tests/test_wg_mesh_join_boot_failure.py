"""wg-mesh-join.sh must report a failed AWS boot at once, with its cause.

When the box's boot script aborts (a fail-closed digest pin, typically), wg0.pub is never
written. Polling for the key alone spends the full ~15 min budget and then blames SSM
registration. The join instead asks cloud-init whether it has finished: finished without
a key is a failed boot, reported with the FATAL line and the -replace remedy.

These tests execute the real script against a stubbed aws/gcloud.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
JOIN = REPO_ROOT / "aws" / "scripts" / "wg-mesh-join.sh"

FATAL = "[viaduct-startup] 14:31:40 FATAL: k3s installer digest mismatch — refusing to execute"


def run_join(tmp: str, box_stdout: str):
    """Run wg-mesh-join.sh with every SSM probe answered by box_stdout."""
    tmpp = Path(tmp)
    binp = tmpp / "bin"; binp.mkdir()
    gcloud_log = tmpp / "gcloud_calls.log"
    out_file = tmpp / "box_stdout"
    out_file.write_text(box_stdout)

    (binp / "aws").write_text(f"""#!/usr/bin/env bash
case "$1 $2" in
  "ssm send-command")            echo cmd-1234 ;;
  "ssm wait")                    : ;;
  "ssm get-command-invocation")
     case "$*" in
       *Status*)                 echo Success ;;
       *StandardOutputContent*)  cat "{out_file}" ;;
     esac ;;
esac
exit 0
""")
    (binp / "gcloud").write_text(f'#!/usr/bin/env bash\necho "$*" >> "{gcloud_log}"\nexit 0\n')
    (binp / "jq").write_text('#!/usr/bin/env bash\ncat >/dev/null; echo "{}"\nexit 0\n')
    # A failed boot must not wait out the poll budget; make any sleep fail loudly.
    (binp / "sleep").write_text('#!/usr/bin/env bash\necho "UNEXPECTED SLEEP" >&2\nexit 99\n')
    for f in binp.iterdir():
        f.chmod(0o755)

    env = dict(
        os.environ,
        PATH=f"{binp}:{os.environ['PATH']}",
        AWS_REGION="eu-west-2", AWS_INSTANCE_ID="i-0123456789",
        GCP_HUB_IP="10.99.0.1", WG_PORT="51820", WG_MESH_IP="10.99.0.3",
        PSK_PARAM="/viaduct/wg/aws-psk", GCP_INSTANCE="viaduct-cp", GCP_ZONE="europe-west2-a",
        GCP_SSH_USER="ops", GCP_SSH_KEY_PATH="/dev/null",
    )
    proc = subprocess.run(["bash", str(JOIN)], capture_output=True, text=True,
                          env=env, timeout=60, stdin=subprocess.DEVNULL)
    proc.gcloud = gcloud_log.read_text().splitlines() if gcloud_log.exists() else []
    return proc


class BootFailureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as tmp:
            cls.proc = run_join(tmp, f"BOOT_FAILED\n{FATAL}\n")

    def test_exits_nonzero_without_waiting(self):
        self.assertEqual(self.proc.returncode, 1, self.proc.stdout + self.proc.stderr)
        self.assertNotIn("UNEXPECTED SLEEP", self.proc.stderr,
                         "a failed boot was polled again instead of reported")

    def test_reports_the_boot_scripts_fatal_line(self):
        self.assertIn("FATAL: k3s installer digest mismatch", self.proc.stdout)

    def test_names_the_rebuild_as_the_remedy(self):
        self.assertIn("terraform apply -replace=aws_instance.spire", self.proc.stdout)

    def test_never_touches_the_hub(self):
        self.assertEqual(self.proc.gcloud, [],
                         "the hub registry was modified for a box that never booted")

    def test_control_characters_from_the_box_are_stripped(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_join(tmp, "BOOT_FAILED\nFATAL: x\x1b]0;pwned\x07\x1b[2J\n")
        self.assertIn("FATAL: x", proc.stdout)
        self.assertNotIn("\x1b", proc.stdout)
        self.assertNotIn("\x07", proc.stdout)


if __name__ == "__main__":
    unittest.main()
