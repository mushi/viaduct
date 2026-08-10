"""Security test: VULN-037 — a PSK left in SSM by a hard kill must not survive the next run.

CWE-459. wg-mesh-join.sh stages the mesh preshared key in an SSM SecureString and removes
it with `trap ... EXIT`.

The finding as filed said an EXIT-only trap leaks on abnormal exit. That premise does not
hold: bash runs EXIT traps on SIGTERM, SIGINT and SIGHUP alike (verified on bash 5.3), so
every trappable termination already cleaned up. The residual that IS real is SIGKILL —
untrappable by definition — after which the PSK stays resident until someone notices. The
remediation is therefore a reaper: clear any stale parameter before staging a new one.

An earlier version of this test compared string offsets in the source, which an
independent review correctly rejected: it would still have passed if the delete call were
made conditional or ineffective. This version executes the real script against a stubbed
aws/gcloud and asserts on the SSM calls actually issued.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
JOIN = REPO_ROOT / "aws" / "scripts" / "wg-mesh-join.sh"

AWS_PUB = "kOtkkR2VfEHFN0m3ES0BJ0BpKbXPQ8YvvKZ5RRSXSHQ="
HUB_PUB = "aB3dEfGhIjKlMnOpQrStUvWxYz0123456789+/ABCDA="
PSK = "PSKPSKPSKPSKPSKPSKPSKPSKPSKPSKPSKPSKPSKPSKA="
PARAM = "/viaduct/wg/aws-psk"


def run_join(tmp: str):
    """Execute the real wg-mesh-join.sh with aws/gcloud/base64 stubbed."""
    tmpp = Path(tmp)
    binp = tmpp / "bin"; binp.mkdir()
    ssm = tmpp / "ssm_calls.log"

    (binp / "aws").write_text(f"""#!/usr/bin/env bash
if [ "$1" = "ssm" ]; then echo "$2 $*" >> "{ssm}"; fi
case "$1 $2" in
  "ssm send-command")            echo cmd-1234 ;;
  "ssm wait")                    : ;;
  "ssm get-command-invocation")
     case "$*" in
       *Status*)                 echo Success ;;
       *StandardOutputContent*)  printf '%s' '{AWS_PUB}' ;;
     esac ;;
esac
exit 0
""")
    (binp / "gcloud").write_text(
        "#!/usr/bin/env bash\n"
        f"printf 'hub_public_key %s\\npsk %s\\n' '{HUB_PUB}' '{PSK}'\nexit 0\n")
    (binp / "jq").write_text('#!/usr/bin/env bash\ncat >/dev/null; echo "{}"\nexit 0\n')
    for f in binp.iterdir():
        f.chmod(0o755)

    env = dict(
        os.environ,
        PATH=f"{binp}:{os.environ['PATH']}",
        AWS_REGION="eu-west-2", AWS_INSTANCE_ID="i-0123456789",
        GCP_HUB_IP="10.99.0.1", WG_PORT="51820", WG_MESH_IP="10.99.0.3",
        PSK_PARAM=PARAM, GCP_INSTANCE="viaduct-cp", GCP_ZONE="europe-west2-a",
        GCP_SSH_USER="ops", GCP_SSH_KEY_PATH="/dev/null",
    )
    # Run the real script. stdin is closed: an inherited terminal stdin let the SSM
    # poll block indefinitely under load, which made this test flaky.
    proc = subprocess.run(["bash", str(JOIN)], capture_output=True, text=True,
                          env=env, timeout=60, stdin=subprocess.DEVNULL)
    proc.ssm = ssm.read_text().splitlines() if ssm.exists() else []
    return proc


class PskResidueTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as tmp:
            cls.proc = run_join(tmp)

    def _indices(self, verb):
        return [i for i, c in enumerate(self.proc.ssm) if c.startswith(verb)]

    def test_the_script_reached_psk_staging(self):
        """Anchor: without this, the ordering assertions below pass vacuously."""
        self.assertTrue(
            self._indices("put-parameter"),
            f"the script never staged the PSK, so nothing below is being tested "
            f"(rc={self.proc.returncode}, stderr={self.proc.stderr[-400:]})",
        )

    def test_stale_parameter_is_deleted_before_staging(self):
        """SIGKILL cannot be trapped, so residue must be cleared on the next run."""
        deletes = self._indices("delete-parameter")
        puts = self._indices("put-parameter")
        self.assertTrue(
            deletes, "no delete-parameter call was issued; residue from a hard-killed run "
                     "would survive into this one")
        self.assertLess(
            min(deletes), min(puts),
            f"the stale-parameter delete did not precede the put: {self.proc.ssm}",
        )

    def test_parameter_is_staged_as_a_securestring(self):
        put = [c for c in self.proc.ssm if c.startswith("put-parameter")]
        self.assertTrue(any("SecureString" in c for c in put),
                        f"the PSK is no longer staged as a SecureString: {put}")

    def test_cleanup_trap_is_retained(self):
        """The EXIT trap covers every trappable termination and must stay."""
        self.assertRegex(
            JOIN.read_text(), r"trap\s+'.*delete-parameter.*'\s+EXIT",
            "the EXIT cleanup trap was removed; the PSK would then persist after every "
            "normal run, which is strictly worse than the filed finding",
        )


if __name__ == "__main__":
    unittest.main()
