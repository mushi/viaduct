"""Security test: VULN-031 — a restored backup must not be executed as shell.

CWE-349. xray-setup.sh recovers the Reality keypair with `source "$KEYPAIR_FILE"`, so the
backup file is executed rather than read. A tampered — or merely corrupted — keypair.env
therefore runs arbitrary commands as root on a freshly replaced node, at the exact moment
the operator is trusting the restore path.

The loader fragment is extracted from cloud-init.yaml.tpl and executed against crafted
keypair.env files.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TPL = REPO_ROOT / "cloud-init.yaml.tpl"
GUARDS = REPO_ROOT / "scripts" / "lib" / "provision-guards.sh"
PROVISION = REPO_ROOT / "scripts" / "provision.sh"

GOOD = "PRIVATE_KEY=aPrivateKeyValue\nPUBLIC_KEY=aPublicKeyValue\nSHORT_ID=0123456789abcdef\n"


def render(body: str) -> str:
    """Undo Terraform's template escaping, as templatefile() does at apply time.

    The node runs the *rendered* script, so `$${x}` reaches bash as `${x}`. Extracting
    the raw template instead would hand bash a literal `$$` (its own PID) and test a
    script that is never deployed.
    """
    return body.replace("$${", "${").replace("%%{", "%{")


def dedent(block: str) -> str:
    lines = block.splitlines()
    indent = min((len(l) - len(l.lstrip()) for l in lines if l.strip()), default=0)
    return "\n".join(l[indent:] for l in lines)


def loader_fragment() -> str:
    """The else-branch that recovers an existing keypair."""
    body = render(TPL.read_text())
    start = body.index("Loaded existing Reality keypair")
    # Walk back to the start of the branch, forward to the end of its validation.
    head = body.rindex("else", 0, start)
    # Anchor on a line-start `fi`: a bare index() matches the "fi" inside "file" in the
    # error message below and truncates the fragment mid-string.
    m = re.search(r"^\s*fi\s*$", body[start:], re.M)
    tail = start + m.end()   # include the closing `fi`
    return dedent(body[head + len("else"):tail])


def run_loader(content: str):
    tmp = tempfile.mkdtemp()
    kp = Path(tmp) / "keypair.env"; kp.write_text(content)
    marker = Path(tmp) / "pwned"
    script = (
        f'KEYPAIR_FILE="{kp}"\n'
        f'VH_MARKER="{marker}"\n'
        + loader_fragment().replace("$KEYPAIR_FILE", str(kp))
        + '\nprintf "LOADED priv=%s pub=%s sid=%s" "${PRIVATE_KEY:-}" "${PUBLIC_KEY:-}" "${SHORT_ID:-}"\n'
    )
    p = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                       env=dict(os.environ, VH_MARKER=str(marker)), timeout=30)
    p.executed = marker.exists()
    return p


class KeypairRestoreTest(unittest.TestCase):
    def test_a_genuine_backup_still_loads(self):
        """Anchor: the restore path must keep working."""
        p = run_loader(GOOD)
        self.assertIn("priv=aPrivateKeyValue", p.stdout,
                      f"a valid keypair.env no longer restores (rc={p.returncode}, {p.stderr[:200]})")
        self.assertIn("sid=0123456789abcdef", p.stdout)

    def test_a_tampered_backup_does_not_execute(self):
        """The decisive case: command substitution in a restored file."""
        payload = GOOD + '\ntouch "$VH_MARKER"\n'
        p = run_loader(payload)
        self.assertFalse(
            p.executed,
            "a command embedded in keypair.env executed during restore — root code "
            "execution on a freshly replaced node",
        )

    def test_command_substitution_in_a_value_does_not_execute(self):
        payload = 'PRIVATE_KEY=$(touch "$VH_MARKER")\nPUBLIC_KEY=x\nSHORT_ID=y\n'
        p = run_loader(payload)
        self.assertFalse(p.executed,
                         "command substitution inside a value was evaluated during restore")

    def test_unexpected_keys_do_not_reach_the_environment(self):
        payload = GOOD + "EXTRA_SETTING=malicious\n"
        p = run_loader(payload)
        self.assertNotIn("malicious", p.stdout,
                         "an unexpected key from the backup was imported")


# ── VULN-031 (restored client UUID) ──────────────────────────────────────────
# Same finding, sibling sink: a restored per-user .uuid is rendered into config.json
# and every client URI. A value that closes the JSON string ("…","flow":"attacker)
# injects config. Folded here from the retired test_verify_followup_gaps.py.

def uncommented(text: str) -> str:
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


class RestoredUuidTest(unittest.TestCase):
    """The re-imported UUID must be shape-checked before it reaches config.json."""

    @staticmethod
    def fragment() -> str:
        body = render(TPL.read_text())
        start = body.rindex("\n", 0, body.index('USER_UUID=$(cat "$UUID_FILE")')) + 1
        # Through the end of the validation block so the extracted shell is self-contained.
        end = body.index("\n", body.index("Remove the file to mint a new one", start))
        end = body.index("\n", body.index("fi", end)) + 1
        return dedent(body[start:end])

    def run_with(self, contents: str):
        tmp = Path(tempfile.mkdtemp())
        f = tmp / "user1.uuid"; f.write_text(contents)
        return subprocess.run(
            ["bash", "-c", f'UUID_FILE="{f}"\nUSERNAME=user1\n' + self.fragment() +
             '\nprintf "ACCEPTED=%s" "$USER_UUID"\n'],
            capture_output=True, text=True, timeout=30)

    def test_a_genuine_uuid_is_accepted(self):
        p = self.run_with("11111111-2222-3333-4444-555555555555\n")
        self.assertEqual(p.returncode, 0, f"a valid backup was rejected: {p.stderr}")
        self.assertIn("ACCEPTED=11111111-2222-3333-4444-555555555555", p.stdout)

    def test_an_injected_value_is_refused(self):
        payload = '11111111-2222-3333-4444-555555555555", "flow": "attacker'
        p = self.run_with(payload + "\n")
        self.assertNotEqual(p.returncode, 0, "a value that closes the JSON string was accepted")
        self.assertNotIn("ACCEPTED=" + payload, p.stdout)

    def test_a_non_uuid_is_refused(self):
        p = self.run_with("not-a-uuid\n")
        self.assertNotEqual(p.returncode, 0, "a non-UUID was rendered into the config")


class UuidGuardAndRoundTripTest(unittest.TestCase):
    def guard(self, value: str):
        return subprocess.run(
            ["bash", "-c", f'. "{GUARDS}"\nvh_is_uuid {value!r} && echo OK || echo REJECT'],
            capture_output=True, text=True)

    def test_the_guard_discriminates(self):
        self.assertIn("OK", self.guard("11111111-2222-3333-4444-555555555555").stdout)
        for bad in ("", "not-a-uuid", '1111"; rm -rf /', "11111111-2222-3333-4444"):
            with self.subTest(value=bad):
                self.assertIn("REJECT", self.guard(bad).stdout, f"vh_is_uuid accepted {bad!r}")

    def test_both_ends_of_the_round_trip_call_it(self):
        """The provisioner validates the UUID both when it pushes a backup up and when it
        stores what the node hands back — a planted value must not survive either leg."""
        body = uncommented(PROVISION.read_text())
        upload_side = body[body.index("Uploading"): body.index('upload "$f"')]
        self.assertIn("vh_is_uuid", upload_side,
                      "a planted UUID is still pushed back to the node unvalidated")
        download_side = body[body.index('download "$rf"'): body.index("Provisioning complete")]
        self.assertIn("vh_is_uuid", download_side,
                      "what the node hands back is still stored unvalidated")


if __name__ == "__main__":
    unittest.main()
