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

GOOD = "PRIVATE_KEY=aPrivateKeyValue\nPUBLIC_KEY=aPublicKeyValue\nSHORT_ID=0123456789abcdef\n"


def dedent(block: str) -> str:
    lines = block.splitlines()
    indent = min((len(l) - len(l.lstrip()) for l in lines if l.strip()), default=0)
    return "\n".join(l[indent:] for l in lines)


def loader_fragment() -> str:
    """The else-branch that recovers an existing keypair."""
    body = TPL.read_text()
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


if __name__ == "__main__":
    unittest.main()
