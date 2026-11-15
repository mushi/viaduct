"""provision.sh holds one SSH connection per run and survives it dropping.

Intrusion prevention on the operator's router blocked Hetzner-bound SSH after a burst
of short-lived connections, so the provisioner must look like one session: a single
master connection opened with backoff, every command riding on it, and a dropped
connection re-established rather than failing the run.

These run the real connection functions from scripts/provision.sh against a stub
`ssh` that plays the server (master up or down, connection attempts that fail, a
connection that drops mid-command) and a `sleep` that records the wait and advances the clock instead of waiting.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PROVISION = REPO_ROOT / "scripts" / "provision.sh"

STUB_SSH = r'''#!/usr/bin/env bash
# Plays the server side. State lives in $STATE.
args="$*"
if [[ " $args " == *" -O check "* ]]; then
  [ -f "$STATE/master" ] && exit 0 || exit 255
fi
if [[ " $args " == *" -O exit "* ]]; then
  rm -f "$STATE/master"; exit 0
fi
if [[ "$args" == *"ControlMaster=yes"* ]]; then
  n=$(( $(cat "$STATE/connects" 2>/dev/null || echo 0) + 1 ))
  echo "$n" > "$STATE/connects"
  if [ -f "$STATE/hostkey" ]; then
    echo "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!" >&2; exit 255
  fi
  if [ "$n" -le "$(cat "$STATE/fail_connects" 2>/dev/null || echo 0)" ]; then
    echo "ssh: connect to host 192.0.2.10 port 22: Operation timed out" >&2; exit 255
  fi
  touch "$STATE/master"; exit 0
fi
echo "$args" >> "$STATE/clients"
if [ -f "$STATE/drop_next" ]; then
  rm -f "$STATE/drop_next" "$STATE/master"; exit 255
fi
exit "$(cat "$STATE/remote_rc" 2>/dev/null || echo 0)"
'''


def connection_functions() -> str:
    """The connection layer of provision.sh, from its setup to remote()."""
    body = PROVISION.read_text()
    start = body.index("CONTROL_DIR=$(mktemp -d)")
    end = body.index("remote() {", start)
    end = body.index("\n", end) + 1
    return body[start:end]


def section_11() -> str:
    """The kernel-reboot step of provision.sh."""
    body = PROVISION.read_text()
    start = re.search(r"# ── \d+\. Run the installed kernel", body).start()
    end = body.index('log ""\nlog "Provisioning complete."', start)
    return body[start:end]


class Harness(unittest.TestCase):
    def run_sh(self, call, fail_connects=0, hostkey=False, remote_rc=0, drop_next=False,
               master_up=False, extra=""):
        tmp = Path(tempfile.mkdtemp())
        binp, state = tmp / "bin", tmp / "state"
        binp.mkdir()
        state.mkdir()
        (binp / "ssh").write_text(STUB_SSH)
        (binp / "scp").write_text(STUB_SSH)
        for f in binp.iterdir():
            f.chmod(0o755)
        (state / "fail_connects").write_text(str(fail_connects))
        (state / "remote_rc").write_text(str(remote_rc))
        if hostkey:
            (state / "hostkey").touch()
        if drop_next:
            (state / "drop_next").touch()
        if master_up:
            (state / "master").touch()
        script = tmp / "run.sh"
        script.write_text(
            "set -euo pipefail\n"
            'SERVER_IP=192.0.2.10; SSH_KEY_PATH=/dev/null; BACKUPS_DIR="' + str(tmp) + '"\n'
            + connection_functions()
            # Record each wait and advance bash's clock by it, so deadlines expire.
            + 'sleep() { echo "$1" >> "$STATE/sleeps"; SECONDS=$(( SECONDS + $1 )); }\n'
            + extra + "\n" + call + "\n")
        p = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=60,
                           stdin=subprocess.DEVNULL,
                           env=dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}",
                                    STATE=str(state)))
        read = lambda n: (state / n).read_text().split() if (state / n).exists() else []
        p.sleeps = [int(s) for s in read("sleeps")]
        p.connects = int((read("connects") or ["0"])[0])
        p.clients = (state / "clients").read_text().splitlines() if (state / "clients").exists() else []
        return p


class OneConnectionTest(Harness):
    def test_the_boot_wait_backs_off_instead_of_retrying_every_ten_seconds(self):
        """A dozen attempts over ten minutes, not sixty."""
        p = self.run_sh("ssh_connect 600 || echo GAVE_UP", fail_connects=1000)
        self.assertIn("GAVE_UP", p.stdout)
        self.assertEqual(p.sleeps[:3], [15, 30, 60], p.sleeps)
        self.assertTrue(all(s <= 60 for s in p.sleeps), p.sleeps)
        self.assertLessEqual(p.connects, 12, f"{p.connects} connection attempts in ten minutes")
        self.assertLessEqual(sum(p.sleeps), 600)

    def test_a_booting_server_is_reached_once_it_answers(self):
        p = self.run_sh("ssh_connect 600 && echo UP", fail_connects=2)
        self.assertIn("UP", p.stdout, p.stderr)
        self.assertEqual(p.connects, 3)

    def test_a_changed_host_key_stops_at_once(self):
        """Retrying cannot fix a host-key mismatch, and it would only add connections."""
        p = self.run_sh("ssh_connect 600", hostkey=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(p.connects, 1)
        self.assertEqual(p.sleeps, [])
        self.assertIn("VIADUCT_HOST_KEY_RESET=1", p.stdout)

    def test_commands_share_the_one_connection(self):
        p = self.run_sh("rssh true; rssh true; remote true; rscp /dev/null /tmp/x")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.connects, 1, "a command opened a connection of its own")
        self.assertEqual(len(p.clients), 4)
        for c in p.clients:
            self.assertIn("ControlMaster=no", c, "a client could fall back to its own connection")

    def test_an_open_connection_is_reused_not_reopened(self):
        p = self.run_sh("rssh true", master_up=True)
        self.assertEqual(p.connects, 0)

    def test_the_connection_outlives_idle_stretches(self):
        """ControlPersist=60 closed it during the probe build and the next call reopened."""
        body = connection_functions()
        self.assertRegex(body, r"ControlMaster=yes -o ControlPersist=10m")
        self.assertNotRegex(body, r"ControlMaster=auto")


class DroppedConnectionTest(Harness):
    def test_a_dropped_connection_is_reopened_and_the_command_retried(self):
        p = self.run_sh("rssh true && echo DONE", drop_next=True)
        self.assertIn("DONE", p.stdout, p.stderr)
        self.assertEqual(p.connects, 2)
        self.assertEqual(len(p.clients), 2)
        self.assertIn("reconnecting", p.stdout)

    def test_a_failing_command_is_not_mistaken_for_a_dropped_connection(self):
        p = self.run_sh("rssh false || echo RC=$?", remote_rc=1)
        self.assertIn("RC=1", p.stdout)
        self.assertEqual(len(p.clients), 1, "a remote failure was retried")

    def test_a_command_reading_stdin_is_never_replayed(self):
        """A replay after stdin was consumed could write an empty wg0.conf."""
        p = self.run_sh("echo data | rssh_stdin cat || echo RC=$?", drop_next=True)
        self.assertIn("RC=255", p.stdout)
        self.assertEqual(len(p.clients), 1)

    def test_stdin_fed_commands_use_the_non_retrying_path(self):
        body = PROVISION.read_text()
        for line in body.splitlines():
            if re.search(r"\|\s*rssh\b(?!_stdin)", line):
                self.fail(f"stdin piped into a retrying call: {line.strip()}")
        self.assertNotIn("$SSH", body)
        self.assertNotIn("$SCP", body)


class KernelRebootTest(Harness):
    STUBS = """
remote() { [ -f "$STATE/reboot_pending" ]; }
rssh() { if [ "$1" = uname ]; then echo 7.0.0-test; fi; }
ssh_connect() { echo "CONNECT $1"; rm -f "$STATE/reboot_pending"; }
"""

    def run_step(self, fresh, pending):
        extra = self.STUBS + f"\nFRESH={fresh}\n"
        setup = 'touch "$STATE/reboot_pending"' if pending else ":"
        call = setup + "\n" + section_11()
        return self.run_sh(call, master_up=True, extra=extra)

    def test_a_fresh_node_is_rebooted_into_the_new_kernel(self):
        p = self.run_step(fresh=1, pending=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        reboots = [c for c in p.clients if "systemctl reboot" in c]
        self.assertEqual(len(reboots), 1, p.clients)
        self.assertIn("ControlMaster=no", reboots[0])
        self.assertIn("CONNECT 600", p.stdout)
        self.assertIn("Running kernel 7.0.0-test", p.stdout)

    def test_a_live_node_waits_for_the_maintenance_window(self):
        p = self.run_step(fresh=0, pending=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse([c for c in p.clients if "reboot" in c], "a live node was rebooted")
        self.assertIn("03:30", p.stdout)

    def test_nothing_happens_without_a_pending_kernel(self):
        p = self.run_step(fresh=1, pending=False)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.clients, [])
        self.assertNotIn("kernel", p.stdout)

    def test_the_reboot_is_never_sent_through_a_retrying_call(self):
        """A retry after the connection drops would reboot the node a second time."""
        self.assertNotRegex(section_11(), r"(rssh|remote)[^\n]*systemctl reboot")


if __name__ == "__main__":
    unittest.main()
