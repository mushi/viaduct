"""VULN-010 — Alloy's admin API was reachable from the node's network namespace.

The listener bound 0.0.0.0:12345. Inside the pod netns that resolves to the pod IP,
and kube-router does not filter node-originated traffic to a local pod, so the
namespace NetworkPolicy never covered that path — the manifest's own comment kept
the listener on 0.0.0.0 precisely so the kubelet could dial the pod IP for a
tcpSocket probe.

What that exposed: /debug/pprof/heap dumps process memory, and the rendered
config.alloy carries the Grafana Cloud basic_auth password in plaintext, so a heap
dump from any node-local process was a credential disclosure.

Unlike the residuals recorded in docs/ACCEPTED-RISKS.md, this one had a complete
fix available. Loopback is not reachable from the host netns at all, so binding
127.0.0.1 eliminates the path rather than narrowing it. The probe moves inside the
pod to compensate, using bash's /dev/tcp — verified present in the pinned image
digest, which ships /usr/bin/bash but neither curl nor wget.
"""

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = REPO_ROOT / "aws" / "k8s" / "20-alloy.yaml"

try:
    import yaml
except ImportError:  # exercised fully in CI, which installs requirements.txt
    yaml = None


def uncommented(text: str) -> str:
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


class ListenerScopeTest(unittest.TestCase):
    def setUp(self):
        self.body = uncommented(MANIFEST.read_text())

    def test_the_admin_api_is_not_bound_to_all_interfaces(self):
        self.assertNotIn(
            "--server.http.listen-addr=0.0.0.0", self.body,
            "the admin API is still on 0.0.0.0, so it resolves to the pod IP and any "
            "process in the node's netns can reach it — a path NetworkPolicy does "
            "not filter")

    def test_it_is_bound_to_loopback(self):
        self.assertIn("--server.http.listen-addr=127.0.0.1:12345", self.body,
                      "the listener is not confined to the pod's loopback")

    def test_pprof_is_disabled(self):
        """The heap is where the Grafana credential lives; the flag defaults to true."""
        self.assertIn("--server.http.enable-pprof=false", self.body,
                      "/debug/pprof is still enabled, so a heap dump discloses the "
                      "Grafana Cloud basic_auth password from the rendered config")


class ProbeTest(unittest.TestCase):
    def setUp(self):
        self.body = uncommented(MANIFEST.read_text())

    def test_the_probe_does_not_dial_the_pod_ip(self):
        self.assertNotIn(
            "tcpSocket", self.body,
            "a tcpSocket probe is dialled by the kubelet against the pod IP, which is "
            "the reachability this change removes — the pod would restart-loop")

    def test_the_probe_runs_inside_the_pod_against_loopback(self):
        self.assertIn("/dev/tcp/127.0.0.1/12345", self.body,
                      "the liveness probe no longer checks the admin port")
        self.assertIn("/usr/bin/bash", self.body,
                      "the probe must name bash by absolute path: the image ships "
                      "/usr/bin/bash but no curl or wget, and no /bin/sh guarantee")

    def test_a_liveness_probe_still_exists(self):
        """Anchor: deleting the probe would satisfy the assertions above."""
        self.assertIn("livenessProbe:", self.body)
        self.assertIn("periodSeconds:", self.body)

    def test_the_dev_tcp_idiom_discriminates(self):
        """Behavioural: it must succeed on a live port and fail on a dead one."""
        bash = "/bin/bash" if Path("/bin/bash").exists() else "/usr/bin/bash"
        if not Path(bash).exists():
            self.skipTest("no bash available to exercise the idiom")

        # A listener we control, then the same port after it is gone.
        import socket
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        probe = f"exec 3<>/dev/tcp/127.0.0.1/{port}"
        live = subprocess.run([bash, "-c", probe], capture_output=True, timeout=30)
        self.assertEqual(live.returncode, 0,
                         f"the probe failed against a live listener: {live.stderr[-200:]}")

        srv.close()
        dead = subprocess.run([bash, "-c", probe], capture_output=True, timeout=30)
        self.assertNotEqual(
            dead.returncode, 0,
            "the probe succeeded against a closed port, so a wedged Alloy would never "
            "be restarted")


class NetworkPolicyRetainedTest(unittest.TestCase):
    """Anchor: loopback binding does not make the policy redundant."""

    @unittest.skipIf(yaml is None, "PyYAML not installed (see requirements.txt)")
    def test_the_default_deny_and_the_scrape_allow_both_survive(self):
        docs = [d for d in yaml.safe_load_all(MANIFEST.read_text()) if d]
        kinds = {(d["kind"], d["metadata"]["name"]) for d in docs}
        self.assertIn(("NetworkPolicy", "default-deny-ingress"), kinds,
                      "the namespace default-deny was dropped")
        self.assertIn(("NetworkPolicy", "allow-alloy-scrape-conduit"), kinds,
                      "Alloy can no longer scrape conduit's metrics")

    @unittest.skipIf(yaml is None, "PyYAML not installed (see requirements.txt)")
    def test_the_manifest_still_describes_one_alloy_deployment(self):
        docs = [d for d in yaml.safe_load_all(MANIFEST.read_text()) if d]
        deploys = [d for d in docs if d["kind"] == "Deployment"]
        self.assertEqual(len(deploys), 1)
        c = deploys[0]["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(c["name"], "alloy")
        self.assertIn("--server.http.listen-addr=127.0.0.1:12345", c["args"],
                      f"the rendered args do not confine the listener: {c['args']}")
        self.assertIn("exec", c["livenessProbe"],
                      f"the probe is not an exec probe: {c['livenessProbe']}")


if __name__ == "__main__":
    unittest.main()
