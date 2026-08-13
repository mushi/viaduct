"""Security test: VULN-010 — the Alloy HTTP server must not be open to the pod network.

CWE-306. aws/k8s/20-alloy.yaml runs Alloy with --server.http.listen-addr=0.0.0.0:12345,
which serves its admin UI and API, and the namespace carries no NetworkPolicy — so any
pod on the cluster network can reach it unauthenticated.

This file originally claimed "binding to loopback is NOT the fix here", on the grounds
that a tcpSocket probe is dialled by the kubelet against the pod IP. The constraint is
real but the conclusion was not: the probe can run *inside* the pod instead. The pinned
image ships /usr/bin/bash (verified against the digest), so bash's /dev/tcp performs the
same connect check without the kubelet needing to reach the port at all.

The NetworkPolicy closed the pod-network half. It never covered the node's netns —
kube-router does not filter node-originated traffic to a local pod — which is why the
listener has now moved to 127.0.0.1 and pprof is off. See
test_alloy_admin_listener_scope.py.

The sink is the manifest, so these assertions parse the emitted YAML.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ALLOY = REPO_ROOT / "aws" / "k8s" / "20-alloy.yaml"


def documents():
    return [d for d in ALLOY.read_text().split("\n---") if d.strip()]


def doc_of_kind(kind: str):
    return [d for d in documents() if re.search(rf"^kind:\s*{kind}\s*$", d, re.M)]


class AlloyExposureTest(unittest.TestCase):
    def setUp(self):
        self.text = ALLOY.read_text()

    def test_a_network_policy_exists(self):
        self.assertTrue(
            doc_of_kind("NetworkPolicy"),
            "no NetworkPolicy in the manifest: any pod on the cluster network can reach "
            "Alloy's admin API on :12345 unauthenticated",
        )

    def test_policy_targets_alloy_and_denies_ingress_by_default(self):
        pols = doc_of_kind("NetworkPolicy")
        self.assertTrue(pols)
        joined = "\n".join(pols)
        self.assertIn("Ingress", joined,
                      "the NetworkPolicy does not declare an Ingress policyType, so ingress "
                      "is not restricted at all")
        self.assertRegex(
            joined, r"podSelector:\s*\{\s*\}|podSelector:\s*$|app:\s*alloy",
            "the NetworkPolicy does not select the Alloy pods, so it constrains nothing",
        )

    def test_no_blanket_allow_from_everywhere(self):
        """An empty `from:` would re-open what the default deny closed."""
        for pol in doc_of_kind("NetworkPolicy"):
            self.assertNotRegex(
                pol, r"-\s*from:\s*\n\s*-\s*podSelector:\s*\{\s*\}\s*\n\s*ports",
                "the policy allows ingress from every pod in the namespace, which is the "
                "exposure this finding is about",
            )

    def test_liveness_probe_still_targets_the_server_port(self):
        """The probe must keep working — but it no longer has to be a tcpSocket probe.

        Amended: this required `tcpSocket: { port: 12345 }`, which pinned the listener
        to the pod IP and so preserved the node-netns exposure this finding is about.
        What actually matters is that liveness is still checked against 12345; doing it
        from inside the pod satisfies that and closes the path.
        """
        self.assertRegex(
            self.text, r"/dev/tcp/127\.0\.0\.1/12345|tcpSocket:\s*\{\s*port:\s*12345\s*\}",
            "nothing checks liveness against 12345 any more, so a wedged Alloy would "
            "never be restarted",
        )

    def test_listener_is_documented_as_deliberately_reachable(self):
        """Guard against a later 'hardening' that silently breaks the probe."""
        self.assertIn(
            "listen-addr", self.text,
            "the listener argument vanished; the probe contract depends on it",
        )


if __name__ == "__main__":
    unittest.main()
