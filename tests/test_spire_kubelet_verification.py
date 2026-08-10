"""Security test: VULN-035 — the SPIRE k8s WorkloadAttestor must verify the kubelet.

CWE-295. aws/scripts/startup.sh.tpl rendered the agent config with
`skip_kubelet_verification = true`, so the agent accepted any TLS peer answering as the
kubelet. Kubelet responses drive workload attestation — they decide which SVID a pod is
issued — so an impersonating peer can steer identity assignment.

The sink here is the rendered agent.conf, so the assertions read the emitted config.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
STARTUP = REPO_ROOT / "aws" / "scripts" / "startup.sh.tpl"


def k8s_attestor_block(text: str) -> str:
    m = re.search(r'WorkloadAttestor "k8s"\s*\{(.*?)\n  \}', text, re.S)
    if not m:
        raise AssertionError('could not locate the WorkloadAttestor "k8s" block')
    return m.group(1)


class KubeletVerificationTest(unittest.TestCase):
    def setUp(self):
        self.text = STARTUP.read_text()
        self.block = k8s_attestor_block(self.text)

    def test_kubelet_verification_is_not_skipped(self):
        self.assertNotRegex(
            self.block, r"skip_kubelet_verification\s*=\s*true",
            "skip_kubelet_verification is still true: the agent accepts any TLS peer "
            "answering as the kubelet, and kubelet responses decide which SVID a pod gets",
        )

    def test_a_kubelet_ca_is_configured(self):
        self.assertRegex(
            self.block, r'kubelet_ca_path\s*=\s*"/[^"]+"',
            "no kubelet_ca_path is configured, so verification has nothing to verify "
            "against and the attestor cannot authenticate the kubelet",
        )

    def test_kubelet_ca_path_is_the_k3s_server_ca(self):
        """k3s signs kubelet serving certs with its server CA; anything else will not verify."""
        m = re.search(r'kubelet_ca_path\s*=\s*"([^"]+)"', self.block)
        self.assertIsNotNone(m)
        self.assertEqual(
            m.group(1), "/var/lib/rancher/k3s/server/tls/server-ca.crt",
            "kubelet_ca_path does not point at the k3s server CA; attestation would fail "
            "closed and pods would stop receiving k8s selectors",
        )

    def test_token_path_is_retained(self):
        """The rotated SA token must survive the change — it is how the agent authenticates."""
        self.assertIn("token_path", self.block,
                      "the rotated kubelet SA token configuration was lost")


if __name__ == "__main__":
    unittest.main()
