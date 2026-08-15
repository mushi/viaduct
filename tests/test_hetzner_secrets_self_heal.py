"""The Hetzner node must self-heal a slow WireGuard converge without a re-provision.

The failure mode (seen repeatedly on 2026-08-14): the mesh handshake sometimes takes longer
than the provisioner's bounded secrets-fetch window, so the fetch is abandoned and Alloy /
nginx / certbot never follow the late render. Two guarantees fix it:

  1. hetzner-secrets.service retries on its own (Restart=on-failure) until the fetch succeeds
     — the provisioner is no longer the only thing driving it.
  2. a .path unit fires a finish-setup oneshot when the secrets render (however long that
     takes), which obtains the TLS cert and (re)starts the dependent services.

The rendered cloud-init is parsed and the units inspected.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TPL = (REPO_ROOT / "cloud-init.yaml.tpl").read_text()


def write_file(path: str) -> str:
    """Return the `content: |` body of the write_files entry for `path`."""
    m = re.search(rf"- path: {re.escape(path)}\n.*?content: \|\n(.*?)(?=\n  - path:|\n  [a-z])",
                  TPL, re.S)
    return m.group(1) if m else ""


class SelfHealTest(unittest.TestCase):
    def test_hetzner_secrets_retries_itself(self):
        unit = write_file("/etc/systemd/system/hetzner-secrets.service")
        self.assertIn("Restart=on-failure", unit,
                      "hetzner-secrets has no Restart=, so once the provisioner's bounded "
                      "retries give up nothing re-runs the fetch and the box never self-heals")
        self.assertIn("RemainAfterExit=yes", unit,
                      "without RemainAfterExit the successful render would not hold active")

    def test_a_path_unit_watches_for_the_rendered_secret(self):
        p = write_file("/etc/systemd/system/hetzner-secrets-ready.path")
        self.assertIn("PathExists=/run/hetzner-secrets/grafana.env", p)
        self.assertIn("Unit=hetzner-secrets-ready.service", p)

    def test_ready_service_obtains_cert_and_starts_dependents(self):
        sh = write_file("/usr/local/bin/hetzner-secrets-ready.sh")
        self.assertIn("certbot certonly", sh, "the ready hook must obtain the TLS cert")
        self.assertIn("systemctl restart alloy.service", sh)
        self.assertIn("systemctl restart nginx.service", sh)

    def test_handshake_gate_runs_as_root_not_in_the_unprivileged_fetch(self):
        """`wg show` needs CAP_NET_ADMIN. fetch-hetzner-secrets.sh runs as viaduct-secrets,
        which gets NO output from `wg show`, so the gate there always fails. It must be a
        root ('+') ExecStartPre instead."""
        fetch = (REPO_ROOT / "scripts" / "fetch-hetzner-secrets.sh").read_text()
        self.assertNotIn(
            "vh_wait_for_mesh_handshake", fetch,
            "the handshake gate is inside the unprivileged fetch again, where `wg show` "
            "returns nothing (no CAP_NET_ADMIN) so the secrets never render")
        unit = write_file("/etc/systemd/system/hetzner-secrets.service")
        self.assertRegex(
            unit, r"ExecStartPre=\+/bin/bash -c '\. /usr/local/bin/lib/mesh-trust\.sh; vh_wait_for_mesh_handshake",
            "the gate must be enforced by a root ('+') ExecStartPre before the fetch")

    def test_the_path_is_started_this_boot_not_just_enabled(self):
        # multi-user.target is already active during runcmd, so a plain `enable` would only
        # arm it for the next boot (the viaduct-crosscloud lesson).
        self.assertRegex(TPL, r"systemctl enable --now hetzner-secrets-ready\.path",
                         "the .path is enabled but never started this boot, so it won't fire "
                         "on the first deploy")


if __name__ == "__main__":
    unittest.main()
