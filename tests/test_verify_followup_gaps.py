"""Gaps an independent re-verification found in the four merged fix clusters.

The /vulnhunt-fix-verify pass over all 46 findings returned 8 NOT_FIXED and 8
PARTIAL. This file covers the subset that were unambiguous gaps in the original
remediation — not the ones that trace back to an accepted design decision.

  VULN-031  the filed PRIMARY location was the re-imported client UUID; only the
            parenthetical secondary site (`source keypair.env`) had been fixed.
            The operator round trip was unvalidated at both ends too.
  VULN-011  the applier skipped a duplicate mesh_ip, but the writer never did, so
            a peer could still claim a victim's address — the winner was merely
            decided by lexical order of the registry instead of by write order.
  VULN-018  kms:Sign stayed in the unconditioned `Resource = "*"` statement.
  VULN-038  only the IPv4 half of the self-address block was implemented.
  VULN-042/044/048  branch-local umasks left /etc/xray/config.json — which holds
            the Reality private key and every client UUID — born 0644 on re-apply.
  (unfiled) the Hetzner analog of VULN-023: the same Vault-held Grafana values
            written into config-file sinks with no validation at all.
"""

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TPL = REPO_ROOT / "cloud-init.yaml.tpl"
PROVISION = REPO_ROOT / "scripts" / "provision.sh"
GUARDS = REPO_ROOT / "scripts" / "lib" / "provision-guards.sh"
FETCH = REPO_ROOT / "scripts" / "fetch-hetzner-secrets.sh"
GCP_STARTUP = REPO_ROOT / "gcp" / "scripts" / "startup.sh"
AWS_MAIN = REPO_ROOT / "aws" / "main.tf"


def render(body: str) -> str:
    return body.replace("$${", "${").replace("%%{", "%{")


def uncommented(text: str) -> str:
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def sh(script: str, **kw):
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                          timeout=60, stdin=subprocess.DEVNULL, **kw)


# ── VULN-031 ────────────────────────────────────────────────────────────────

class RestoredUuidTest(unittest.TestCase):
    """The re-imported UUID reaches config.json and every client URI."""

    @staticmethod
    def fragment() -> str:
        body = render(TPL.read_text())
        start = body.rindex("\n", 0, body.index('USER_UUID=$(cat "$UUID_FILE")')) + 1
        # Through the end of the validation block, so the extracted shell is
        # self-contained — slicing mid-construct leaves an unterminated `if`.
        end = body.index("\n", body.index("Remove the file to mint a new one", start))
        end = body.index("\n", body.index("fi", end)) + 1
        lines = body[start:end].splitlines()
        indent = min(len(l) - len(l.lstrip()) for l in lines if l.strip())
        return "\n".join(l[indent:] for l in lines)

    def run_with(self, contents: str):
        tmp = Path(tempfile.mkdtemp())
        f = tmp / "user1.uuid"
        f.write_text(contents)
        return sh(f'UUID_FILE="{f}"\nUSERNAME=user1\n' + self.fragment() +
                  '\nprintf "ACCEPTED=%s" "$USER_UUID"\n')

    def test_a_genuine_uuid_is_accepted(self):
        """Anchor: restore must keep working, or the rejections below prove nothing."""
        p = self.run_with("11111111-2222-3333-4444-555555555555\n")
        self.assertEqual(p.returncode, 0, f"a valid backup was rejected: {p.stderr}")
        self.assertIn("ACCEPTED=11111111-2222-3333-4444-555555555555", p.stdout)

    def test_an_injected_value_is_refused(self):
        payload = '11111111-2222-3333-4444-555555555555", "flow": "attacker'
        p = self.run_with(payload + "\n")
        self.assertNotEqual(p.returncode, 0,
                            "a value that closes the JSON string was accepted")
        self.assertNotIn("ACCEPTED=" + payload, p.stdout)

    def test_a_non_uuid_is_refused(self):
        p = self.run_with("not-a-uuid\n")
        self.assertNotEqual(p.returncode, 0, "a non-UUID was rendered into the config")


class ProvisionerRoundTripTest(unittest.TestCase):
    """Both ends of the backup round trip must shape-check the UUID."""

    def guard(self, value: str):
        return sh(f'. "{GUARDS}"\nvh_is_uuid {value!r} && echo OK || echo REJECT')

    def test_the_guard_discriminates(self):
        self.assertIn("OK", self.guard("11111111-2222-3333-4444-555555555555").stdout)
        for bad in ("", "not-a-uuid", '1111"; rm -rf /', "11111111-2222-3333-4444"):
            with self.subTest(value=bad):
                self.assertIn("REJECT", self.guard(bad).stdout,
                              f"vh_is_uuid accepted {bad!r}")

    def test_both_ends_of_the_round_trip_call_it(self):
        body = uncommented(PROVISION.read_text())
        upload_side = body[body.index("Uploading"): body.index("upload \"$f\"")]
        self.assertIn("vh_is_uuid", upload_side,
                      "a planted UUID is still pushed back to the node unvalidated")
        download_side = body[body.index('download "$rf"'):]
        download_side = download_side[: download_side.index("Provisioning complete")]
        self.assertIn("vh_is_uuid", download_side,
                      "what the node hands back is still stored unvalidated")


# ── VULN-011 ────────────────────────────────────────────────────────────────

class RegistryAddressUniquenessTest(unittest.TestCase):
    def setUp(self):
        body = GCP_STARTUP.read_text()
        self.reg = body[body.index("cat > /usr/local/bin/wg-register-peer.sh"):]
        self.reg = self.reg[: self.reg.index("\nREG\n")]

    def test_the_writer_refuses_an_address_another_peer_holds(self):
        self.assertIn("mesh_ip", self.reg)
        self.assertRegex(
            uncommented(self.reg), r"already registered to peer",
            "the writer still lets a peer register on an address another peer holds; "
            "the applier's seen-set only decides who wins, not who is evicted")

    def test_the_check_precedes_the_write(self):
        body = uncommented(self.reg)
        self.assertLess(
            body.index("already registered to peer"), body.index("vault kv put"),
            "the uniqueness check runs after the registry write")

    def test_identical_key_reregistration_is_still_allowed(self):
        """Anchor: routine `terraform apply` re-registers with an unchanged key."""
        self.assertIn('[ "$existing_pub" != "$pub" ]', self.reg,
                      "the identical-key idempotency path was lost")


# ── VULN-018 ────────────────────────────────────────────────────────────────

class KmsSignScopeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        body = AWS_MAIN.read_text()
        blk = body[body.index('resource "aws_iam_role_policy" '):]
        cls.policy = blk[: blk.index("\n}\n")]

    def statement_containing(self, action):
        for chunk in self.policy.split('Effect = "Allow"'):
            # Cut at the statement's own closing brace so the next statement's
            # explanatory comment cannot be read as part of this one.
            chunk = chunk.split("\n      },")[0]
            if f'"{action}"' in chunk:
                return chunk
        return None

    def test_sign_is_not_account_wide(self):
        st = self.statement_containing("kms:Sign")
        self.assertIsNotNone(st, "kms:Sign disappeared from the policy entirely")
        self.assertIn("kms:ResourceAliases", st,
                      "kms:Sign is still in an unconditioned statement, so the role "
                      "can sign with every asymmetric KMS key in the account")
        self.assertIn("alias/SPIRE_SERVER/*", st)

    def test_destructive_actions_stay_scoped(self):
        """Anchor: the half that was already fixed must not regress."""
        st = self.statement_containing("kms:ScheduleKeyDeletion")
        self.assertIsNotNone(st)
        self.assertIn("kms:ResourceAliases", st)

    def test_createkey_stays_unscoped(self):
        """CreateKey has no resource yet; scoping it would deny SPIRE its own keys."""
        st = self.statement_containing("kms:CreateKey")
        self.assertIsNotNone(st)
        self.assertNotIn("kms:ResourceAliases", st)


# ── VULN-038 ────────────────────────────────────────────────────────────────

class SelfAddressIpv6Test(unittest.TestCase):
    def setUp(self):
        self.body = render(TPL.read_text())

    def test_the_nodes_own_ipv6_is_blocked(self):
        self.assertIn("SELF_IP6_RULE", self.body,
                      "only the IPv4 self-address is blocked; the node keeps a "
                      "routable IPv6 by default and there is no host firewall")
        self.assertIn("/128", self.body)

    def test_both_self_rules_reach_the_routing_table(self):
        start = self.body.index('"rules": [')
        # "outbounds" precedes "rules" in this config, so bound the slice on the
        # array's own closing bracket instead.
        rules = self.body[start: self.body.index("\n          ]", start)]
        for var in ("$SELF_IP_RULE", "$SELF_IP6_RULE"):
            self.assertIn(var, rules, f"{var} is not interpolated into the routing rules")

    def test_link_local_v6_is_denied(self):
        self.assertIn("fe80::/10", self.body,
                      "IPv6 link-local is still reachable through the proxy")


# ── VULN-042 / 044 / 048 ────────────────────────────────────────────────────

class XraySetupUmaskTest(unittest.TestCase):
    def setUp(self):
        self.body = render(TPL.read_text())
        self.setup = self.body[self.body.index("CONFIG_DIR=/etc/xray"):]
        self.setup = self.setup[: self.setup.index("xray-setup.sh")] \
            if "xray-setup.sh" in self.setup else self.setup

    def test_the_script_sets_a_private_umask_before_any_write(self):
        head = self.body[: self.body.index("CONFIG_DIR=/etc/xray")]
        self.assertRegex(
            head.split("xray-setup.sh")[-1], r"umask 077",
            "config.json is still born at the ambient umask on a re-apply, where the "
            "keypair branch (and its branch-local umask) is skipped")

    def test_config_json_mode_is_still_narrowed_for_the_xray_group(self):
        """Anchor: xray must still be able to read its own config."""
        self.assertIn('chmod 640 "$CONFIG_FILE"', self.body)
        self.assertIn('chown root:xray "$CONFIG_FILE"', self.body)

    def test_etc_xray_is_not_world_traversable(self):
        self.assertIn("chmod 0750 /etc/xray", self.body,
                      "/etc/xray is still 0755, so any local account can reach "
                      "probe-client.json and config.json")
        self.assertIn("chown root:xray /etc/xray", self.body)

    def test_the_umask_idiom_yields_0600(self):
        """Behavioural, and platform-portable: GNU stat first, BSD as fallback."""
        p = sh('umask 077; printf secret > f; '
               'stat -c %a f 2>/dev/null || stat -f %Lp f',
               cwd=tempfile.mkdtemp())
        self.assertEqual(p.stdout.strip(), "600", f"got {p.stdout!r}")


# ── unfiled: the Hetzner analog of VULN-023 ─────────────────────────────────

class HetznerSecretRenderTest(unittest.TestCase):
    """Run the real renderer with the Vault API stubbed."""

    @staticmethod
    def fragment() -> str:
        body = FETCH.read_text()
        start = body.index("vh_reject() {")
        end = body.index('printf \'dns_cloudflare_api_token')
        end = body.index("\n", end) + 1
        return body[start:end]

    def render_with(self, url, user, key, token="cftokenabc123"):
        tmp = Path(tempfile.mkdtemp())
        vals = {"grafana prometheus_url": url, "grafana prometheus_user": user,
                "grafana api_key": key, "cloudflare api_token": token}
        for k, v in vals.items():
            (tmp / k.replace(" ", "_")).write_text(v)
        stub = 'kv() { cat "%s/$1_$2"; }\nRUN="%s"\n' % (tmp, tmp)
        p = sh(stub + self.fragment())
        p.env_file = (tmp / "grafana.env").read_text() if (tmp / "grafana.env").exists() else None
        p.ini_file = (tmp / "cloudflare.ini").read_text() if (tmp / "cloudflare.ini").exists() else None
        return p

    GOOD = ("https://prometheus-prod-01.grafana.net/api/prom/push", "1234567",
            "glc_eyJvIjoiMTIzIn0=")

    def test_legitimate_values_render(self):
        """Anchor: without this every rejection below could be an unconditional abort."""
        p = self.render_with(*self.GOOD)
        self.assertEqual(p.returncode, 0, f"a legitimate secret was rejected: {p.stderr}")
        self.assertIn(f"GRAFANA_URL={self.GOOD[0]}", p.env_file)
        self.assertIn("dns_cloudflare_api_token = cftokenabc123", p.ini_file)

    def test_a_newline_cannot_declare_another_variable(self):
        """grafana.env is a systemd EnvironmentFile — a newline adds a directive."""
        p = self.render_with(self.GOOD[0], "1234567\nGRAFANA_KEY=attacker", self.GOOD[2])
        self.assertNotEqual(p.returncode, 0, "a multi-line prometheus_user was accepted")
        self.assertIsNone(p.env_file, f"grafana.env was written:\n{p.env_file}")

    def test_a_plaintext_endpoint_is_rejected(self):
        p = self.render_with("http://prometheus-prod-01.grafana.net/api/prom/push",
                             self.GOOD[1], self.GOOD[2])
        self.assertNotEqual(p.returncode, 0, "a plaintext remote_write URL was accepted")

    def test_an_empty_value_is_rejected(self):
        p = self.render_with(self.GOOD[0], "", self.GOOD[2])
        self.assertNotEqual(p.returncode, 0, "an empty prometheus_user was accepted")
        self.assertIsNone(p.env_file)


if __name__ == "__main__":
    unittest.main()
