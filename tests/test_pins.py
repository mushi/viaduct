"""pins.json is the one place versions and digests live, and update-pins.sh moves them safely.

Terraform reads every boot-time version and digest from pins.json, so an automated PR
that edits the file is the whole update; nothing is left in terraform.tfvars to forget.
update-pins.sh picks the next version, so its rules are run here against canned
release listings: the cool-off, prereleases and drafts, the tag prefix, numeric
ordering, and never moving backwards.
"""

import json
import os
import re
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PINS_PATH = REPO_ROOT / "pins.json"
PINS = json.loads(PINS_PATH.read_text())
MAIN = (REPO_ROOT / "main.tf").read_text()
VARIABLES = (REPO_ROOT / "variables.tf").read_text()
UPDATE = REPO_ROOT / "scripts" / "update-pins.sh"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ENTRIES = {k: v for k, v in PINS.items() if isinstance(v, dict)}

# Template variable -> the pins.json path main.tf must read it from.
WIRING = {
    "conduit_version": 'local.pins.conduit.version',
    "conduit_sha256": 'local.pins.conduit.sha256["conduit-linux-amd64"]',
    "xray_version": 'local.pins.xray.version',
    "xray_zip_sha256": 'local.pins.xray.sha256["Xray-linux-64.zip"]',
    "xray_exporter_version": 'local.pins.xray_exporter.version',
    "xray_exporter_sha256": 'local.pins.xray_exporter.sha256["xray-exporter-linux-amd64"]',
    "alloy_version": 'local.pins.alloy.version',
    "alloy_zip_sha256": 'local.pins.alloy.sha256["alloy-linux-amd64.zip"]',
    "geoip_version": 'local.pins.geoip.version',
    "geoip_sha256": 'local.pins.geoip.sha256["geoip.dat"]',
    "geosite_version": 'local.pins.geosite.version',
    "geosite_sha256": 'local.pins.geosite.sha256["dlc.dat"]',
}


class PinsFileTest(unittest.TestCase):
    def test_every_entry_is_complete(self):
        self.assertTrue(ENTRIES)
        for name, e in ENTRIES.items():
            with self.subTest(entry=name):
                self.assertRegex(e["source"], r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
                self.assertIn("tag_prefix", e)
                self.assertTrue(e["version"].startswith(e["tag_prefix"]),
                                "the pinned version would never be compared with its upstream releases")
                self.assertTrue(e["sha256"])
                for asset, digest in e["sha256"].items():
                    self.assertRegex(digest, SHA256_RE, f"{name}/{asset}")

    def test_digests_are_distinct(self):
        digests = [d for e in ENTRIES.values() for d in e["sha256"].values()]
        self.assertEqual(len(digests), len(set(digests)), "two assets share a digest: a copy-paste slip")

    def test_terraform_reads_every_pin_from_pins_json(self):
        for var, path in WIRING.items():
            with self.subTest(template_var=var):
                self.assertRegex(MAIN, rf"(?m)^\s*{var}\s*=\s*{re.escape(path)}\s*$")

    def test_wired_paths_exist(self):
        for var, path in WIRING.items():
            with self.subTest(template_var=var):
                m = re.fullmatch(r'local\.pins\.(\w+)\.(version|sha256\["([^"]+)"\])', path)
                entry = ENTRIES[m.group(1)]
                if m.group(3):
                    self.assertIn(m.group(3), entry["sha256"])

    def test_no_pin_left_as_a_variable(self):
        for var in WIRING:
            self.assertNotIn(f'variable "{var}"', VARIABLES,
                             f"{var} is a variable again; a tfvars value would silently override pins.json")


def release(tag, days_ago, prerelease=False, draft=False):
    t = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return {"tag_name": tag, "published_at": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "prerelease": prerelease, "draft": draft,
            "html_url": f"https://github.com/o/r/releases/tag/{tag}"}


class UpdatePinsTest(unittest.TestCase):
    """Run update-pins.sh with a stub curl that serves a canned release listing."""

    def run_update(self, version, prefix, listing, extra_env=None):
        tmp = Path(tempfile.mkdtemp())
        pins = tmp / "pins.json"
        pins.write_text(json.dumps({
            "$comment": "x",
            "thing": {"source": "o/r", "tag_prefix": prefix, "version": version,
                      "sha256": {"a.bin": "0" * 64}},
        }))
        (tmp / "releases.json").write_text(json.dumps(listing))
        binp = tmp / "bin"
        binp.mkdir()
        (binp / "curl").write_text(f'#!/usr/bin/env bash\ncat "{tmp}/releases.json"\n')
        (binp / "curl").chmod(0o755)
        env = dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}", PINS_FILE=str(pins),
                   SUMMARY_FILE=str(tmp / "summary.md"), **(extra_env or {}))
        env.pop("GITHUB_TOKEN", None)
        p = subprocess.run(["bash", str(UPDATE)], capture_output=True, text=True,
                           env=env, timeout=60, stdin=subprocess.DEVNULL)
        p.version = json.loads(pins.read_text())["thing"]["version"]
        p.summary = (tmp / "summary.md").read_text()
        return p

    def test_moves_to_newest_release_past_the_cool_off(self):
        p = self.run_update("v1.2.0", "v", [release("v1.3.0", 10), release("v1.2.0", 30)])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.version, "v1.3.0")
        self.assertIn("`v1.2.0` → `v1.3.0`", p.summary)

    def test_a_release_inside_the_cool_off_waits(self):
        p = self.run_update("v1.2.0", "v", [release("v1.4.0", 2), release("v1.3.0", 5)])
        self.assertEqual(p.version, "v1.3.0", "a 2-day-old release was taken")

    def test_cool_off_is_four_days_by_default(self):
        p = self.run_update("v1.2.0", "v", [release("v1.3.0", 3.9)])
        self.assertEqual(p.version, "v1.2.0")
        p = self.run_update("v1.2.0", "v", [release("v1.3.0", 4.1)])
        self.assertEqual(p.version, "v1.3.0")

    def test_majors_are_taken(self):
        p = self.run_update("v1.9.0", "v", [release("v2.0.0", 10)])
        self.assertEqual(p.version, "v2.0.0")

    def test_prereleases_and_drafts_are_ignored(self):
        p = self.run_update("v1.2.0", "v", [release("v1.4.0", 10, prerelease=True),
                                            release("v1.5.0", 10, draft=True)])
        self.assertEqual(p.version, "v1.2.0")

    def test_other_tag_families_are_ignored(self):
        p = self.run_update("release-cli-2.1.0", "release-cli-",
                            [release("release-android-9.0.0", 10), release("release-cli-2.2.0", 10)])
        self.assertEqual(p.version, "release-cli-2.2.0")

    def test_numeric_not_lexical_order(self):
        p = self.run_update("v26.11.9", "v", [release("v26.11.10", 10), release("v26.11.9", 20)])
        self.assertEqual(p.version, "v26.11.10")

    def test_a_later_backport_is_not_chosen_over_a_newer_line(self):
        p = self.run_update("v1.21.3", "v", [release("v1.20.9", 5), release("v1.22.0", 9)])
        self.assertEqual(p.version, "v1.22.0")

    def test_never_moves_backwards(self):
        p = self.run_update("v1.22.0", "v", [release("v1.21.9", 10)])
        self.assertEqual(p.version, "v1.22.0")
        self.assertEqual(p.summary, "")

    def test_dated_geo_tags(self):
        p = self.run_update("20261101000000", "", [release("20261110034535", 5), release("20261115151618", 0)])
        self.assertEqual(p.version, "20261110034535")

    def test_a_tag_with_shell_characters_is_skipped(self):
        p = self.run_update("v1.2.0", "v", [release("v1.3.0;reboot", 10), release("v1.2.5", 10)])
        self.assertEqual(p.version, "v1.2.5")

    def test_an_api_error_fails_loudly(self):
        p = self.run_update("v1.2.0", "v", {"message": "API rate limit exceeded"})
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(p.version, "v1.2.0")
        self.assertIn("could not check", p.stderr)


if __name__ == "__main__":
    unittest.main()
