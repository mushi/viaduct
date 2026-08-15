"""Security test: VULN-018 — destructive KMS actions must not carry Resource "*".

CWE-732. aws/main.tf granted the SPIRE instance role a single KMS statement with
Resource = "*", including kms:ScheduleKeyDeletion, kms:DeleteAlias and kms:UpdateAlias.
The instance role could therefore schedule deletion of any KMS key in the account, not
merely the keys SPIRE created. The file's own comment already proposes the remedy:
condition the destructive actions on the tag SPIRE applies to its keys.

The sink is the rendered IAM policy, so the assertions read the policy document.
"""

import json
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MAIN_TF = REPO_ROOT / "aws" / "main.tf"

# Genuinely destructive / signing actions that must stay resource-scoped. kms:UpdateAlias
# is NOT here: it is alias management, and it must run UNCONDITIONED — on CA rotation SPIRE
# repoints the alias to a freshly created key with no SPIRE_SERVER/ alias yet, so a
# kms:ResourceAliases condition matches nothing and denies the rotation (the server then
# crash-loops). See test_update_alias_must_be_unconditioned.
DESTRUCTIVE = {"kms:ScheduleKeyDeletion", "kms:DeleteAlias"}


def kms_policy_statements():
    """Extract the statement objects from the spire-aws-kms policy document."""
    text = MAIN_TF.read_text()
    m = re.search(r'resource "aws_iam_role_policy" "kms" \{(.*?)\n\}', text, re.S)
    if not m:
        raise AssertionError('could not locate aws_iam_role_policy "kms" in aws/main.tf')
    block = m.group(1)
    # Statement = [ { ... }, { ... } ] — pull each top-level object.
    stmts, depth, start = [], 0, None
    region = block[block.index("Statement"):]
    for i, ch in enumerate(region):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                stmts.append(region[start:i + 1])
                start = None
    if not stmts:
        raise AssertionError("no statement objects found in the kms policy")
    return stmts


def actions_of(stmt: str):
    m = re.search(r"Action\s*=\s*\[(.*?)\]", stmt, re.S)
    if not m:
        one = re.search(r'Action\s*=\s*"([^"]+)"', stmt)
        return {one.group(1)} if one else set()
    return set(re.findall(r'"([^"]+)"', m.group(1)))


class KmsScopeTest(unittest.TestCase):
    def setUp(self):
        self.stmts = kms_policy_statements()

    def test_destructive_actions_are_scoped(self):
        """Unscoped destruction is the defect.

        AWS cannot resource-scope kms:ScheduleKeyDeletion by ARN for keys created at
        runtime, so the idiomatic control is Resource "*" plus a condition key. What
        must never hold is a destructive action reachable with neither.
        """
        for stmt in self.stmts:
            acts = actions_of(stmt) & DESTRUCTIVE
            if not acts:
                continue
            wildcard = re.search(r'Resource\s*=\s*"\*"', stmt) is not None
            conditioned = "Condition" in stmt
            self.assertFalse(
                wildcard and not conditioned,
                f"destructive KMS actions {sorted(acts)} are granted on Resource \"*\" "
                f"with no Condition: the instance role can schedule deletion of any key "
                f"in the account",
            )

    def test_non_destructive_actions_are_not_silently_conditioned_away(self):
        """CreateKey/List* must stay reachable, or the KeyManager cannot bootstrap."""
        for stmt in self.stmts:
            if "kms:CreateKey" in actions_of(stmt):
                self.assertNotIn(
                    "kms:ScheduleKeyDeletion", actions_of(stmt),
                    "create and destroy are still in one statement, so any condition "
                    "added for destruction also gates key creation",
                )

    def test_destructive_actions_carry_a_condition(self):
        found = False
        for stmt in self.stmts:
            if actions_of(stmt) & DESTRUCTIVE:
                found = True
                self.assertIn(
                    "Condition", stmt,
                    "the destructive-action statement has no Condition scoping it to "
                    "keys SPIRE created",
                )
        self.assertTrue(found, "no statement grants the destructive KMS actions at all — "
                               "SPIRE needs them for its own keys")

    def test_update_alias_must_be_unconditioned(self):
        """Regression: kms:UpdateAlias conditioned on kms:ResourceAliases crash-loops the
        server. On rotation the alias is repointed to a brand-new key that has no
        SPIRE_SERVER/ alias yet, so the condition can never match. It must be granted in a
        statement with NO Condition (it is alias management, not signing or destruction)."""
        granting = [s for s in self.stmts if "kms:UpdateAlias" in actions_of(s)]
        self.assertTrue(granting, "kms:UpdateAlias not granted at all — the SPIRE server "
                                  "cannot rotate its X509 CA and will crash-loop")
        for stmt in granting:
            self.assertNotIn(
                "Condition", stmt,
                "kms:UpdateAlias is in a conditioned statement; on rotation the target key "
                "has no alias yet, so the condition denies it and the server crash-loops")

    def test_schedule_key_deletion_is_tag_scoped_not_alias_scoped(self):
        """Regression: ScheduleKeyDeletion conditioned on kms:ResourceAliases cannot prune.
        SPIRE repoints a key's alias to its replacement BEFORE pruning the old key, so the
        orphaned key carries no SPIRE_SERVER/ alias and an alias condition matches nothing
        — the prune is denied and superseded keys linger. It must be scoped by kms:ResourceTag
        (a tag survives the alias move), still conditioned (never blanket Resource "*")."""
        granting = [s for s in self.stmts if "kms:ScheduleKeyDeletion" in actions_of(s)]
        self.assertTrue(granting, "kms:ScheduleKeyDeletion not granted — SPIRE cannot prune "
                                  "rotated keys and they accrue cost indefinitely")
        for stmt in granting:
            self.assertIn("Condition", stmt,
                          "ScheduleKeyDeletion is unconditioned on Resource \"*\": the instance "
                          "role could schedule deletion of any KMS key in the account")
            self.assertIn("kms:ResourceTag/", stmt,
                          "ScheduleKeyDeletion is not tag-scoped")
            self.assertNotIn(
                "kms:ResourceAliases", stmt,
                "ScheduleKeyDeletion is alias-scoped; a rotated key's alias has already moved, "
                "so the prune is denied and orphaned keys linger (the pruning bug)")

    def test_sign_is_alias_scoped_not_account_wide(self):
        """VULN-018: kms:Sign unscoped let the instance role sign with every asymmetric
        KMS key in the account. SPIRE aliases a key before it ever signs with it, so Sign
        must sit in the kms:ResourceAliases-conditioned statement (alias/SPIRE_SERVER/*)."""
        granting = [s for s in self.stmts if "kms:Sign" in actions_of(s)]
        self.assertTrue(granting, "kms:Sign disappeared from the policy entirely")
        for stmt in granting:
            self.assertIn("kms:ResourceAliases", stmt,
                          "kms:Sign is in an unconditioned statement, so the role can sign "
                          "with every asymmetric KMS key in the account")
            self.assertIn("alias/SPIRE_SERVER/", stmt)

    def test_spire_can_still_create_and_sign(self):
        """The fix must not break SPIRE's normal operation."""
        all_actions = set()
        for stmt in self.stmts:
            all_actions |= actions_of(stmt)
        for needed in ("kms:CreateKey", "kms:Sign", "kms:DescribeKey", "kms:ListKeys"):
            self.assertIn(needed, all_actions,
                          f"{needed} was dropped; the SPIRE KMS KeyManager would break")


class KmsTagSyncTest(unittest.TestCase):
    """The tag that scopes ScheduleKeyDeletion in the IAM policy must be exactly the tag
    SPIRE stamps on the keys it creates. If they drift, SPIRE's keys don't carry the tag
    the policy requires and every prune is silently denied — the pruning bug returns with
    no error at apply time. This pins the two together across the two files."""

    STARTUP_TPL = REPO_ROOT / "aws" / "scripts" / "startup.sh.tpl"

    def test_iam_resourcetag_matches_spire_key_tags(self):
        policy = MAIN_TF.read_text()
        m = re.search(r'"kms:ResourceTag/([^"]+)"\s*=\s*"([^"]+)"', policy)
        self.assertIsNotNone(
            m, "no kms:ResourceTag condition in the KMS policy; ScheduleKeyDeletion is no "
               "longer tag-scoped")
        iam_key, iam_val = m.group(1), m.group(2)

        tpl = self.STARTUP_TPL.read_text()
        block = re.search(r"key_tags\s*=\s*\{(.*?)\}", tpl, re.S)
        self.assertIsNotNone(
            block, "the aws_kms KeyManager sets no key_tags, so SPIRE tags none of its keys "
                   "and the IAM ResourceTag condition can never match — pruning stays broken")
        pair = re.search(r'"([^"]+)"\s*=\s*"([^"]+)"', block.group(1))
        self.assertIsNotNone(pair, "key_tags block has no \"key\" = \"value\" entry")
        tpl_key, tpl_val = pair.group(1), pair.group(2)

        self.assertEqual(
            (iam_key, iam_val), (tpl_key, tpl_val),
            f"IAM condition tags kms:ResourceTag/{iam_key}={iam_val!r} but SPIRE stamps "
            f"{tpl_key}={tpl_val!r}; they must match or every ScheduleKeyDeletion is denied")


if __name__ == "__main__":
    unittest.main()
