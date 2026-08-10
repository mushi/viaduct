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

DESTRUCTIVE = {"kms:ScheduleKeyDeletion", "kms:DeleteAlias", "kms:UpdateAlias"}


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

    def test_spire_can_still_create_and_sign(self):
        """The fix must not break SPIRE's normal operation."""
        all_actions = set()
        for stmt in self.stmts:
            all_actions |= actions_of(stmt)
        for needed in ("kms:CreateKey", "kms:Sign", "kms:DescribeKey", "kms:ListKeys"):
            self.assertIn(needed, all_actions,
                          f"{needed} was dropped; the SPIRE KMS KeyManager would break")


if __name__ == "__main__":
    unittest.main()
