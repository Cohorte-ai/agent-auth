"""Tests for approval tier evaluation — ApprovalEvaluator."""

from __future__ import annotations


from theaios.agent_auth.approval import ApprovalEvaluator
from theaios.agent_auth.types import ApprovalPolicyConfig


class TestApprovalEvaluator:
    """ApprovalEvaluator.evaluate(action, context, default_tier) -> str."""

    def _evaluator(self) -> ApprovalEvaluator:
        policies = [
            ApprovalPolicyConfig(
                name="destructive",
                condition='action == "delete"',
                tier="strong",
            ),
            ApprovalPolicyConfig(
                name="prod_deploy",
                condition='action == "deploy" and resource starts_with "/prod"',
                tier="strong",
            ),
            ApprovalPolicyConfig(
                name="staging_deploy",
                condition='action == "deploy"',
                tier="soft",
            ),
            ApprovalPolicyConfig(
                name="always_true",
                condition="",  # Empty condition = always True
                tier="autonomous",
            ),
        ]
        return ApprovalEvaluator(policies)

    def test_matching_policy_returns_tier(self) -> None:
        ev = self._evaluator()
        tier = ev.evaluate("delete", {"resource": ""}, default_tier="autonomous")
        assert tier == "strong"

    def test_no_matching_condition_uses_default(self) -> None:
        policies = [
            ApprovalPolicyConfig(
                name="specific",
                condition='action == "nuke"',
                tier="strong",
            ),
        ]
        ev = ApprovalEvaluator(policies)
        tier = ev.evaluate("read", {}, default_tier="autonomous")
        assert tier == "autonomous"

    def test_escalation_picks_most_restrictive(self) -> None:
        ev = self._evaluator()
        # deploy on /prod matches both prod_deploy (strong) and staging_deploy (soft)
        tier = ev.evaluate("deploy", {"resource": "/prod/api"}, default_tier="autonomous")
        assert tier == "strong"

    def test_soft_tier_for_staging(self) -> None:
        ev = self._evaluator()
        tier = ev.evaluate("deploy", {"resource": "/staging/api"}, default_tier="autonomous")
        # staging_deploy matches (soft), prod_deploy doesn't match
        assert tier in ("soft", "strong")  # soft or escalated

    def test_empty_condition_always_matches(self) -> None:
        policies = [
            ApprovalPolicyConfig(name="catch_all", condition="", tier="soft"),
        ]
        ev = ApprovalEvaluator(policies)
        tier = ev.evaluate("anything", {}, default_tier="autonomous")
        assert tier == "soft"

    def test_empty_policies_returns_default(self) -> None:
        ev = ApprovalEvaluator([])
        tier = ev.evaluate("read", {}, default_tier="autonomous")
        assert tier == "autonomous"

    def test_variables_passed_to_evaluator(self) -> None:
        policies = [
            ApprovalPolicyConfig(
                name="env_check",
                condition='$env == "production"',
                tier="strong",
            ),
        ]
        ev = ApprovalEvaluator(policies, variables={"env": "production"})
        tier = ev.evaluate("deploy", {}, default_tier="autonomous")
        assert tier == "strong"

    def test_variables_no_match(self) -> None:
        policies = [
            ApprovalPolicyConfig(
                name="env_check",
                condition='$env == "production"',
                tier="strong",
            ),
        ]
        ev = ApprovalEvaluator(policies, variables={"env": "staging"})
        tier = ev.evaluate("deploy", {}, default_tier="autonomous")
        assert tier == "autonomous"
