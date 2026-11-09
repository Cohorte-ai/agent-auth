"""A typo in a condition must never turn a policy off.

Before 0.1.3, an approval or A2A condition naming an undefined `$variable` passed validation,
raised at every evaluation and was skipped: `resource == $protectd` let deletes on prod run
autonomously.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from theaios.agent_auth.a2a import A2AEvaluator
from theaios.agent_auth.approval import ApprovalEvaluator
from theaios.agent_auth.config import ConfigError, load_config
from theaios.agent_auth.expressions import ExpressionError
from theaios.agent_auth.types import A2AConfig, A2APolicyConfig, ApprovalPolicyConfig

TYPO_CONFIG = """
version: "1.0"
variables:
  protected: prod
roles:
  ops:
    actions: [delete]
profiles:
  bot:
    role: ops
approval_policies:
  - name: protect-prod
    condition: 'action == "delete" and resource == $protectd'
    tier: strong
a2a:
  default: allow
  policies:
    - name: no-exfil
      effect: deny
      condition: 'action == "send" and target in $blocked'
    - name: matcher
      effect: deny
      condition: 'content matches pii'
"""


def test_load_rejects_undefined_variable_and_matches(tmp_path: Path) -> None:
    path = tmp_path / "agent_auth.yaml"
    path.write_text(TYPO_CONFIG)
    with pytest.raises(ConfigError) as exc:
        load_config(str(path))
    errors = "\n".join(exc.value.errors)
    assert "undefined variable '$protectd' (did you mean 'protected'?)" in errors
    assert "undefined variable '$blocked'" in errors
    assert "'matches pii', but agent-auth has no matchers" in errors


def test_evaluators_built_in_code_reject_undefined_variable() -> None:
    with pytest.raises(ExpressionError, match="protectd"):
        ApprovalEvaluator(
            [ApprovalPolicyConfig(name="p", condition="resource == $protectd", tier="strong")],
            {"protected": "prod"},
        )
    with pytest.raises(ExpressionError, match="blocked"):
        A2AEvaluator(
            A2AConfig(
                policies=[A2APolicyConfig(name="p", effect="deny", condition="x in $blocked")]
            )
        )


def test_correct_policy_still_escalates() -> None:
    ev = ApprovalEvaluator(
        [ApprovalPolicyConfig(name="p", condition="resource == $protected", tier="strong")],
        {"protected": "prod"},
    )
    assert ev.evaluate("delete", {"resource": "prod"}) == "strong"
    assert ev.evaluate("delete", {"resource": "dev"}) == "autonomous"


def test_approval_policy_that_cannot_be_evaluated_applies_its_tier() -> None:
    variables: dict[str, object] = {"protected": "prod"}
    ev = ApprovalEvaluator(
        [ApprovalPolicyConfig(name="p", condition="resource == $protected", tier="strong")],
        variables,
    )
    variables.clear()  # the variable disappears after validation
    assert ev.evaluate("delete", {"resource": "dev"}) == "strong"


def _a2a(effect: str, default: str) -> A2AEvaluator:
    variables: dict[str, object] = {"blocked": ["x"]}
    ev = A2AEvaluator(
        A2AConfig(
            default=default,
            policies=[A2APolicyConfig(name="p", effect=effect, condition="target in $blocked")],
        ),
        variables,
    )
    variables.clear()
    return ev


def test_a2a_deny_policy_that_cannot_be_evaluated_denies() -> None:
    allowed, reason = _a2a("deny", default="allow").evaluate("a", "b", "send", {"target": "y"})
    assert not allowed
    assert "p" in reason


def test_a2a_allow_policy_that_cannot_be_evaluated_grants_nothing() -> None:
    allowed, _ = _a2a("allow", default="deny").evaluate("a", "b", "send", {"target": "x"})
    assert not allowed
