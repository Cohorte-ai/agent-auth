"""Tests for agent-to-agent (A2A) authorization — A2AEvaluator."""

from __future__ import annotations


from theaios.agent_auth.a2a import A2AEvaluator
from theaios.agent_auth.types import A2AConfig, A2APolicyConfig


class TestA2AEvaluator:
    """A2AEvaluator.evaluate(from_agent, to_agent, action) -> (bool, str)."""

    def _config(self, default: str = "deny") -> A2AConfig:
        return A2AConfig(
            default=default,
            policies=[
                A2APolicyConfig(
                    name="assistant-reviewer",
                    from_agent="assistant",
                    to_agent="reviewer",
                    action="read",
                    effect="allow",
                ),
                A2APolicyConfig(
                    name="assistant-deployer-deny",
                    from_agent="assistant",
                    to_agent="deployer",
                    action="deploy",
                    effect="deny",
                ),
                A2APolicyConfig(
                    name="any-to-logger",
                    from_agent="*",
                    to_agent="logger",
                    action="log",
                    effect="allow",
                ),
                A2APolicyConfig(
                    name="scanner-wildcard",
                    from_agent="scanner",
                    to_agent="*",
                    action="scan",
                    effect="allow",
                    condition='action == "scan"',
                ),
            ],
        )

    def test_explicit_allow(self) -> None:
        ev = A2AEvaluator(self._config())
        allowed, reason = ev.evaluate("assistant", "reviewer", "read")
        assert allowed is True

    def test_explicit_deny(self) -> None:
        ev = A2AEvaluator(self._config())
        allowed, reason = ev.evaluate("assistant", "deployer", "deploy")
        assert allowed is False

    def test_wildcard_from_agent(self) -> None:
        ev = A2AEvaluator(self._config())
        allowed, reason = ev.evaluate("any_agent", "logger", "log")
        assert allowed is True

    def test_wildcard_to_agent_with_condition(self) -> None:
        ev = A2AEvaluator(self._config())
        allowed, reason = ev.evaluate("scanner", "any_target", "scan")
        assert allowed is True

    def test_default_deny(self) -> None:
        ev = A2AEvaluator(self._config(default="deny"))
        allowed, reason = ev.evaluate("unknown", "unknown", "unknown")
        assert allowed is False

    def test_default_allow(self) -> None:
        ev = A2AEvaluator(self._config(default="allow"))
        allowed, reason = ev.evaluate("unknown", "unknown", "unknown")
        assert allowed is True

    def test_no_matching_rule_uses_default(self) -> None:
        ev = A2AEvaluator(self._config())
        allowed, reason = ev.evaluate("assistant", "reviewer", "deploy")
        assert allowed is False  # default is deny, no rule matches this action

    def test_deny_overrides_allow(self) -> None:
        # If both deny and allow match, deny wins
        config = A2AConfig(
            default="allow",
            policies=[
                A2APolicyConfig(
                    name="allow-all",
                    from_agent="*",
                    to_agent="*",
                    action="*",
                    effect="allow",
                ),
                A2APolicyConfig(
                    name="deny-deploy",
                    from_agent="*",
                    to_agent="*",
                    action="deploy",
                    effect="deny",
                ),
            ],
        )
        ev = A2AEvaluator(config)
        allowed, reason = ev.evaluate("a", "b", "deploy")
        assert allowed is False
