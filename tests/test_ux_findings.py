"""Regression tests for the 0.1.3 pre-release usability test.

Each test is a mistake a tester made that used to load as a valid config and change what it
does, in two cases allowing what it was written to block.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from theaios.agent_auth.config import ConfigError, load_config
from theaios.agent_auth.engine import AuthEngine
from theaios.agent_auth.types import ApprovalPolicyConfig, AuthConfig, AuthRequest

BASE = """
version: "1.0"
variables:
  protected: /ledger/main
roles:
  ops:
    actions: [read, delete, send]
profiles:
  finbot:
    role: ops
"""


def _errors(tmp_path: Path, body: str) -> str:
    path = tmp_path / "agent_auth.yaml"
    path.write_text(BASE + body)
    with pytest.raises(ConfigError) as exc:
        load_config(str(path))
    return "\n".join(exc.value.errors)


def test_approval_policies_as_mapping_is_rejected(tmp_path: Path) -> None:
    body = "approval_policies:\n  destructive: {condition: 'action == \"delete\"', tier: strong}\n"
    assert "approval_policies: must be a list" in _errors(tmp_path, body)


def test_guardrails_style_from_to_in_a2a_is_rejected(tmp_path: Path) -> None:
    body = (
        "a2a:\n  default: deny\n  policies:\n    - name: reporter-only\n"
        "      from: reporter\n      to: finbot\n      effect: allow\n"
    )
    errors = _errors(tmp_path, body)
    assert (
        "a2a.policies[0] (reporter-only): unknown key 'from' (did you mean 'from_agent'?)" in errors
    )
    assert "unknown key 'to' (did you mean 'to_agent'?)" in errors


def test_misspelled_condition_key_is_rejected(tmp_path: Path) -> None:
    body = (
        "approval_policies:\n  - name: d\n    conditon: 'action == \"delete\"'\n    tier: strong\n"
    )
    assert "unknown key 'conditon' (did you mean 'condition'?)" in _errors(tmp_path, body)


def test_misspelled_top_level_key_is_rejected(tmp_path: Path) -> None:
    errors = _errors(tmp_path, "profils:\n  x: {role: ops}\n")
    assert "unknown key 'profils' (did you mean 'profiles'?)" in errors


def test_non_string_condition_is_rejected(tmp_path: Path) -> None:
    body = "approval_policies:\n  - name: d\n    condition: 42\n    tier: strong\n"
    assert "'condition' must be a string" in _errors(tmp_path, body)


def test_quoted_boolean_is_rejected(tmp_path: Path) -> None:
    assert "'enabled' must be true or false" in _errors(tmp_path, 'audit:\n  enabled: "false"\n')


def test_not_a_config_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "mkdocs.yml"
    path.write_text("site_name: Docs\n")
    with pytest.raises(ConfigError, match="unknown key 'site_name'"):
        load_config(str(path))


def test_yaml_syntax_error_and_directory_are_config_errors(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text('version: "1.0"\nroles:\n  x: {actions: [a\n')
    with pytest.raises(ConfigError, match="YAML syntax error"):
        load_config(str(path))
    with pytest.raises(ConfigError, match="is not a file"):
        load_config(str(tmp_path))


def test_engine_built_in_code_is_validated() -> None:
    config = AuthConfig(
        approval_policies=[ApprovalPolicyConfig(name="p", condition="x == 1", tier="medium")]
    )
    with pytest.raises(ConfigError, match="invalid tier 'medium'"):
        AuthEngine(config)


def test_string_values_still_escalate_correctly(tmp_path: Path) -> None:
    path = tmp_path / "ok.yaml"
    path.write_text(
        BASE
        + "approval_policies:\n  - name: protect\n"
        + "    condition: 'action == \"delete\" and resource == $protected'\n    tier: strong\n"
        + "audit:\n  enabled: false\n"
    )
    engine = AuthEngine(load_config(str(path)))
    decision = engine.authorize(
        AuthRequest(agent="finbot", user="u", action="delete", resource="/ledger/main")
    )
    assert decision.requires_approval and decision.tier == "strong" and not decision.is_autonomous


# --- Re-verification findings ------------------------------------------------------------

PAY = """
variables:
  cap: 5000
approval_policies:
  - name: never
    condition: 'action == "nothing"'
    tier: strong
  - name: big-payments
    condition: 'action == "pay" and metadata.amount > $cap'
    tier: soft
  - name: protect
    condition: 'action == "delete" and resource == $protected'
    tier: strong
audit:
  enabled: false
"""


def _engine(tmp_path: Path) -> AuthEngine:
    path = tmp_path / "pay.yaml"
    base = BASE.replace("[read, delete, send]", "[read, delete, send, pay]")
    base = base.replace("  protected: /ledger/main\n", "  protected: /ledger/main\n  cap: 5000\n")
    path.write_text(base + PAY.replace("variables:\n  cap: 5000\n", ""))
    return AuthEngine(load_config(str(path)))


def test_metadata_dot_key_conditions_apply(tmp_path: Path) -> None:
    decision = _engine(tmp_path).authorize(
        AuthRequest(agent="finbot", user="u", action="pay", metadata={"amount": 10000})
    )
    assert decision.requires_approval and decision.tier == "soft"
    assert decision.approval_policy == "big-payments"


def test_metadata_cannot_overwrite_the_resource(tmp_path: Path) -> None:
    decision = _engine(tmp_path).authorize(
        AuthRequest(
            agent="finbot",
            user="u",
            action="delete",
            resource="/ledger/main",
            metadata={"resource": "/tmp/scratch"},
        )
    )
    assert decision.tier == "strong"
    assert decision.approval_policy == "protect"


def test_when_key_in_agent_auth_suggests_condition(tmp_path: Path) -> None:
    body = "approval_policies:\n  - name: d\n    when: 'action == \"delete\"'\n    tier: strong\n"
    assert "unknown key 'when' (did you mean 'condition'?)" in _errors(tmp_path, body)


def test_cli_check_shows_brackets_verbatim(tmp_path: Path) -> None:
    from click.testing import CliRunner

    from theaios.agent_auth.cli import main

    path = tmp_path / "a.yaml"
    path.write_text(BASE + "audit:\n  enabled: false\n")
    result = CliRunner().invoke(
        main, ["-c", str(path), "check", "--agent", "[bot]", "--user", "u", "--action", "[act]"]
    )
    assert "'[act]'" in result.output and "'[bot]'" in result.output


def test_a_delegation_applies_only_to_the_user_who_granted_it(tmp_path: Path) -> None:
    import os

    path = tmp_path / "agent_auth.yaml"
    path.write_text(BASE + "audit:\n  enabled: false\n")
    cwd = os.getcwd()
    os.chdir(tmp_path)  # delegations are stored under ./.agent_auth
    try:
        engine = AuthEngine(load_config(str(path)))
        engine.create_delegation(
            from_user="bob",
            to_agent="finbot",
            actions=["send_report"],
            duration=600,
            reason="weekly",
        )
        bob = engine.authorize(AuthRequest(agent="finbot", user="bob", action="send_report"))
        alice = engine.authorize(AuthRequest(agent="finbot", user="alice", action="send_report"))
    finally:
        os.chdir(cwd)
    assert bob.allowed
    assert not alice.allowed


def test_guardrails_adapter_checks_the_tool_of_a_tool_call(tmp_path: Path) -> None:
    pytest.importorskip("theaios.guardrails")
    from theaios.guardrails.engine import Engine
    from theaios.guardrails.types import GuardEvent, PolicyConfig

    from theaios.agent_auth.adapters.guardrails import GuardrailsAuthAdapter

    path = tmp_path / "agent_auth.yaml"
    path.write_text(
        'version: "1.0"\nroles:\n  all: {actions: ["*"]}\n'
        "profiles:\n  bot: {role: all, deny: ['payments:*']}\naudit:\n  enabled: false\n"
    )
    adapter = GuardrailsAuthAdapter(load_config(str(path)), Engine(PolicyConfig()))

    def outcome(data: dict[str, object], scope: str = "tool_call") -> str:
        return adapter.evaluate(GuardEvent(scope=scope, agent="bot", data=data), user="u").outcome

    # guardrails' LangChain and OpenAI Agents adapters send the tool as data["tool_name"]
    assert outcome({"tool_name": "payments:transfer", "arguments": {}}) == "deny"
    assert outcome({"tool_name": "read:docs", "arguments": {}}) == "allow"
    assert outcome({"tool_name": "payments:transfer", "action": "read:docs"}) == "deny"
    assert outcome({"tool_name": "read:docs", "action": "read:docs"}) == "allow"
    assert outcome({"arguments": {}}) == "deny"  # a tool call must name its tool
    assert outcome({"action": ["payments:transfer"]}, scope="action") == "deny"  # not str()
    assert outcome({"action": "read:x", "resource": ["inv-1"]}, scope="action") == "deny"
    assert outcome({"action": "read:x"}, scope="action") == "allow"


def test_middleware_decides_head_as_get(tmp_path: Path) -> None:
    import asyncio

    pytest.importorskip("starlette")
    from theaios.agent_auth.adapters.middleware import fastapi_auth_middleware

    path = tmp_path / "agent_auth.yaml"
    path.write_text(
        BASE.replace("role: ops", "role: ops\n    allow: ['*']\n    deny: ['get:/admin*']")
        + "audit:\n  enabled: false\n"
    )
    engine = AuthEngine(load_config(str(path)))

    class URL:
        path = "/admin/users"

    class Req:
        def __init__(self, method: str) -> None:
            self.method, self.url = method, URL()
            self.headers = {"X-Agent-Name": "finbot", "X-User-Name": "alice"}

    async def ok(_req: object) -> str:
        return "ran"

    for method in ("GET", "HEAD"):  # HEAD runs the GET handler
        out = asyncio.run(fastapi_auth_middleware(engine, Req(method), ok))
        assert out != "ran", method
