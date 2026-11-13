"""Regression tests for the agent-auth 0.2.0 pre-release test (newcomer, red team, integrator).

Each test reproduces one finding against the first 0.2 build (b6971ae).
"""

from __future__ import annotations

import base64
import json
import os
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from click.testing import CliRunner

from theaios.agent_auth import AuthEngine, AuthRequest, Principal, TokenError, load_config
from theaios.agent_auth.cli import main as cli
from theaios.agent_auth.config import ConfigError
from theaios.agent_auth.resolution import ResolvedAgent, covers

BASE = """
version: "1.0"
roles:
  reader: {actions: ["read:*"]}
  everything: {actions: ["*"]}
profiles:
  assistant:
    role: reader
    access: [finance, sales, "user:alice"]
    grants:
      finance: [approve_invoice, "export:ledger"]
  researcher: {role: reader}
  intern-bot: {role: everything}
  nightly: {role: reader, access: [service]}
  payer:
    allow: [create_payment, approve_payment]
"""
ROLES = {"alice": ["finance"], "bob": ["sales"]}
KEY = b"k" * 32


@pytest.fixture(autouse=True)
def _in_tmp(tmp_path: Path) -> Iterator[None]:
    cwd = os.getcwd()
    os.chdir(tmp_path)
    yield
    os.chdir(cwd)


def _engine(tmp_path: Path, extra: str = "", **kw: object) -> AuthEngine:
    path = tmp_path / "agent_auth.yaml"
    path.write_text(BASE + extra + "audit:\n  enabled: false\n")
    kw.setdefault("user_roles", lambda u: ROLES.get(u, []))
    kw.setdefault("token_key", KEY)
    return AuthEngine(load_config(str(path)), **kw)  # type: ignore[arg-type]


def _req(user: str, action: str, agent: str = "assistant", **kw: object) -> AuthRequest:
    return AuthRequest(agent=agent, user=user, action=action, **kw)  # type: ignore[arg-type]


# --- Red team ----------------------------------------------------------------------------------

RULES = """
delegation:
  rules:
    - {name: finance-delegates, roles: [finance], allowed_actions: [approve_invoice, "read:*"]}
"""


def test_a_user_cannot_delegate_what_role_rules_do_not_let_them(tmp_path: Path) -> None:
    e = _engine(tmp_path, RULES)
    with pytest.raises(ValueError, match="No delegation rule lets roles sales delegate"):
        e.create_delegation("bob", "assistant", ["approve_invoice"], 600, "x")
    e.create_delegation("alice", "assistant", ["approve_invoice"], 600, "x")


def test_a_delegation_stops_when_the_delegator_loses_the_role(tmp_path: Path) -> None:
    roles = {"alice": ["finance"]}
    e = _engine(tmp_path, RULES, user_roles=lambda u: roles.get(u, []))
    e.create_delegation("alice", "assistant", ["approve_invoice"], 600, "x")
    roles["alice"] = ["sales", "user:alice"]  # moves to sales (access via user:alice still)
    d = e.authorize(_req("alice", "approve_invoice"))
    assert not d.allowed


def test_attenuation_never_reads_a_wildcard_as_text() -> None:
    p = Principal.for_user("alice")
    parent = ResolvedAgent("a", p, True, "", capabilities={"read:[!s]*": ["baseline"]})
    child = ResolvedAgent("b", p, True, "", capabilities={"read:*": ["baseline"]})
    out = parent.attenuate(child)
    assert not out.check("read:secrets")[0]
    assert not covers("read:[!s]*", "read:*") and not covers("x:?", "x:*")
    assert covers("read:*", "read:[ab]*") and covers("read:*", "read:docs")


def test_delegation_rules_never_read_a_wildcard_as_text(tmp_path: Path) -> None:
    e = _engine(
        tmp_path, 'delegation:\n  rules:\n    - {name: r, allowed_actions: ["read:[!s]*"]}\n'
    )
    with pytest.raises(ValueError, match="not allowed by delegation rule"):
        e.create_delegation("bob", "assistant", ["read:*"], 600, "x")


A2A = """
a2a:
  default: allow
  policies:
    - {name: no-prod, from_agent: "*", to_agent: "*", effect: deny,
       condition: 'resource starts_with "/prod"'}
    - {name: alice-only, from_agent: assistant, to_agent: nightly, effect: deny,
       condition: 'user != "alice"'}
"""


def test_a2a_conditions_see_the_request_not_metadata(tmp_path: Path) -> None:
    e = _engine(tmp_path, A2A)
    prod = _req("alice", "read:x", resource="/prod/db", target_agent="researcher")
    assert not e.authorize(prod).allowed
    spoof = _req("bob", "read:x", target_agent="nightly", metadata={"user": "alice"})
    assert not e.authorize(spoof).allowed


def test_delegate_respects_a2a(tmp_path: Path) -> None:
    e = _engine(tmp_path)  # no a2a section: default deny
    child = e.delegate(e.resolve("assistant", e.principal("alice")), "researcher")
    assert not child.access and not child.capabilities
    with pytest.raises(TokenError, match="without access"):
        e.issue_token(child, "mcp://x")


def test_tool_servers_get_approval_scope_and_sod_through_authorize(tmp_path: Path) -> None:
    extra = (
        "approval_policies:\n  - {name: big, condition: 'action == \"export:ledger\"', "
        "tier: strong}\n"
    )
    e = _engine(tmp_path, extra)
    token = e.issue_token(e.resolve("assistant", e.principal("alice")), "mcp://ledger")
    v = e.verify_token(token, "mcp://ledger")
    d = e.authorize(_req("alice", "export:ledger"), resolved=v.resolved)
    assert d.allowed and d.requires_approval and d.tier == "strong"
    other = e.authorize(_req("bob", "export:ledger"), resolved=v.resolved)
    assert not other.allowed and "not for this request" in other.reason


def test_access_names_do_not_collide(tmp_path: Path) -> None:
    e = _engine(tmp_path, user_roles=lambda u: [])
    assert not e.authorize(_req("service", "read:x", agent="nightly")).allowed
    assert not e.authorize(_req("finance", "read:x")).allowed
    assert e.authorize(_req("alice", "read:x")).allowed  # listed as user:alice


def test_limits_are_validated(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="list of patterns"):
        _engine(tmp_path, limits={"*": "approve_invoice"})
    with pytest.raises(ValueError, match="no profile"):
        _engine(tmp_path, limits={"intern-*": ["delete_*"]})
    with pytest.raises(TypeError, match="mapping"):
        _engine(tmp_path, limits=["x"])


def test_denials_and_limits_ignore_case(tmp_path: Path) -> None:
    e = _engine(tmp_path, limits={"intern-bot": ["payments:*", "delete_*"]})
    for action in ("PAYMENTS:transfer", "DELETE_users", "Delete_Users"):
        assert not e.authorize(_req("", action, agent="intern-bot")).allowed, action


SOD = """
separation_of_duties:
  - {name: payments, actions: [create_payment, approve_payment]}
"""


def test_separation_of_duties_resists_variants(tmp_path: Path) -> None:
    e = _engine(tmp_path, SOD)
    assert e.authorize(_req("alice", "create_payment", agent="payer", resource="INV-1")).allowed
    for resource in ("inv-1", " INV-1 "):
        d = e.authorize(_req("alice", "approve_payment", agent="payer", resource=resource))
        assert not d.allowed, resource
    assert e.authorize(_req("alice", "create_payment", agent="payer")).allowed
    assert not e.authorize(_req("alice", "Approve_Payment", agent="payer")).allowed  # no resource


def test_a_session_scope_binds_its_requests(tmp_path: Path) -> None:
    extra = "  scoped: {role: reader, scopes: ['project:*']}\n"
    path = tmp_path / "agent_auth.yaml"
    path.write_text(BASE + extra + "audit:\n  enabled: false\n")
    e = AuthEngine(load_config(str(path)))
    s = e.create_session("scoped", "alice", scope="project:acme")
    other = AuthRequest(agent="scoped", user="alice", action="read:x", scope="project:other",
                        session_id=s.session_id)  # fmt: skip
    assert not e.authorize(other).allowed
    same = AuthRequest(agent="scoped", user="alice", action="read:x", session_id=s.session_id)
    assert e.authorize(same).allowed


@pytest.mark.parametrize("roles", [None, "finance", ZeroDivisionError])
def test_a_failing_identity_provider_fails_closed(tmp_path: Path, roles: object) -> None:
    def provider(user: str) -> object:
        if roles is ZeroDivisionError:
            raise ZeroDivisionError("idp down")
        return roles

    e = _engine(tmp_path, user_roles=provider)
    d = e.authorize(_req("alice", "read:x"))
    assert not d.allowed and "user_roles failed" in d.reason


# --- Tokens ------------------------------------------------------------------------------------


def _forge(token: str, **changes: object) -> str:
    body, _ = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    claims.update(changes)
    import hashlib
    import hmac

    raw = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    enc = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(hmac.new(KEY, raw, hashlib.sha256).digest()).rstrip(b"=")
    return f"{enc}.{sig.decode()}"


def test_token_encoding_has_one_spelling(tmp_path: Path) -> None:
    e = _engine(tmp_path)
    token = e.issue_token(e.resolve("assistant", e.principal("alice")), "mcp://x")
    body, sig = token.split(".")
    for variant in (f"{body}=.{sig}", f"{body}.{sig}==", token.replace("-", "+").replace("_", "/")):
        if variant != token:
            with pytest.raises(TokenError):
                e.verify_token(variant, "mcp://x")


def test_issuer_clock_skew_cannot_stretch_a_token(tmp_path: Path) -> None:
    e = _engine(tmp_path)
    token = e.issue_token(e.resolve("assistant", e.principal("alice")), "mcp://x")
    now = int(time.time())
    with pytest.raises(TokenError, match="in the future"):
        e.verify_token(_forge(token, iat=now + 3 * 86400, exp=now + 3 * 86400 + 60), "mcp://x")
    with pytest.raises(TokenError, match="lifetime"):
        e.verify_token(_forge(token, exp=now + 86400), "mcp://x")
    with pytest.raises(TokenError, match="leeway"):
        e.verify_token(token, "mcp://x", leeway=10**6)


def test_key_rotation_and_key_types(tmp_path: Path) -> None:
    old = _engine(tmp_path)
    token = old.issue_token(old.resolve("assistant", old.principal("alice")), "mcp://x")
    rotated = _engine(tmp_path, token_key=[b"n" * 32, KEY])  # new key signs, old verifies
    rotated.verify_token(token, "mcp://x")
    with pytest.raises(TokenError, match="must be bytes"):
        _engine(tmp_path, token_key="x" * 40)


# --- Integrator ----------------------------------------------------------------------------------


def test_a_revocation_in_another_engine_takes_effect(tmp_path: Path) -> None:
    a = _engine(tmp_path)
    b = _engine(tmp_path)  # a long-running verifier
    g = a.create_delegation("alice", "assistant", ["deploy"], 600, "x")
    assert b.authorize(_req("alice", "deploy")).allowed
    a.revoke_delegation(g.delegation_id)
    assert not b.authorize(_req("alice", "deploy")).allowed
    s = a.create_session("assistant", "alice")
    a.revoke_session(s.session_id)
    assert not b.authorize(_req("alice", "read:x", session_id=s.session_id)).allowed


def test_duplicate_keys_and_grant_values_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "dup.yaml"
    path.write_text(BASE + "  assistant: {role: reader}\n")
    with pytest.raises(ConfigError, match="duplicate key 'assistant'"):
        load_config(str(path))
    path.write_text(
        BASE.replace(
            "finance: [approve_invoice", "sales: send_quote\n      finance: [approve_invoice"
        )
    )
    with pytest.raises(ConfigError, match="grants for 'sales' must be a list"):
        load_config(str(path))


# --- Newcomer --------------------------------------------------------------------------------------


def test_preview_shows_the_deprecated_union(tmp_path: Path) -> None:
    e = _engine(tmp_path, user_permissions_provider=lambda u: {"deploy"})
    r = e.preview("assistant", e.principal("bob"))
    assert r.capabilities["deploy"] == ["user_permissions"]


def test_disabled_or_tightened_delegation_stops_existing_grants(tmp_path: Path) -> None:
    e = _engine(tmp_path)
    e.create_delegation("bob", "assistant", ["*"], 600, "x")
    assert e.authorize(_req("bob", "deploy")).allowed
    off = _engine(tmp_path, "delegation:\n  enabled: false\n")
    assert not off.authorize(_req("bob", "deploy")).allowed
    tight = _engine(
        tmp_path, 'delegation:\n  rules:\n    - {name: r, allowed_actions: ["read:*"]}\n'
    )
    assert not tight.authorize(_req("bob", "deploy")).allowed


def test_no_delegation_to_an_unknown_agent(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no profile 'asistant'"):
        _engine(tmp_path).create_delegation("bob", "asistant", ["read:x"], 600, "x")


def test_service_principal_with_a_user_is_refused(tmp_path: Path) -> None:
    e = _engine(tmp_path)
    with pytest.raises(ValueError, match="acts for no one"):
        e.principal("alice", service=True)
    path = tmp_path / "agent_auth.yaml"
    result = CliRunner().invoke(
        cli, ["-c", str(path), "check", "--agent", "nightly", "--service", "--user", "alice",
              "--action", "read:x"],
    )  # fmt: skip
    assert result.exit_code == 2 and "do not pass --user" in result.output
