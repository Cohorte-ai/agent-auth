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


# --- Re-verification (round 2) ---------------------------------------------------------------------

CHAIN = """
  a-agent: {role: everything, scopes: ["project:acme"], default_tier: strong}
  b-agent: {role: everything}
  c-agent: {role: everything}
a2a:
  default: deny
  policies:
    - {name: a-b, from_agent: a-agent, to_agent: b-agent, action: "read:*", effect: allow}
    - {name: b-c, from_agent: b-agent, to_agent: c-agent, effect: allow}
"""


def _chain_engine(tmp_path: Path) -> AuthEngine:
    path = tmp_path / "agent_auth.yaml"
    path.write_text(BASE + CHAIN + "audit:\n  enabled: false\n")
    return AuthEngine(load_config(str(path)), user_roles=lambda u: ROLES.get(u, []))


def test_limits_given_as_a_generator_still_apply(tmp_path: Path) -> None:
    e = _engine(tmp_path, limits={"*": (x for x in ["payments:*"])})
    assert not e.authorize(_req("", "payments:transfer", agent="intern-bot")).allowed


def test_a_sub_agent_keeps_the_parents_scopes_tier_and_every_hop(tmp_path: Path) -> None:
    e = _chain_engine(tmp_path)
    a = e.resolve("a-agent", e.principal("alice"))
    b = e.delegate(a, "b-agent")
    c = e.delegate(b, "c-agent")
    out = e.authorize(_req("alice", "read:x", agent="b-agent", scope="project:secret"), resolved=b)
    assert not out.allowed  # the parent is scoped to project:acme
    tier = e.explain(_req("alice", "read:x", agent="b-agent", scope="project:acme"), resolved=b)
    assert tier.allowed and tier.tier == "strong"  # inherited from the parent
    write = e.authorize(_req("alice", "write:x", agent="c-agent", scope="project:acme"), resolved=c)
    assert not write.allowed and "'a-agent' delegated to 'b-agent'" in write.reason


def test_a_stale_resolution_is_refused(tmp_path: Path) -> None:
    roles = {"alice": ["finance"]}
    e = _engine(tmp_path, user_roles=lambda u: roles.get(u, []))
    snapshot = e.resolve("assistant", e.principal("alice"))
    roles["alice"] = ["sales"]
    d = e.authorize(_req("alice", "approve_invoice"), resolved=snapshot)
    assert not d.allowed and "stale" in d.reason


def test_actions_with_surrounding_spaces_are_refused(tmp_path: Path) -> None:
    e = _engine(tmp_path, SOD, limits={"intern-bot": ["delete_*"]})
    for action in (" delete_users", "delete_users ", ""):
        assert not e.authorize(_req("", action, agent="intern-bot")).allowed, repr(action)


def test_a2a_deny_ignores_case(tmp_path: Path) -> None:
    extra = (
        "a2a:\n  default: allow\n  policies:\n"
        "    - {name: no-del, from_agent: '*', to_agent: '*', action: 'delete_*', effect: deny}\n"
    )
    e = _engine(tmp_path, extra)
    d = e.authorize(_req("", "DELETE_x", agent="intern-bot", target_agent="researcher"))
    assert not d.allowed


def test_approval_conditions_see_identity_not_metadata(tmp_path: Path) -> None:
    extra = (
        "approval_policies:\n  - {name: humans, condition: 'identity != \"service\"', tier: soft}\n"
    )
    e = _engine(tmp_path, extra)
    d = e.authorize(_req("bob", "read:x", metadata={"identity": "service"}))
    assert d.requires_approval and d.tier == "soft"


def test_duplicate_separation_of_duties_actions_are_refused(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(BASE + "separation_of_duties:\n  - {name: p, actions: [a, b, b]}\n")
    with pytest.raises(ConfigError, match="listed twice"):
        load_config(str(path))


# --- Second re-verification (round 3) --------------------------------------------------------------

PAY = """
  pa: {role: reader, grants: {finance: ["pay:*"]}}
  pc: {role: everything}
approval_policies:
  - {name: pa-pay, condition: 'agent == "pa" and action starts_with "pay"', tier: strong}
a2a:
  default: deny
  policies:
    - {name: pa-pc, from_agent: pa, to_agent: pc, effect: allow}
"""


def test_a_parents_approval_policy_passes_to_its_sub_agents(tmp_path: Path) -> None:
    path = tmp_path / "agent_auth.yaml"
    path.write_text(BASE + PAY + "audit:\n  enabled: false\n")
    e = AuthEngine(load_config(str(path)), user_roles=lambda u: ROLES.get(u, []))
    child = e.delegate(e.resolve("pa", e.principal("alice")), "pc")
    d = e.explain(_req("alice", "pay:1", agent="pc"), resolved=child)
    assert d.allowed and d.tier == "strong" and d.approval_policy == "pa-pay@pa"


def test_authorize_async_accepts_a_resolution(tmp_path: Path) -> None:
    import asyncio

    e = _engine(tmp_path, user_roles=lambda u: {"alice": ["sales"]}.get(u, []))
    snap = e.resolve("assistant", e.principal("alice"))
    stale = _engine(tmp_path).resolve("assistant", _engine(tmp_path).principal("alice"))
    assert asyncio.run(e.authorize_async(_req("alice", "read:x"), resolved=snap)).allowed
    d = asyncio.run(e.authorize_async(_req("alice", "read:x"), resolved=stale))
    assert not d.allowed and "stale" in d.reason


def test_separation_of_duties_holds_under_concurrency(tmp_path: Path) -> None:
    import sys
    import threading

    e = _engine(tmp_path, SOD)
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        for i in range(200):
            barrier = threading.Barrier(2)
            results: list[bool] = []

            def go(action: str, i: int = i) -> None:
                barrier.wait()
                req = _req("alice", action, agent="payer", resource=f"inv-{i}")
                results.append(e.authorize(req).allowed)

            ts = [
                threading.Thread(target=go, args=(a,))
                for a in ("create_payment", "approve_payment")
            ]
            for t in ts:
                t.start()
            for t in ts:
                t.join()
            assert results.count(True) == 1, i
    finally:
        sys.setswitchinterval(old)


def test_reasons_name_the_parent(tmp_path: Path) -> None:
    extra = "  denier: {role: reader, deny: ['read:secret']}\n" + (
        "a2a:\n  default: deny\n  policies:\n"
        "    - {name: d-r, from_agent: denier, to_agent: researcher, effect: allow}\n"
    )
    e = _engine(tmp_path, extra)
    child = e.delegate(e.resolve("denier", e.principal("alice")), "researcher")
    d = e.authorize(_req("alice", "read:secret", agent="researcher"), resolved=child)
    assert not d.allowed and "denied by profile 'denier', which delegated" in d.reason


def test_chains_are_capped(tmp_path: Path) -> None:
    extra = "a2a:\n  default: allow\n"
    e = _engine(tmp_path, extra)
    r = e.resolve("researcher", e.principal("alice"))
    with pytest.raises(ValueError, match="limited to 16"):
        for _ in range(20):
            r = e.delegate(r, "researcher")


def test_roles_are_looked_up_once_per_resolution(tmp_path: Path) -> None:
    calls: list[str] = []

    def roles(u: str) -> list[str]:
        calls.append(u)
        return ROLES.get(u, [])

    e = _engine(tmp_path, user_roles=roles)
    for i in range(30):
        e.create_delegation("alice", "assistant", [f"task:{i}"], 600, "x")
    calls.clear()
    e.authorize(_req("alice", "task:3"))
    assert len(calls) == 1


def test_separation_of_duties_normalises_the_user(tmp_path: Path) -> None:
    e = _engine(tmp_path, SOD)
    assert e.authorize(_req("alice", "create_payment", agent="payer", resource="r")).allowed
    assert not e.authorize(_req("Alice", "approve_payment", agent="payer", resource="r")).allowed


@pytest.mark.parametrize(
    "action", ["delete_users\x00", "delete_users\u200b", "\u200bdelete_users", "\uff44elete_users"]
)
def test_actions_with_hidden_or_look_alike_characters_are_refused(
    tmp_path: Path, action: str
) -> None:
    e = _engine(tmp_path, limits={"intern-bot": ["delete_*"]})
    d = e.authorize(_req("", action, agent="intern-bot"))
    assert not d.allowed and "Invalid action" in d.reason


def test_the_middleware_token_mode_ignores_identity_headers(tmp_path: Path) -> None:
    from theaios.agent_auth.adapters.middleware import _decide

    e = _engine(tmp_path)
    forged = {"X-Agent-Name": "assistant", "X-User-Name": "alice"}
    assert _decide(e, forged, "read:x", "", "mcp://x", "X-Agent-Name", "X-User-Name", "S") == (
        401,
        {"error": "a Bearer token is required"},
    )
    token = e.issue_token(e.resolve("assistant", e.principal("bob")), "mcp://x")
    ok = {"Authorization": f"Bearer {token}", "X-User-Name": "alice"}
    assert _decide(e, ok, "read:x", "", "mcp://x", "X-Agent-Name", "X-User-Name", "S") is None
    finance = {"Authorization": f"Bearer {token}"}
    status = _decide(e, finance, "approve_invoice", "", "mcp://x", "a", "u", "s")
    assert status is not None and status[0] == 403  # bob (sales) has no finance grant


# --- Final red team ---------------------------------------------------------------------------------


def test_middleware_decides_on_the_path_not_the_url(tmp_path: Path) -> None:
    from theaios.agent_auth.adapters.middleware import _decide

    extra = (
        "approval_policies:\n  - {name: prod, condition: 'resource starts_with \"/prod\"', "
        "tier: strong}\n"
    )
    e = _engine(tmp_path, extra)
    token = e.issue_token(e.resolve("assistant", e.principal("alice")), "api")
    h = {"Authorization": f"Bearer {token}"}
    answer = _decide(e, h, "read:report", "/prod/report", "api", "a", "u", "s")
    assert answer is not None and answer[1]["error"] == "Approval required"


def test_middleware_uses_the_request_path_for_fastapi(tmp_path: Path) -> None:
    import asyncio

    pytest.importorskip("starlette")
    from theaios.agent_auth.adapters.middleware import fastapi_auth_middleware

    extra = "separation_of_duties:\n  - {name: inv, actions: ['put:*', 'post:*']}\n"
    path = tmp_path / "agent_auth.yaml"
    path.write_text(
        BASE.replace("role: reader\n    access", "role: everything\n    access")
        + extra
        + "audit:\n  enabled: false\n"
    )
    e = AuthEngine(load_config(str(path)), user_roles=lambda u: ROLES.get(u, []), token_key=KEY)
    token = e.issue_token(e.resolve("assistant", e.principal("alice")), "api")

    class URL:
        def __init__(self, path: str) -> None:
            self.path = path

        def __str__(self) -> str:
            return f"http://evil.example{self.path}?x=1"

    class Req:
        def __init__(self, method: str, path: str) -> None:
            self.method, self.url = method, URL(path)
            self.headers = {"Authorization": f"Bearer {token}"}

    async def ok(_req: object) -> str:
        return "ran"

    put = asyncio.run(fastapi_auth_middleware(e, Req("PUT", "/invoices/42"), ok, audience="api"))
    post = asyncio.run(fastapi_auth_middleware(e, Req("POST", "/invoices/42"), ok, audience="api"))
    assert put == "ran" and post != "ran"  # the host and query string cannot split the resource


def test_guardrails_adapter_uses_the_apps_engine_and_service_identity(tmp_path: Path) -> None:
    pytest.importorskip("theaios.guardrails")
    from theaios.guardrails.engine import Engine
    from theaios.guardrails.types import GuardEvent, PolicyConfig

    from theaios.agent_auth.adapters.guardrails import GuardrailsAuthAdapter

    e = _engine(tmp_path, limits={"*": ["payments:*"]})
    adapter = GuardrailsAuthAdapter(e, Engine(PolicyConfig()))
    ev = GuardEvent(scope="action", agent="intern-bot", data={"action": "payments:send"})
    assert adapter.evaluate(ev, user="alice").outcome == "deny"  # the code limit applies
    e.create_delegation("system", "assistant", ["export:all"], 600, "x")
    ev2 = GuardEvent(scope="action", agent="assistant", data={"action": "export:all"})
    assert adapter.evaluate(ev2).outcome == "deny"  # no user: service, not "system"


def test_approval_conditions_ignore_case(tmp_path: Path) -> None:
    extra = (
        "approval_policies:\n  - {name: del, condition: 'action == \"db:delete\"', tier: strong}\n"
    )
    e = _engine(tmp_path, extra)
    for action in ("db:delete", "db:DELETE", "db:Delete"):
        d = e.authorize(_req("", action, agent="intern-bot"))
        assert d.tier == "strong", action


def test_a2a_deny_ignores_agent_case(tmp_path: Path) -> None:
    extra = (
        "a2a:\n  default: allow\n  policies:\n"
        "    - {name: no-pay, from_agent: '*', to_agent: 'researcher*', effect: deny}\n"
    )
    e = _engine(tmp_path, extra)
    d = e.authorize(_req("", "read:x", agent="intern-bot", target_agent="RESEARCHER"))
    assert not d.allowed


def test_request_scopes_are_values(tmp_path: Path) -> None:
    extra = "  scoped: {role: reader, scopes: ['project:[!s]*']}\n"
    path = tmp_path / "agent_auth.yaml"
    path.write_text(BASE + extra + "audit:\n  enabled: false\n")
    e = AuthEngine(load_config(str(path)))
    for scope in ("project:*", "project:[s]ecret"):
        d = e.authorize(AuthRequest(agent="scoped", user="a", action="read:x", scope=scope))
        assert not d.allowed and "not a pattern" in d.reason


def test_sessions_and_delegations_never_share_the_audit_file(tmp_path: Path) -> None:
    path = tmp_path / "agent_auth.yaml"
    path.write_text(BASE + "audit:\n  enabled: true\n  path: logs/agent-audit.log\n")
    e = AuthEngine(load_config(str(path)), user_roles=lambda u: ROLES.get(u, []))
    e.authorize(_req("alice", "read:x"))
    e.create_delegation("alice", "assistant", ["deploy"], 600, "x")
    e.create_session("assistant", "alice")
    audit = (tmp_path / "logs" / "agent-audit.log").read_text()
    assert '"action": "read:x"' in audit or '"action":"read:x"' in audit
    assert e.authorize(_req("alice", "deploy")).allowed


# --- Adapter re-check (722c591) ----------------------------------------------------------------


def _adapter(tmp_path: Path, extra: str = "", **kw: object) -> object:
    pytest.importorskip("theaios.guardrails")
    from theaios.guardrails.engine import Engine
    from theaios.guardrails.types import PolicyConfig

    from theaios.agent_auth.adapters.guardrails import GuardrailsAuthAdapter

    return GuardrailsAuthAdapter(_engine(tmp_path, extra, **kw), Engine(PolicyConfig()))


def test_guardrails_adapter_checks_the_tool_of_a_tool_call(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path, limits={"*": ["payments:*"]})
    from theaios.guardrails.types import GuardEvent

    def outcome(data: dict[str, object], scope: str = "tool_call") -> str:
        ev = GuardEvent(scope=scope, agent="intern-bot", data=data)
        return adapter.evaluate(ev, user="alice").outcome  # type: ignore[attr-defined, no-any-return]

    # guardrails' LangChain and OpenAI Agents adapters send the tool as data["tool_name"]
    assert outcome({"tool_name": "payments:transfer", "arguments": {}}) == "deny"
    assert outcome({"tool_name": "read:docs", "arguments": {}}) == "allow"
    # an event naming a harmless action and a limited tool is checked for both
    assert outcome({"tool_name": "payments:transfer", "action": "read:docs"}) == "deny"
    assert outcome({"arguments": {}}) == "deny"  # a tool call must name its tool
    assert outcome({"action": ["payments:transfer"]}, scope="action") == "deny"  # not str()
    assert outcome({"action": "read:x", "resource": ["inv-1"]}, scope="action") == "deny"


def test_guardrails_adapter_takes_the_scope_from_the_app(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path, "  scoped: {role: reader, scopes: ['project:alpha']}\n")
    from theaios.guardrails.types import GuardEvent

    ev = GuardEvent(scope="action", agent="scoped", data={"action": "read:x"})
    # the event's scope is its type, not an agent-auth scope: a scoped agent works
    assert adapter.evaluate(ev, user="alice").outcome == "allow"  # type: ignore[attr-defined]
    assert adapter.evaluate(ev, user="alice", scope="project:alpha").outcome == "allow"  # type: ignore[attr-defined]
    assert adapter.evaluate(ev, user="alice", scope="project:beta").outcome == "deny"  # type: ignore[attr-defined]


def test_a_sub_agent_cannot_escape_the_parents_approval_by_case(tmp_path: Path) -> None:
    extra = (
        "  db-parent: {role: everything}\n  db-child: {role: everything}\n"
        "approval_policies:\n"
        '  - {name: drop, condition: \'agent == "db-parent" and action == "db:drop"\', '
        "tier: strong}\n"
        "a2a:\n  default: allow\n"
    )
    e = _engine(tmp_path, extra)
    child = e.delegate(e.resolve("db-parent", e.principal("alice")), "db-child")
    for action in ("db:drop", "db:DROP"):
        d = e.explain(_req("alice", action, agent="db-child"), resolved=child)
        assert d.allowed and d.tier == "strong" and d.approval_policy == "drop@db-parent", action


def test_a2a_deny_conditions_ignore_case(tmp_path: Path) -> None:
    extra = (
        "a2a:\n  default: allow\n  policies:\n"
        "    - {name: no-transfer, from_agent: '*', to_agent: '*', effect: deny,\n"
        '       condition: \'action == "transfer" or to_agent == "researcher"\'}\n'
    )
    e = _engine(tmp_path, extra)
    for action, target in [("TRANSFER", "nightly"), ("read:x", "RESEARCHER")]:
        d = e.authorize(_req("", action, agent="intern-bot", target_agent=target))
        assert not d.allowed, (action, target)
    assert e.authorize(_req("", "read:x", agent="intern-bot", target_agent="nightly")).allowed


def test_middleware_decides_head_as_get(tmp_path: Path) -> None:
    import asyncio

    pytest.importorskip("starlette")
    from theaios.agent_auth.adapters.middleware import fastapi_auth_middleware

    path = tmp_path / "agent_auth.yaml"
    path.write_text(
        BASE.replace(
            "role: reader\n    access", "role: everything\n    deny: ['get:/admin*']\n    access"
        )
        + "audit:\n  enabled: false\n"
    )
    e = AuthEngine(load_config(str(path)), user_roles=lambda u: ROLES.get(u, []), token_key=KEY)
    token = e.issue_token(e.resolve("assistant", e.principal("alice")), "api")

    class URL:
        path = "/admin/users"

    class Req:
        def __init__(self, method: str) -> None:
            self.method, self.url = method, URL()
            self.headers = {"Authorization": f"Bearer {token}"}

    async def ok(_req: object) -> str:
        return "ran"

    for method in ("GET", "HEAD", "head"):  # HEAD runs the GET handler
        out = asyncio.run(fastapi_auth_middleware(e, Req(method), ok, audience="api"))
        assert out != "ran", method


# --- Re-verification of the adapter fixes (2266559) -------------------------------------------


def test_an_event_naming_two_actions_is_refused_and_records_nothing(tmp_path: Path) -> None:
    extra = "separation_of_duties:\n  - {name: pay, actions: [create_payment, approve_payment]}\n"
    adapter = _adapter(tmp_path, extra)
    from theaios.guardrails.types import GuardEvent

    two = GuardEvent(
        scope="tool_call",
        agent="payer",
        data={"tool_name": "create_payment", "action": "approve_payment", "resource": "inv-1"},
    )
    assert adapter.evaluate(two, user="alice").outcome == "deny"  # type: ignore[attr-defined]
    same = GuardEvent(
        scope="tool_call",
        agent="payer",
        data={"tool_name": "approve_payment", "action": "approve_payment", "resource": "inv-1"},
    )
    # nothing was recorded for the refused event: alice may still approve inv-1
    assert adapter.evaluate(same, user="alice").outcome == "allow"  # type: ignore[attr-defined]


def test_restriction_conditions_ignore_case_on_both_sides(tmp_path: Path) -> None:
    extra = (
        "approval_policies:\n"
        "  - {name: del, condition: 'action == \"deleteUser\"', tier: strong}\n"
        "a2a:\n  default: allow\n  policies:\n"
        "    - {name: only-report, from_agent: intern-bot, to_agent: nightly, effect: deny,\n"
        "       condition: 'action != \"getReport\"'}\n"
        "    - {name: no-del, from_agent: '*', to_agent: '*', effect: deny,\n"
        "       condition: 'action == \"deleteUser\"'}\n"
    )
    e = _engine(tmp_path, extra)
    for action in ("deleteUser", "DELETEUSER", "deleteuser"):
        assert e.explain(_req("", action, agent="intern-bot")).tier == "strong", action
        d = e.explain(_req("", action, agent="intern-bot", target_agent="researcher"))
        assert not d.allowed, action
    # a != against a mixed-case literal does not deny the value it names
    assert e.explain(_req("", "getReport", agent="intern-bot", target_agent="nightly")).allowed
    assert not e.explain(_req("", "other", agent="intern-bot", target_agent="nightly")).allowed
    assert e.explain(_req("", "getReport", agent="intern-bot")).tier == "autonomous"


def test_actions_whose_upper_case_folds_differently_are_refused(tmp_path: Path) -> None:
    e = _engine(tmp_path, limits={"intern-bot": ["drop_index"]})
    d = e.explain(_req("", "drop_\u0131ndex", agent="intern-bot"))  # dotless i
    assert not d.allowed and d.provenance == ["action"]
    assert not e.explain(_req("", "DROP_INDEX", agent="intern-bot")).allowed
    assert e.explain(_req("", "Stra\u00dfe", agent="intern-bot")).allowed  # ß is fine


# --- Re-verification at 14eecf6 ------------------------------------------------------------


def test_a_request_cannot_split_spellings_across_a_restriction(tmp_path: Path) -> None:
    cond = '\'action == "db:drop" and resource != "scratch"\''
    extra = (
        f"approval_policies:\n  - {{name: drop, condition: {cond}, tier: strong}}\n"
        "a2a:\n  default: allow\n  policies:\n"
        f"    - {{name: no-drop, from_agent: '*', to_agent: '*', effect: deny, condition: {cond}}}\n"
    )
    e = _engine(tmp_path, extra)
    for action, resource in [
        ("db:drop", "Scratch"),
        ("db:DROP", "Scratch"),
        ("db:Drop", "sCratch"),
    ]:
        d = e.explain(_req("", action, agent="intern-bot", resource=resource))
        assert d.tier == "strong", (action, resource)
        d = e.explain(
            _req("", action, agent="intern-bot", resource=resource, target_agent="nightly")
        )
        assert not d.allowed, (action, resource)
    # the exception itself still exempts, in any spelling of the action
    for action in ("db:drop", "DB:DROP"):
        assert (
            e.explain(_req("", action, agent="intern-bot", resource="scratch")).tier == "autonomous"
        )


def test_deny_patterns_with_single_character_wildcards_and_classes(tmp_path: Path) -> None:
    extra = (
        "  guarded: {role: everything, deny: ['db:drop_?', 'cfg:[!a-z]*']}\n"
        "separation_of_duties:\n  - {name: two, actions: ['pay_?', approve]}\n"
    )
    e = _engine(tmp_path, extra, limits={"intern-bot": ["db:drop_?", "cfg:[!a-z]*"]})
    for agent in ("guarded", "intern-bot"):
        for action in ("db:drop_\u00df", "db:drop_\u0130", "cfg:ADMIN", "db:drop_x"):
            assert not e.explain(_req("", action, agent=agent)).allowed, (agent, action)
        assert e.explain(_req("", "cfg:admin", agent=agent)).allowed
    assert e.authorize(_req("alice", "pay_\u00df", agent="intern-bot", resource="r")).allowed
    assert not e.authorize(_req("alice", "approve", agent="intern-bot", resource="r")).allowed


def test_deeply_nested_metadata_is_decided_not_raised(tmp_path: Path) -> None:
    extra = "approval_policies:\n  - {name: m, condition: 'action == \"read:x\"', tier: soft}\n"
    e = _engine(tmp_path, extra)
    deep: object = "X"
    for _ in range(5000):
        deep = [deep]
    d = e.explain(_req("", "READ:X", agent="intern-bot", metadata={"deep": deep}))
    assert d.allowed and d.tier == "soft"  # decided, no RecursionError


def test_case_insensitive_restrictions_never_drop_what_the_condition_applies() -> None:
    import random

    from theaios.agent_auth.casefold import Restriction, fold_context
    from theaios.agent_auth.expressions import compile_expression, evaluate

    words = ["drop", "DROP", "Drop", "scratch", "Scratch", "x"]
    atoms = [
        'action == "{}"',
        'action != "{}"',
        'resource == "{}"',
        'resource != "{}"',
        'resource in ["{}", "y"]',
        'resource not in ["{}"]',
        'action starts_with "{}"',
    ]
    rng = random.Random(7)
    for _ in range(3000):
        parts = [rng.choice(atoms).format(rng.choice(words)) for _ in range(rng.randint(1, 3))]
        parts = [f"not ({p})" if rng.random() < 0.3 else p for p in parts]
        src = f" {rng.choice(['and', 'or'])} ".join(parts)
        ctx: dict[str, object] = {"action": rng.choice(words), "resource": rng.choice(words)}
        ast = compile_expression(src)
        written = bool(evaluate(ast, context=ctx, variables={}))
        folded = Restriction(ast, {}).holds(ctx, fold_context(ctx))
        assert folded or not written, (src, ctx)


# --- Re-verification at c2ad7af ------------------------------------------------------------


def test_every_case_variant_of_a_denied_action_is_denied() -> None:
    import unicodedata

    from theaios.agent_auth.resolution import denial_matches

    cased = [
        chr(cp)
        for cp in range(0x80, 0x110000)
        if not 0xD800 <= cp <= 0xDFFF
        and (lambda c: c.lower() != c or c.upper() != c or c.casefold() != c)(chr(cp))
        and unicodedata.normalize("NFKC", chr(cp)) == chr(cp)
        and unicodedata.category(chr(cp)) not in ("Cc", "Cf")
        and chr(cp).upper().casefold() == chr(cp).casefold()  # the engine refuses the rest
    ]
    assert len(cased) > 1000
    for ch in cased:
        for prefix in ("db:drop_", "DB:DROP_", "Db:Drop_"):
            assert denial_matches(prefix + ch, "db:drop_?"), (prefix, hex(ord(ch)))


def test_a_denied_mixed_case_action_escapes_nothing(tmp_path: Path) -> None:
    extra = "separation_of_duties:\n  - {name: two, actions: ['pay_?', approve]}\n"
    e = _engine(tmp_path, extra, limits={"intern-bot": ["db:drop_?"]})
    for action in ("DB:DROP_ß", "Db:Drop_ß", "DB:DROP_İ"):
        assert not e.explain(_req("", action, agent="intern-bot")).allowed, action
    assert e.authorize(_req("alice", "PAY_ß", agent="intern-bot", resource="r")).allowed
    assert not e.authorize(_req("alice", "approve", agent="intern-bot", resource="r")).allowed


def test_a_restriction_that_errors_as_written_applies(tmp_path: Path) -> None:
    cond = (
        '\'(action == "Payments:Transfer" or metadata.amount > 1000)'
        ' and metadata.currency == "EUR"\''
    )
    e = _engine(
        tmp_path, f"approval_policies:\n  - {{name: big, condition: {cond}, tier: strong}}\n"
    )
    d = e.explain(
        _req(
            "",
            "payments:transfer",
            agent="intern-bot",
            metadata={"amount": "lots", "currency": "USD"},
        )
    )
    assert d.tier == "strong"  # the condition as written raises: fail closed


def test_long_restriction_chains_build_and_decide(tmp_path: Path) -> None:
    cond = " or ".join(["x==1"] * 1200)  # under the 10,000-character limit
    e = _engine(
        tmp_path, f"approval_policies:\n  - {{name: many, condition: '{cond}', tier: soft}}\n"
    )
    assert e.explain(_req("", "a", agent="intern-bot", metadata={"x": 1})).tier == "soft"
    assert e.explain(_req("", "a", agent="intern-bot", metadata={"x": 2})).tier == "autonomous"


# --- Re-verification at 7df69a9 ------------------------------------------------------------


def test_combined_special_characters_cannot_flip_a_denial() -> None:
    import itertools

    from theaios.agent_auth.resolution import denial_matches

    specials = ["ß", "İ", "ῌ", "Ѳ", "ς", "ẞ", "a"]
    for n in (1, 2, 3):
        for chars in itertools.product(specials, repeat=n):
            tail = "".join(chars)
            for pattern in (f"db:drop_{'?' * n}", f"DB:DROP_{'?' * n}"):
                verdicts = {
                    denial_matches(prefix + tail, pattern)
                    for prefix in ("db:drop_", "DB:DROP_", "Db:Drop_")
                }
                assert verdicts == {True}, (tail, pattern, verdicts)
    assert denial_matches("DB:DROP_İNDEX", "db:drop_index")  # İ is an i


def test_a_long_chain_inside_a_comparison_is_decided(tmp_path: Path) -> None:
    chain = " or ".join(["x==1"] * 1100)
    cond = f'({chain} or action=="pay") == true'
    e = _engine(tmp_path, f"approval_policies:\n  - {{name: c, condition: '{cond}', tier: soft}}\n")
    assert e.explain(_req("", "read", agent="intern-bot", metadata={"x": 2})).tier == "autonomous"
    assert e.explain(_req("", "PAY", agent="intern-bot", metadata={"x": 2})).tier == "soft"
