"""agent-auth 0.2: resolution, provenance, identity, limits, attenuation, tokens, SoD."""

from __future__ import annotations

import os
import time
import warnings
from collections.abc import Iterator
from pathlib import Path

import pytest

from theaios.agent_auth import (
    AuthEngine,
    AuthRequest,
    Principal,
    TokenError,
    load_config,
)
from theaios.agent_auth.config import ConfigError

CONFIG = """
version: "1.0"
roles:
  reader: {actions: ["read:*"]}
profiles:
  assistant:
    role: reader
    deny: ["read:secrets"]
    access: [finance, sales, ops-bot-owner, service]
    grants:
      finance: [approve_invoice, "export:ledger"]
      sales: [send_quote]
  researcher:
    role: reader
    allow: [search_web]
  locked:
    role: reader
    access: [finance]
separation_of_duties:
  - name: payments
    actions: [create_payment, approve_payment]
audit:
  enabled: false
"""

ROLES = {"alice": ["finance"], "bob": ["sales"], "carol": []}
KEY = b"k" * 32


@pytest.fixture(autouse=True)
def _in_tmp(tmp_path: Path) -> Iterator[None]:
    cwd = os.getcwd()
    os.chdir(tmp_path)  # delegations and sessions live under ./.agent_auth
    yield
    os.chdir(cwd)


def _engine(tmp_path: Path, extra: str = "", **kw: object) -> AuthEngine:
    path = tmp_path / "agent_auth.yaml"
    path.write_text(CONFIG + extra)
    kw.setdefault("user_roles", lambda u: ROLES.get(u, []))
    kw.setdefault("token_key", KEY)
    return AuthEngine(load_config(str(path)), **kw)  # type: ignore[arg-type]


def _req(user: str, action: str, **kw: object) -> AuthRequest:
    return AuthRequest(agent="assistant", user=user, action=action, **kw)  # type: ignore[arg-type]


# --- Resolution and provenance -----------------------------------------------------------


def test_grants_are_additive_per_role_with_provenance(tmp_path: Path) -> None:
    e = _engine(tmp_path)
    alice = e.authorize(_req("alice", "approve_invoice"))
    assert alice.allowed and alice.provenance == ["grant:finance:approve_invoice"]
    assert "the 'finance' grant" in alice.reason
    assert not e.authorize(_req("bob", "approve_invoice")).allowed
    base = e.authorize(_req("bob", "read:docs"))
    assert base.allowed and base.provenance == ["baseline:read:*"]


def test_access_is_checked_first(tmp_path: Path) -> None:
    e = _engine(tmp_path)
    d = e.authorize(_req("carol", "read:docs"))
    assert not d.allowed and d.provenance == ["access"]
    assert "may not use 'assistant'" in d.reason
    d = e.authorize(AuthRequest(agent="locked", user="bob", action="read:docs"))
    assert not d.allowed


def test_deny_beats_grants(tmp_path: Path) -> None:
    e = _engine(tmp_path)
    d = e.authorize(_req("alice", "read:secrets"))
    assert not d.allowed and d.provenance == ["deny:read:secrets"]


def test_code_limits_cannot_be_widened_by_config(tmp_path: Path) -> None:
    e = _engine(tmp_path, limits={"*": ["export:*"]})
    d = e.authorize(_req("alice", "export:ledger"))  # granted in config, limited in code
    assert not d.allowed and d.provenance == ["limit:export:*"]
    assert "limit set in code" in d.reason
    e.create_delegation("alice", "assistant", ["export:ledger"], 600, "quarter close")
    assert not e.authorize(_req("alice", "export:ledger")).allowed  # nor by delegation


def test_preview_lists_everything_with_sources(tmp_path: Path) -> None:
    e = _engine(tmp_path, limits={"assistant": ["send_*"]})
    r = e.preview("assistant", e.principal("alice"))
    assert r.access and r.capabilities["approve_invoice"] == ["grant:finance"]
    assert r.capabilities["read:*"] == ["baseline"]
    assert r.denials == {"read:secrets": ["deny"], "send_*": ["limit"]}
    assert r.fingerprint == e.preview("assistant", e.principal("alice")).fingerprint
    assert r.fingerprint != e.preview("assistant", e.principal("bob")).fingerprint


# --- Identity ------------------------------------------------------------------------------


def test_service_requests_get_the_baseline_only(tmp_path: Path) -> None:
    e = _engine(tmp_path)
    svc = AuthRequest(agent="assistant", user="", action="read:docs", identity="service")
    assert e.authorize(svc).allowed
    granted = AuthRequest(agent="assistant", user="", action="approve_invoice", identity="service")
    assert not e.authorize(granted).allowed
    e.create_delegation("alice", "assistant", ["deploy"], 600, "x")
    deploy = AuthRequest(agent="assistant", user="", action="deploy", identity="service")
    assert not e.authorize(deploy).allowed


def test_identities_are_never_mixed(tmp_path: Path) -> None:
    e = _engine(tmp_path)
    mixed = AuthRequest(agent="assistant", user="alice", action="read:docs", identity="service")
    d = e.authorize(mixed)
    assert not d.allowed and "must not carry a user" in d.reason
    odd = AuthRequest(agent="assistant", user="alice", action="read:docs", identity="admin")
    assert not e.authorize(odd).allowed
    assert not e.authorize(
        AuthRequest(agent="locked", user="", action="read:docs", identity="service")
    ).allowed  # 'service' is not in locked's access


def test_user_permissions_union_is_deprecated_and_can_be_turned_off(tmp_path: Path) -> None:
    provider = {"alice": {"delete_db"}}
    e = _engine(tmp_path, user_permissions_provider=lambda u: provider.get(u, set()))
    with pytest.warns(FutureWarning, match="'assistant' was allowed 'delete_db' for 'alice'"):
        d = e.authorize(_req("alice", "delete_db"))
    assert d.allowed and d.provenance == ["user_permissions:delete_db"]
    strict = _engine(
        tmp_path,
        "resolution:\n  user_permissions: ignore\n",
        user_permissions_provider=lambda u: provider.get(u, set()),
    )
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert not strict.authorize(_req("alice", "delete_db")).allowed


def test_the_union_never_overrides_a_denial_or_access(tmp_path: Path) -> None:
    provider = {"alice": {"read:secrets"}, "carol": {"read:docs"}}
    e = _engine(tmp_path, user_permissions_provider=lambda u: provider.get(u, set()))
    assert not e.authorize(_req("alice", "read:secrets")).allowed
    assert not e.authorize(_req("carol", "read:docs")).allowed


# --- Separation of duties --------------------------------------------------------------------


def test_separation_of_duties_per_user_and_resource(tmp_path: Path) -> None:
    extra = "    allow: [create_payment, approve_payment]\n"
    path = tmp_path / "agent_auth.yaml"
    path.write_text(CONFIG.replace("    access: [finance]\n", "    access: [finance]\n" + extra))
    e = AuthEngine(load_config(str(path)), user_roles=lambda u: ROLES.get(u, []))

    def req(user: str, action: str, resource: str) -> AuthRequest:
        return AuthRequest(agent="locked", user=user, action=action, resource=resource)

    assert e.explain(req("alice", "create_payment", "inv-1")).allowed
    assert e.explain(req("alice", "approve_payment", "inv-1")).allowed  # explain records nothing
    assert e.authorize(req("alice", "create_payment", "inv-1")).allowed
    d = e.authorize(req("alice", "approve_payment", "inv-1"))
    assert not d.allowed and "Separation of duties ('payments')" in d.reason
    assert e.authorize(req("alice", "approve_payment", "inv-2")).allowed  # other resource
    assert e.authorize(req("alice", "create_payment", "inv-1")).allowed  # same action again


# --- Attenuation -----------------------------------------------------------------------------


def test_a_sub_agent_never_gets_more_than_its_parent(tmp_path: Path) -> None:
    e = _engine(tmp_path)
    parent = e.resolve("assistant", e.principal("alice"))
    child = e.delegate(parent, "researcher")
    assert "search_web" not in child.capabilities  # the parent cannot search
    assert "approve_invoice" not in child.capabilities  # the child has no such grant
    assert child.check("read:docs")[0]
    assert not child.check("read:secrets")[0]  # the parent's denial follows
    assert child.chain == ["assistant"]


def test_attenuation_keeps_the_narrower_pattern() -> None:
    from theaios.agent_auth.resolution import ResolvedAgent

    p = Principal.for_user("alice")
    parent = ResolvedAgent("a", p, True, "", capabilities={"read:docs": ["baseline"]})
    child = ResolvedAgent("b", p, True, "", capabilities={"read:*": ["baseline"]})
    assert list(parent.attenuate(child).capabilities) == ["read:docs"]
    wide = ResolvedAgent("a", p, True, "", capabilities={"read:*": ["baseline"]})
    narrow = ResolvedAgent("b", p, True, "", capabilities={"read:docs": ["baseline"]})
    assert list(wide.attenuate(narrow).capabilities) == ["read:docs"]
    with pytest.raises(ValueError, match="same principal"):
        wide.attenuate(ResolvedAgent("b", Principal.service(), True, ""))
    a = ResolvedAgent("a", p, True, "", scopes=["project:x"])
    b = ResolvedAgent("b", p, True, "", scopes=["project:y"])
    assert not a.attenuate(b).access  # no common scope is no access, not every scope


# --- Tokens -----------------------------------------------------------------------------------


def test_token_round_trip(tmp_path: Path) -> None:
    e = _engine(tmp_path)
    r = e.resolve("assistant", e.principal("alice"))
    token = e.issue_token(r, audience="mcp://ledger", ttl=60)
    v = e.verify_token(token, audience="mcp://ledger")
    assert v.claims.user == "alice" and v.resolved.check("approve_invoice")[0]


def test_token_refusals(tmp_path: Path) -> None:
    e = _engine(tmp_path)
    r = e.resolve("assistant", e.principal("alice"))
    token = e.issue_token(r, audience="mcp://ledger", ttl=60)
    with pytest.raises(TokenError, match="not 'mcp://crm'"):
        e.verify_token(token, audience="mcp://crm")
    body, sig = token.split(".")
    with pytest.raises(TokenError, match="bad signature"):
        e.verify_token(body + "x." + sig, audience="mcp://ledger")
    other = _engine(tmp_path, token_key=b"z" * 32)
    with pytest.raises(TokenError, match="bad signature"):
        other.verify_token(token, audience="mcp://ledger")
    short = e.issue_token(r, audience="mcp://ledger", ttl=1)
    time.sleep(1.1)
    with pytest.raises(TokenError, match="expired"):
        e.verify_token(short, audience="mcp://ledger")
    with pytest.raises(TokenError, match="at least 32 bytes"):
        _engine(tmp_path, token_key=b"short").issue_token(r, "mcp://ledger")
    with pytest.raises(TokenError, match="without access"):
        e.issue_token(e.resolve("assistant", e.principal("carol")), "mcp://ledger")


def test_a_token_dies_when_permissions_change(tmp_path: Path) -> None:
    roles = {"alice": ["finance"]}
    e = _engine(tmp_path, user_roles=lambda u: roles.get(u, []))
    token = e.issue_token(e.resolve("assistant", e.principal("alice")), "mcp://ledger")
    roles["alice"] = []  # alice leaves finance
    with pytest.raises(TokenError, match="changed since the token was issued"):
        e.verify_token(token, "mcp://ledger")
    roles["alice"] = ["finance"]
    edited = _engine(tmp_path, limits={"*": ["approve_*"]})  # the policy changed
    with pytest.raises(TokenError, match="changed"):
        edited.verify_token(token, "mcp://ledger")


def test_a_delegated_token_carries_and_rechecks_the_chain(tmp_path: Path) -> None:
    e = _engine(tmp_path)
    child = e.delegate(e.resolve("assistant", e.principal("alice")), "researcher")
    v = e.verify_token(e.issue_token(child, "mcp://search"), "mcp://search")
    assert v.claims.chain == ("assistant",) and not v.resolved.check("search_web")[0]


# --- Config ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ("resolution:\n  user_permissions: maybe\n", "expected 'union' or 'ignore'"),
        ("separation_of_duties:\n  - {name: x, actions: [a]}\n", "at least two actions"),
        ("resolution:\n  user_permision: ignore\n", "unknown key 'user_permision'"),
    ],
)
def test_config_errors(tmp_path: Path, extra: str, message: str) -> None:
    path = tmp_path / "bad.yaml"
    base = CONFIG.replace(
        "separation_of_duties:\n  - name: payments\n    actions: [create_payment, approve_payment]\n",
        "",
    )
    path.write_text(base + extra)
    with pytest.raises(ConfigError) as exc:
        load_config(str(path))
    assert message in "\n".join(exc.value.errors)


def test_grants_must_map_roles_to_action_lists(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(CONFIG.replace("      sales: [send_quote]", "      sales: send_quote"))
    with pytest.raises(ConfigError, match="grants"):
        load_config(str(path))
