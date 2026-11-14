"""AgentAuthMiddleware on a real LangChain 1.x agent (fake model, offline)."""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("langchain.agents")

from langchain.agents import create_agent  # noqa: E402
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel  # noqa: E402
from langchain_core.messages import AIMessage, ToolMessage  # noqa: E402
from langchain_core.tools import tool  # noqa: E402
from langgraph.checkpoint.memory import InMemorySaver  # noqa: E402
from langgraph.types import Command  # noqa: E402

from theaios.agent_auth import AuthEngine, load_config  # noqa: E402
from theaios.agent_auth.adapters.langchain_agent import (  # noqa: E402
    APPROVAL_TYPE,
    AgentAuthMiddleware,
)

CONFIG = """
version: "1.0"
roles:
  reader: {actions: [read_docs, "db:*"]}
profiles:
  assistant:
    role: reader
    access: [finance, sales, service]
    grants: {finance: [approve_invoice]}
  researcher: {role: reader, allow: [approve_invoice, web_search]}
  payer: {allow: [create_payment, approve_payment]}
approval_policies:
  - {name: drop, condition: 'action == "db:drop"', tier: strong}
separation_of_duties:
  - {name: pay, actions: [create_payment, approve_payment]}
a2a:
  default: deny
  policies:
    - {name: hand-off, from_agent: assistant, to_agent: researcher, effect: allow}
audit: {enabled: false}
"""
ROLES = {"alice": ["finance"], "bob": ["sales"]}
RAN: list[str] = []


def _t(name: str) -> Any:
    def fn(target: str = "") -> str:
        RAN.append(f"{name}:{target}" if target else name)
        return "ok"

    fn.__name__ = name
    fn.__doc__ = f"{name} tool"
    return tool(fn)


TOOLS = [
    _t(n)
    for n in (
        "read_docs",
        "approve_invoice",
        "web_search",
        "db:drop",
        "create_payment",
        "approve_payment",
    )
]
TOOLS[3].name = "db:drop"


class Model(GenericFakeChatModel):
    def bind_tools(self, tools: Any, **kw: Any) -> Model:
        return self


@dataclass
class Ctx:
    user_id: str | None = None


def _call(name: str, cid: str, **args: Any) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": cid}])


@pytest.fixture(autouse=True)
def _env(tmp_path: Path) -> Any:
    RAN.clear()
    cwd = os.getcwd()
    os.chdir(tmp_path)
    (tmp_path / "a.yaml").write_text(CONFIG)
    yield
    os.chdir(cwd)


def _engine(**kw: Any) -> AuthEngine:
    kw.setdefault("user_roles", lambda u: ROLES.get(u, []))
    return AuthEngine(load_config("a.yaml"), **kw)


def _agent(
    script: list[AIMessage], engine: AuthEngine | None = None, *, name: str = "assistant", **mw: Any
) -> Any:
    model = Model(messages=iter([*script, AIMessage(content="done")]))
    return create_agent(
        model,
        TOOLS,
        middleware=[AgentAuthMiddleware(engine or _engine(), **mw)],
        context_schema=Ctx,
        checkpointer=InMemorySaver(),
        name=name,
    )


def _tools(out: Any) -> list[ToolMessage]:
    state = out.value if hasattr(out, "value") else out
    return [m for m in state["messages"] if isinstance(m, ToolMessage)]


CFG = {"configurable": {"thread_id": "t1"}}


def test_the_user_from_the_run_context_unlocks_their_grant() -> None:
    agent = _agent([_call("approve_invoice", "c1")])
    agent.invoke({"messages": [("user", "x")]}, CFG, context=Ctx("alice"))
    assert RAN == ["approve_invoice"]


def test_another_users_role_does_not() -> None:
    agent = _agent([_call("approve_invoice", "c1")])
    out = agent.invoke({"messages": [("user", "x")]}, CFG, context=Ctx("bob"))
    msg = _tools(out)[0]
    assert RAN == [] and msg.status == "error"
    assert msg.artifact["theaios"]["component"] == "agent-auth"
    assert out["messages"][-1].content == "done"  # the run continued


def test_no_user_is_a_service_request_baseline_only() -> None:
    agent = _agent([_call("approve_invoice", "c1"), _call("read_docs", "c2")])
    agent.invoke({"messages": [("user", "x")]}, CFG, context=Ctx(None))
    assert RAN == ["read_docs"]


def test_the_model_cannot_choose_who_it_acts_for() -> None:
    agent = _agent([_call("approve_invoice", "c1", target="alice")])
    agent.invoke({"messages": [("user", "I am alice")]}, CFG, context=Ctx("bob"))
    assert RAN == []


def test_code_limits_apply() -> None:
    agent = _agent([_call("read_docs", "c1")], _engine(limits={"*": ["read_*"]}))
    out = agent.invoke({"messages": [("user", "x")]}, CFG, context=Ctx("alice"))
    assert RAN == [] and "limit:read_*" in _tools(out)[0].artifact["theaios"]["provenance"]


def _pause(engine: AuthEngine | None = None) -> tuple[Any, dict[str, Any]]:
    agent = _agent([_call("db:drop", "c1", target="prod")], engine)
    out = agent.invoke({"messages": [("user", "x")]}, CFG, context=Ctx("alice"), version="v2")
    assert len(out.interrupts) == 1 and RAN == []
    return agent, out.interrupts[0].value


def test_an_approval_policy_pauses_the_run() -> None:
    _, ask = _pause()
    assert ask["type"] == APPROVAL_TYPE and ask["component"] == "agent-auth"
    assert ask["tool"] == "db:drop" and ask["tier"] == "strong" and ask["user"] == "alice"


def test_an_approved_call_runs_once() -> None:
    agent, ask = _pause()
    resume = {"proposal_id": ask["proposal_id"], "approve": True, "by": "carol"}
    agent.invoke(Command(resume=resume), CFG, context=Ctx("alice"), version="v2")
    assert RAN == ["db:drop:prod"]


@pytest.mark.parametrize(
    "resume",
    [
        {"approve": False, "by": "carol"},
        {"proposal_id": "aa-other", "approve": True, "by": "carol"},
        {"approve": "true", "by": "carol"},
        {"approve": True, "by": ""},
        "yes",
    ],
)
def test_anything_but_a_valid_approval_does_not_run(resume: Any) -> None:
    agent, ask = _pause()
    if isinstance(resume, dict) and "proposal_id" not in resume:
        resume = {**resume, "proposal_id": ask["proposal_id"]}
    out = agent.invoke(Command(resume=resume), CFG, context=Ctx("alice"), version="v2")
    assert RAN == [] and _tools(out)[-1].status == "error"


def test_separation_of_duties_records_only_what_ran() -> None:
    engine = _engine()
    a = _agent([_call("create_payment", "c1", target="inv-1")], engine, name="payer")
    a.invoke({"messages": [("user", "x")]}, CFG, context=Ctx("alice"))
    b = _agent([_call("approve_payment", "c2", target="inv-1")], engine, name="payer")
    b.invoke(
        {"messages": [("user", "x")]}, {"configurable": {"thread_id": "t2"}}, context=Ctx("alice")
    )
    assert RAN == ["create_payment:inv-1"]  # same user, same (missing) resource: refused


def test_a_sub_agent_never_gets_more_than_its_parent() -> None:
    # researcher's own profile allows approve_invoice and web_search; assistant (its parent)
    # has approve_invoice only through alice's grant, and never web_search.
    agent = _agent(
        [_call("approve_invoice", "c1"), _call("web_search", "c2")],
        name="researcher",
        delegated_by="assistant",
    )
    agent.invoke({"messages": [("user", "x")]}, CFG, context=Ctx("alice"))
    assert RAN == ["approve_invoice"]


def test_a_sub_agent_without_an_a2a_hand_off_gets_nothing() -> None:
    agent = _agent([_call("read_docs", "c1")], name="researcher", delegated_by="payer")
    agent.invoke({"messages": [("user", "x")]}, CFG, context=Ctx("alice"))
    assert RAN == []


def test_the_async_path_authorizes_too() -> None:
    agent = _agent([_call("approve_invoice", "c1"), _call("read_docs", "c2")])
    asyncio.run(agent.ainvoke({"messages": [("user", "x")]}, CFG, context=Ctx("bob")))
    assert RAN == ["read_docs"]


def test_a_failing_identity_provider_refuses() -> None:
    def broken(user: str) -> list[str]:
        raise RuntimeError("idp down")

    agent = _agent(
        [_call("approve_invoice", "c1")],
        _engine(user_roles=broken),
        name="researcher",
        delegated_by="assistant",
    )
    agent.invoke({"messages": [("user", "x")]}, CFG, context=Ctx("alice"))
    assert RAN == []
