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

from theaios.agent_auth import AuthEngine, load_config  # noqa: E402
from theaios.agent_auth.adapters.langchain_agent import AgentAuthMiddleware  # noqa: E402

CONFIG = """
version: "1.0"
roles:
  reader: {actions: [read_docs, "db:*"]}
profiles:
  assistant:
    role: reader
    allow: [task]
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


def test_an_approval_policy_refuses_and_points_to_guardrails() -> None:
    agent = _agent([_call("db:drop", "c1", target="prod")])
    out = agent.invoke({"messages": [("user", "x")]}, CFG, context=Ctx("alice"), version="v2")
    assert out.interrupts == () and RAN == []
    msg = _tools(out)[0]
    assert msg.artifact["theaios"]["codes"] == ["approval_required"]
    assert "FlowMiddleware" in msg.content and "strong" in msg.content


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


# --- Round 1 findings (usability test of 6c78d67) ----------------------------------------------

from langchain.agents.middleware import AgentMiddleware  # noqa: E402
from langgraph.types import interrupt  # noqa: E402


class RefuseInside(AgentMiddleware):  # stands in for guardrails inside AgentAuthMiddleware
    def _refuse(self, request: Any) -> ToolMessage:
        return ToolMessage(
            content="Blocked",
            name=request.tool_call["name"],
            tool_call_id=request.tool_call["id"],
            status="error",
            artifact={"theaios": {"component": "guardrails", "codes": ["rule_deny"]}},
        )

    def wrap_tool_call(self, request: Any, handler: Any) -> Any:
        return (
            self._refuse(request)
            if request.tool_call["name"] == "create_payment"
            else handler(request)
        )

    async def awrap_tool_call(self, request: Any, handler: Any) -> Any:
        return (
            self._refuse(request)
            if request.tool_call["name"] == "create_payment"
            else await handler(request)
        )


class PauseInside(AgentMiddleware):
    def wrap_tool_call(self, request: Any, handler: Any) -> Any:
        if request.tool_call["name"] == "create_payment":
            interrupt({"q": "ok?"})
        return handler(request)


def _payer(script: list[AIMessage], engine: AuthEngine, inner: AgentMiddleware) -> Any:
    model = Model(messages=iter([*script, AIMessage(content="done")]))
    return create_agent(
        model,
        TOOLS,
        middleware=[AgentAuthMiddleware(engine), inner],
        context_schema=Ctx,
        checkpointer=InMemorySaver(),
        name="payer",
    )


def test_a_call_refused_inside_leaves_no_separation_of_duties_record() -> None:
    engine = _engine()
    _payer([_call("create_payment", "c1", target="inv-1")], engine, RefuseInside()).invoke(
        {"messages": [("user", "x")]}, CFG, context=Ctx("alice")
    )
    _agent([_call("approve_payment", "c2", target="inv-1")], engine, name="payer").invoke(
        {"messages": [("user", "x")]}, {"configurable": {"thread_id": "t2"}}, context=Ctx("alice")
    )
    assert RAN == ["approve_payment:inv-1"]  # the refused create did not count


def test_a_pause_inside_leaves_no_record_until_the_call_runs() -> None:
    engine = _engine()
    out = _payer([_call("create_payment", "c1", target="inv-1")], engine, PauseInside()).invoke(
        {"messages": [("user", "x")]}, CFG, context=Ctx("alice"), version="v2"
    )
    assert out.interrupts
    _agent([_call("approve_payment", "c2", target="inv-1")], engine, name="payer").invoke(
        {"messages": [("user", "x")]}, {"configurable": {"thread_id": "t2"}}, context=Ctx("alice")
    )
    assert RAN == ["approve_payment:inv-1"]


@tool
def task(description: str, subagent_type: str) -> str:
    """Hand work to a sub-agent."""
    RAN.append("task")
    return "handed off"


TASK = task


def _handoff(child: str) -> list[ToolMessage]:
    model = Model(
        messages=iter(
            [_call("task", "c1", description="d", subagent_type=child), AIMessage(content="done")]
        )
    )
    engine = AuthEngine(load_config("a.yaml"), user_roles=lambda u: ROLES.get(u, []))
    agent = create_agent(
        model,
        [*TOOLS, TASK],
        middleware=[AgentAuthMiddleware(engine)],
        context_schema=Ctx,
        checkpointer=InMemorySaver(),
        name="assistant",
    )
    return _tools(agent.invoke({"messages": [("user", "x")]}, CFG, context=Ctx("alice")))


def test_a_handoff_to_a_sub_agent_without_profile_or_a2a_allow_is_refused() -> None:
    for child in ("general-purpose", "payer"):
        msg = _handoff(child)[0]
        assert msg.status == "error" and msg.artifact["theaios"]["codes"] == ["handoff"], child
    assert RAN == []


def test_a_handoff_the_a2a_rules_allow_goes_through() -> None:
    msg = _handoff("researcher")[0]
    assert msg.status == "success" and RAN == ["task"], msg.content


def test_a_sub_agent_without_delegated_by_is_refused() -> None:
    agent = _agent([_call("read_docs", "c1")], name="researcher")
    cfg = {"configurable": {"thread_id": "t1", "ls_agent_type": "subagent"}}
    out = agent.invoke({"messages": [("user", "x")]}, cfg, context=Ctx("alice"))
    assert RAN == [] and _tools(out)[0].artifact["theaios"]["codes"] == ["no_parent"]


def test_a_service_run_denial_says_why() -> None:
    agent = _agent([_call("approve_invoice", "c1")])
    out = agent.invoke({"messages": [("user", "x")]}, CFG, context=Ctx(None))
    assert "service run" in _tools(out)[0].content
