"""Authorization for LangChain 1.x agents (``create_agent``) and Deep Agents, as middleware.

Requires ``langchain>=1.0`` and ``langgraph>=1.0``: ``pip install "theaios-agent-auth[langchain-agent]"``.

Every tool call the model makes is authorized before it runs, as the agent, for the user the
run is for:

- **allowed**: the tool runs;
- **denied**: the tool does not run; the model gets an error ``ToolMessage`` with the reason
  (the run continues), and the decision (with its provenance) rides in its ``artifact``;
- **approval required** (an approval policy's tier): the run pauses with a LangGraph
  ``interrupt``; resume with ``Command(resume={"proposal_id": ..., "approve": True, "by":
  "alice"})``. Nothing is recorded (audit, separation of duties) until the call really runs.

Identity comes from the application, never from the model:

- **user**: ``user=`` (a function of the request) or ``runtime.context.user_id`` /
  ``context["user_id"]``. No user = a service request (the agent's baseline only).
- **agent**: ``agent=`` or the graph's name (``create_agent(name=...)``, Deep Agents sub-agent
  names).
- **sub-agents**: ``delegated_by="parent"`` decides with ``engine.delegate(...)``: a sub-agent
  never gets more than the agent that handed it the work.

The action is the tool name. ``resource=`` and ``scope=`` (functions of the request) feed
separation of duties, scopes and approval conditions; they may read the tool arguments, which
the model chooses.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from theaios.agent_auth.engine import AuthEngine
from theaios.agent_auth.types import AuthDecision, AuthRequest

try:
    from langchain.agents.middleware import AgentMiddleware, ToolCallRequest
    from langchain_core.messages import ToolMessage
    from langgraph.types import Command, interrupt
except ImportError as e:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "The LangChain agent middleware needs langchain>=1.0 and langgraph>=1.0. "
        'Install with: pip install "theaios-agent-auth[langchain-agent]"'
    ) from e

APPROVAL_TYPE = "theaios.approval"
COMPONENT = "agent-auth"

Handler = Callable[[ToolCallRequest], "ToolMessage | Command[Any]"]
AsyncHandler = Callable[[ToolCallRequest], Awaitable["ToolMessage | Command[Any]"]]
Of = Callable[[ToolCallRequest], "str | None"]


class AgentAuthMiddleware(AgentMiddleware):  # type: ignore[type-arg, unused-ignore]
    """Authorize every tool call through an :class:`AuthEngine`.

    Parameters
    ----------
    engine : AuthEngine
        Your application's engine (its limits, ``user_roles`` and state apply).
    agent : str, optional
        The agent name. Default: the graph's name, else ``"default"``.
    user : callable, optional
        ``user(request) -> str | None``. Default: ``user_id`` from the run's context.
    resource, scope : callable, optional
        ``resource(request)`` / ``scope(request)`` for the authorization request.
    delegated_by : str, optional
        The parent agent's name, for a sub-agent: decide with the parent's attenuated
        resolution (``engine.delegate``), for the same user.
    """

    def __init__(
        self,
        engine: AuthEngine,
        *,
        agent: str | None = None,
        user: Of | None = None,
        resource: Of | None = None,
        scope: Of | None = None,
        delegated_by: str | None = None,
    ) -> None:
        super().__init__()
        if not isinstance(engine, AuthEngine):
            raise TypeError("AgentAuthMiddleware needs an AuthEngine")
        if delegated_by is not None and not (isinstance(delegated_by, str) and delegated_by):
            raise ValueError("delegated_by must be the parent agent's name")
        self._engine = engine
        self._agent = agent
        self._user = user
        self._resource = resource
        self._scope = scope
        self._parent = delegated_by

    def wrap_tool_call(
        self, request: ToolCallRequest, handler: Handler
    ) -> ToolMessage | Command[Any]:
        refusal = self._decide(request)
        return refusal if refusal is not None else handler(request)

    async def awrap_tool_call(
        self, request: ToolCallRequest, handler: AsyncHandler
    ) -> ToolMessage | Command[Any]:
        refusal = self._decide(request)
        return refusal if refusal is not None else await handler(request)

    # ------------------------------------------------------------------------------------

    def _decide(self, request: ToolCallRequest) -> ToolMessage | None:
        """None if the tool may run now; otherwise what the model sees instead. May pause the
        run for approval (``interrupt``)."""
        call = request.tool_call
        tool = str(call["name"])
        user = self._of(self._user, request) if self._user else _context_user(request)
        auth = AuthRequest(
            agent=self._agent_of(request),
            user=user,
            action=tool,
            resource=self._of(self._resource, request),
            scope=self._of(self._scope, request),
            identity="on_behalf_of" if user else "service",
        )
        try:
            resolved = self._resolved(auth)
        except Exception as exc:  # the identity provider failed, or no such parent: closed
            return _refusal(call, f"could not resolve the agent: {exc}", None)

        first = self._engine.explain(auth, resolved=resolved)
        if not first.allowed or not first.requires_approval:
            final = self._engine.authorize(auth, resolved=resolved)  # logs, records
            return (
                None
                if final.allowed and not final.requires_approval
                else _refusal(call, final.reason, final)
            )

        # Approval. LangGraph runs this node again on resume: everything above runs twice
        # (explain records nothing), and interrupt() then returns the decision.
        proposal_id = _proposal_id(request, auth)
        decision = interrupt(
            {
                "type": APPROVAL_TYPE,
                "component": COMPONENT,
                "proposal_id": proposal_id,
                "agent": auth.agent,
                "user": auth.user,
                "tool": tool,
                "args": dict(call.get("args") or {}),
                "tier": first.tier,
                "reasons": [{"code": first.approval_policy or "approval", "message": first.reason}],
            }
        )
        problem = _check_decision(decision, proposal_id)
        if problem:
            return _refusal(call, problem, first, codes=["bad_decision"], proposal_id=proposal_id)
        assert isinstance(decision, Mapping)
        if not decision["approve"]:
            note = f": {decision.get('note')}" if decision.get("note") else ""
            return _refusal(
                call,
                f"rejected by {decision['by']}{note}",
                first,
                codes=["rejected"],
                proposal_id=proposal_id,
            )
        final = self._engine.authorize(auth, resolved=self._resolved(auth))
        if not final.allowed:  # something changed while it waited (a role, a policy)
            return _refusal(call, final.reason, final, proposal_id=proposal_id)
        return None

    def _resolved(self, auth: AuthRequest) -> Any:
        if self._parent is None:
            return None
        principal = (
            self._engine.principal(auth.user) if auth.user else self._engine.principal(service=True)
        )
        return self._engine.delegate(self._engine.resolve(self._parent, principal), auth.agent)

    def _agent_of(self, request: ToolCallRequest) -> str:
        if self._agent:
            return self._agent
        config = getattr(request.runtime, "config", None) or {}
        name = (config.get("metadata") or {}).get("lc_agent_name")
        return str(name) if name else "default"

    @staticmethod
    def _of(fn: Of | None, request: ToolCallRequest) -> str:
        if fn is None:
            return ""
        value = fn(request)
        return "" if value is None else str(value)


def _context_user(request: ToolCallRequest) -> str:
    context = getattr(request.runtime, "context", None)
    if context is None:
        return ""
    value = (
        context.get("user_id")
        if isinstance(context, Mapping)
        else getattr(context, "user_id", None)
    )
    return "" if value is None else str(value)


def _proposal_id(request: ToolCallRequest, auth: AuthRequest) -> str:
    """Stable across the pause: the thread, the tool call, who asks, and the arguments."""
    config = getattr(request.runtime, "config", None) or {}
    body = {
        "thread": str((config.get("configurable") or {}).get("thread_id") or ""),
        "call": str(request.tool_call.get("id") or ""),
        "agent": auth.agent,
        "user": auth.user,
        "tool": auth.action,
        "args": request.tool_call.get("args") or {},
    }
    raw = json.dumps(body, sort_keys=True, default=str).encode()
    return "aa-" + hashlib.sha256(raw).hexdigest()[:24]


def _check_decision(decision: object, proposal_id: str) -> str:
    if not isinstance(decision, Mapping):
        return (
            "the run was resumed without a decision: resume with {'proposal_id': ..., "
            "'approve': True|False, 'by': '<who>'}"
        )
    if decision.get("proposal_id") != proposal_id:
        return f"the decision does not name proposal {proposal_id}"
    if type(decision.get("approve")) is not bool:
        return "the decision's 'approve' must be true or false"
    by = decision.get("by")
    if not isinstance(by, str) or not by.strip():
        return "the decision must say who decided ('by')"
    return ""


def _refusal(
    call: Mapping[str, Any],
    message: str,
    decision: AuthDecision | None,
    *,
    codes: list[str] | None = None,
    proposal_id: str | None = None,
) -> ToolMessage:
    detail: dict[str, object] = {
        "component": COMPONENT,
        "verdict": "deny",
        "codes": codes
        if codes is not None
        else (["approval"] if decision and decision.requires_approval else ["deny"]),
        "reason": message,
        "provenance": list(decision.provenance) if decision is not None else [],
    }
    if proposal_id:
        detail["proposal_id"] = proposal_id
    return ToolMessage(
        content=f"Not authorized: {message}",
        name=str(call.get("name") or ""),
        tool_call_id=str(call.get("id") or ""),
        status="error",
        artifact={"theaios": detail},
    )
