"""Authorization for LangChain 1.x agents (``create_agent``) and Deep Agents, as middleware.

Requires ``langchain>=1.0`` and ``langgraph>=1.0``: ``pip install "theaios-agent-auth[langchain-agent]"``.

Every tool call the model makes is authorized before it runs, as the agent, for the user the
run is for:

- **allowed**: the tool runs;
- **denied**: the tool does not run; the model gets an error ``ToolMessage`` with the reason
  (the run continues), and the decision (with its provenance) rides in its ``artifact``;
- **approval policy matches**: refused too. Approvals in agents go through theaios-guardrails'
  ``FlowMiddleware`` (durable proposals, decided once, executed once): write the condition as
  a guardrails rule with ``then: require_approval``.

Identity comes from the application, never from the model:

- **user**: ``user=`` (a function of the request) or ``runtime.context.user_id`` /
  ``context["user_id"]``. No user = a service request (the agent's baseline only).
- **agent**: ``agent=`` or the graph's name (``create_agent(name=...)``, Deep Agents sub-agent
  names).
- **sub-agents**: ``delegated_by="parent"`` decides with ``engine.delegate(...)``: a sub-agent
  never gets more than the agent that handed it the work. A Deep Agents sub-agent without
  ``delegated_by`` is refused.
- **hand-offs**: a Deep Agents ``task`` call is authorized as the action ``task`` *and* as a
  hand-off to the sub-agent it names (A2A rules, the sub-agent's profile): a sub-agent with no
  profile or no A2A allow (Deep Agents' automatic ``general-purpose`` one, unless you allow
  it) cannot be reached.

The separation-of-duties record is kept only if the call really ran: when a check inside
this one refuses the call, or the run pauses before it, the record is released.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import replace
from typing import Any

from theaios.agent_auth.engine import AuthEngine
from theaios.agent_auth.resolution import ResolvedAgent
from theaios.agent_auth.types import AuthDecision, AuthRequest

try:
    from langchain.agents.middleware import AgentMiddleware, ToolCallRequest
    from langchain_core.messages import ToolMessage
    from langgraph.errors import GraphInterrupt
    from langgraph.types import Command
except ImportError as e:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "The LangChain agent middleware needs langchain>=1.0 and langgraph>=1.0. "
        'Install with: pip install "theaios-agent-auth[langchain-agent]"'
    ) from e

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
        resolution (``engine.delegate``), for the same user. Required in a Deep Agents
        sub-agent.
    handoff_tool : str
        The tool that hands work to a sub-agent (Deep Agents: ``"task"``, whose
        ``subagent_type`` argument names the sub-agent).
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
        handoff_tool: str = "task",
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
        self._handoff_tool = handoff_tool

    def wrap_tool_call(
        self, request: ToolCallRequest, handler: Handler
    ) -> ToolMessage | Command[Any]:
        decided = self._decide(request)
        if isinstance(decided, ToolMessage):
            return decided
        try:
            result = handler(request)
        except GraphInterrupt:  # the run paused before the tool finished: not done yet
            self._engine._sod_release(decided)
            raise
        if _refused_inside(result):
            self._engine._sod_release(decided)
        return result

    async def awrap_tool_call(
        self, request: ToolCallRequest, handler: AsyncHandler
    ) -> ToolMessage | Command[Any]:
        decided = self._decide(request)
        if isinstance(decided, ToolMessage):
            return decided
        try:
            result = await handler(request)
        except GraphInterrupt:
            self._engine._sod_release(decided)
            raise
        if _refused_inside(result):
            self._engine._sod_release(decided)
        return result

    # ------------------------------------------------------------------------------------

    def _decide(self, request: ToolCallRequest) -> ToolMessage | AuthRequest:
        """The authorized request (recorded) if the tool may run; otherwise what the model
        sees instead."""
        call = request.tool_call
        tool = str(call["name"])
        config = getattr(request.runtime, "config", None) or {}
        if (
            self._parent is None
            and (config.get("configurable") or {}).get("ls_agent_type") == "subagent"
        ):
            return _refusal(
                call,
                "this agent runs as a sub-agent: give its AgentAuthMiddleware "
                "delegated_by='<parent agent>' so it never gets more than its parent",
                None,
                codes=["no_parent"],
            )
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

        handoff = self._handoff_refusal(request, auth, resolved)
        if handoff is not None:
            return handoff

        first = self._engine.explain(auth, resolved=resolved)
        if first.allowed and first.requires_approval:
            reason = (
                f"requires {first.tier} approval ({first.approval_policy or 'approval policy'}). "
                "Approvals in agents go through theaios-guardrails' FlowMiddleware: write this "
                "condition as a guardrails rule with 'then: require_approval'"
            )
            refused = replace(first, allowed=False, requires_approval=False, reason=reason)
            self._engine._log(auth, refused)  # audited, not recorded for separation of duties
            return _refusal(call, reason, refused, codes=["approval_required"])
        final = self._engine.authorize(auth, resolved=resolved)  # logs, records
        if not final.allowed:
            return _refusal(call, _with_hint(final.reason, auth), final)
        if final.requires_approval:  # a policy changed between explain and authorize
            self._engine._sod_release(auth)
            return _refusal(call, "requires approval", final, codes=["approval_required"])
        return auth

    def _handoff_refusal(
        self, request: ToolCallRequest, auth: AuthRequest, resolved: ResolvedAgent | None
    ) -> ToolMessage | None:
        """A hand-off to a sub-agent must be allowed like any delegation (A2A, profile)."""
        call = request.tool_call
        args = call.get("args") or {}
        if call["name"] != self._handoff_tool or not isinstance(args, Mapping):
            return None
        child = args.get("subagent_type")
        if not isinstance(child, str) or not child:
            return _refusal(call, "a hand-off must name its sub-agent", None, codes=["handoff"])
        try:
            parent = (
                resolved
                if resolved is not None
                else self._engine.resolve(auth.agent, self._principal(auth))
            )
            delegated = self._engine.delegate(parent, child)
        except Exception as exc:
            return _refusal(call, f"hand-off to '{child}' refused: {exc}", None, codes=["handoff"])
        if not delegated.access:
            return _refusal(
                call,
                f"hand-off to sub-agent '{child}' refused: {delegated.access_reason}",
                None,
                codes=["handoff"],
            )
        return None

    def _principal(self, auth: AuthRequest) -> Any:
        return (
            self._engine.principal(auth.user) if auth.user else self._engine.principal(service=True)
        )

    def _resolved(self, auth: AuthRequest) -> ResolvedAgent | None:
        if self._parent is None:
            return None
        principal = self._principal(auth)
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


def _with_hint(reason: str, auth: AuthRequest) -> str:
    if auth.user:
        return reason
    return (
        reason + " (service run: no user in the run's context, so no grants or delegations apply)"
    )


def _refused_inside(result: object) -> bool:
    """Did another theaios check inside this one refuse the call (so the tool did not run)?"""
    if not (isinstance(result, ToolMessage) and result.status == "error"):
        return False
    artifact = result.artifact if isinstance(result.artifact, Mapping) else {}
    detail = artifact.get("theaios")
    return isinstance(detail, Mapping) and detail.get("component") != COMPONENT


def _refusal(
    call: Mapping[str, Any],
    message: str,
    decision: AuthDecision | None,
    *,
    codes: list[str] | None = None,
) -> ToolMessage:
    detail: dict[str, object] = {
        "component": COMPONENT,
        "verdict": "deny",
        "codes": codes if codes is not None else ["deny"],
        "reason": message,
        "provenance": list(decision.provenance) if decision is not None else [],
    }
    return ToolMessage(
        content=f"Not authorized: {message}",
        name=str(call.get("name") or ""),
        tool_call_id=str(call.get("id") or ""),
        status="error",
        artifact={"theaios": detail},
    )
