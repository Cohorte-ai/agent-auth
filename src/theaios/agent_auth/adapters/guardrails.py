"""Integration adapter for theaios-guardrails.

Wraps the guardrails Engine to run an auth check before every evaluation.
If the auth check fails, the guardrails evaluation is skipped and a
deny Decision is returned directly.

Usage::

    from theaios.agent_auth.adapters.guardrails import GuardrailsAuthAdapter
    from theaios.agent_auth.config import load_config as load_auth_config
    from theaios.guardrails.config import load_policy
    from theaios.guardrails.engine import Engine

    auth_config = load_auth_config("agent_auth.yaml")
    policy = load_policy("guardrails.yaml")

    adapter = GuardrailsAuthAdapter(
        auth_config=auth_config,
        guardrails_engine=Engine(policy),
    )

    # This checks auth first, then evaluates guardrails
    decision = adapter.evaluate(event, user="alice")
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from theaios.agent_auth.engine import AuthEngine
from theaios.agent_auth.types import AuthConfig, AuthRequest

if TYPE_CHECKING:
    from theaios.guardrails.engine import Engine as GuardrailsEngine
    from theaios.guardrails.types import Decision as GuardrailsDecision
    from theaios.guardrails.types import GuardEvent


class GuardrailsAuthAdapter:
    """Wraps a guardrails Engine with agent-auth authorization.

    Runs an auth check before every guardrails evaluation. If the
    auth check denies the request, a deny Decision is returned
    without running guardrails rules.

    Parameters
    ----------
    auth_config : AuthEngine or AuthConfig
        Your application's ``AuthEngine`` (recommended: its code limits, ``user_roles``,
        separation-of-duties state and delegations apply), or a parsed config, for which a
        bare engine is built (no limits, no user roles).
    guardrails_engine : Engine
        An initialized guardrails Engine instance.
    default_user : str, optional
        User for events that name none. Default ``None``: such events are service requests
        (the agent's baseline only), never attributed to an account.
    """

    def __init__(
        self,
        auth_config: AuthConfig | AuthEngine,
        guardrails_engine: GuardrailsEngine,
        default_user: str | None = None,
    ) -> None:
        self._auth_engine = (
            auth_config if isinstance(auth_config, AuthEngine) else AuthEngine(auth_config)
        )
        self._guardrails = guardrails_engine
        self._default_user = default_user

    def evaluate(
        self,
        event: GuardEvent,
        user: str | None = None,
        session_id: str | None = None,
        scope: str | None = None,
    ) -> GuardrailsDecision:
        """Evaluate with auth check, then guardrails.

        Parameters
        ----------
        event : GuardEvent
            The guardrails event to evaluate.
        user : str, optional
            User making the request. Falls back to default_user.
        session_id : str, optional
            Session ID for session-based auth.
        scope : str, optional
            The agent-auth scope of the request (``project:acme``), set by your application.
            The event's own ``scope`` is its type (input, tool_call...), never an agent-auth
            scope.

        The action checked is the tool for a ``tool_call`` event (``data["tool_name"]``),
        ``data["action"]`` when the event carries one, and the event type otherwise. An event
        whose ``tool_name`` and ``action`` differ is denied, as are a non-string ``tool_name``,
        ``action`` or ``resource`` and a ``tool_call`` event without ``tool_name``.

        Returns
        -------
        Decision
            Guardrails Decision. If auth fails, returns a deny Decision
            with the auth denial reason.
        """
        from theaios.guardrails.types import Decision

        def deny(reason: str) -> GuardrailsDecision:
            return Decision(outcome="deny", reason=f"Auth denied: {reason}", severity="high")

        action, problem = _event_action(event)
        resource = event.data.get("resource", "")
        if not problem and resource is not None and not isinstance(resource, str):
            problem = f"event field 'resource' must be a string, got {type(resource).__name__}"
        if problem:
            return deny(problem)

        effective_user = user or self._default_user or ""
        auth_decision = self._auth_engine.authorize(
            AuthRequest(
                agent=event.agent,
                user=effective_user,
                identity="on_behalf_of" if effective_user else "service",
                action=action,
                resource=resource or "",
                session_id=session_id or event.session_id,
                scope=scope or "",
                target_agent=event.target_agent,
            )
        )
        if auth_decision.is_denied:
            return deny(auth_decision.reason)

        if auth_decision.requires_approval:
            return Decision(
                outcome="require_approval",
                reason=f"Auth requires {auth_decision.tier} approval: {auth_decision.reason}",
                tier=auth_decision.tier,
                severity="medium",
            )
        # Auth passed — run guardrails
        return self._guardrails.evaluate(event)

    async def evaluate_async(
        self,
        event: GuardEvent,
        user: str | None = None,
        session_id: str | None = None,
        scope: str | None = None,
    ) -> GuardrailsDecision:
        """Async version of evaluate."""
        import asyncio

        return await asyncio.to_thread(self.evaluate, event, user, session_id, scope)


def _event_action(event: GuardEvent) -> tuple[str, str]:
    """The action an event asks for, or the reason it is refused."""
    names: dict[str, str] = {}
    for key in ("tool_name", "action"):
        if key in event.data:
            value = event.data[key]
            if not isinstance(value, str):
                return "", f"event field '{key}' must be a string, got {type(value).__name__}"
            names[key] = value
    if event.scope == "tool_call" and "tool_name" not in names:
        return "", "a tool_call event must name its tool in data['tool_name']"
    if len(set(names.values())) > 1:
        return "", (
            f"the event names the tool {names['tool_name']!r} and the action "
            f"{names['action']!r}: one action per event"
        )
    return next(iter(names.values()), event.scope), ""
