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
    auth_config : AuthConfig
        Parsed agent-auth configuration.
    guardrails_engine : Engine
        An initialized guardrails Engine instance.
    default_user : str
        Default user name if not provided per-call.
    """

    def __init__(
        self,
        auth_config: AuthConfig,
        guardrails_engine: GuardrailsEngine,
        default_user: str = "system",
    ) -> None:
        self._auth_engine = AuthEngine(auth_config)
        self._guardrails = guardrails_engine
        self._default_user = default_user

    def evaluate(
        self,
        event: GuardEvent,
        user: str | None = None,
        session_id: str | None = None,
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

        Returns
        -------
        Decision
            Guardrails Decision. If auth fails, returns a deny Decision
            with the auth denial reason.
        """
        from theaios.guardrails.types import Decision

        effective_user = user or self._default_user

        def deny(reason: str) -> GuardrailsDecision:
            return Decision(outcome="deny", reason=f"Auth denied: {reason}", severity="high")

        # The action: the tool of a tool_call event (data["tool_name"]), data["action"] when
        # present (both when both are), else the event type.
        names, problem = _event_actions(event)
        resource = event.data.get("resource", "")
        if not problem and resource is not None and not isinstance(resource, str):
            problem = f"event field 'resource' must be a string, got {type(resource).__name__}"
        if problem:
            return deny(problem)

        strictest = None
        for name in names:
            auth_decision = self._auth_engine.authorize(
                AuthRequest(
                    agent=event.agent,
                    user=effective_user,
                    action=name,
                    resource=resource or "",
                    session_id=session_id or event.session_id,
                    scope=event.scope,
                    target_agent=event.target_agent,
                )
            )
            if auth_decision.is_denied:
                return deny(auth_decision.reason)
            if auth_decision.requires_approval and (
                strictest is None
                or _TIERS.get(auth_decision.tier, 0) > _TIERS.get(strictest.tier, 0)
            ):
                strictest = auth_decision

        if strictest is not None:
            return Decision(
                outcome="require_approval",
                reason=f"Auth requires {strictest.tier} approval: {strictest.reason}",
                tier=strictest.tier,
                severity="medium",
            )

        # Auth passed — run guardrails
        return self._guardrails.evaluate(event)

    async def evaluate_async(
        self,
        event: GuardEvent,
        user: str | None = None,
        session_id: str | None = None,
    ) -> GuardrailsDecision:
        """Async version of evaluate."""
        import asyncio

        return await asyncio.to_thread(self.evaluate, event, user, session_id)


_TIERS = {"autonomous": 0, "soft": 1, "strong": 2}


def _event_actions(event: GuardEvent) -> tuple[list[str], str]:
    """The action names an event asks for, or the reason it is refused."""
    names: list[str] = []
    for key in ("tool_name", "action"):
        if key in event.data:
            value = event.data[key]
            if not isinstance(value, str):
                return [], f"event field '{key}' must be a string, got {type(value).__name__}"
            if value not in names:
                names.append(value)
    if event.scope == "tool_call" and "tool_name" not in event.data:
        return [], "a tool_call event must name its tool in data['tool_name']"
    return names or [event.scope], ""
