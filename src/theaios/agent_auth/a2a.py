"""Agent-to-agent (A2A) communication authorization."""

from __future__ import annotations

import fnmatch

from theaios.agent_auth.expressions import (
    ASTNode,
    ExpressionError,
    compile_expression,
    evaluate as eval_expr,
)
from theaios.agent_auth.config import condition_errors
from theaios.agent_auth.types import A2AConfig, A2APolicyConfig


class A2AEvaluator:
    """Evaluates agent-to-agent communication policies.

    Policies are evaluated in order. Deny overrides allow.
    If no policy matches, the configured default applies.
    """

    def __init__(
        self,
        config: A2AConfig,
        variables: dict[str, object] | None = None,
    ) -> None:
        self._default = config.default
        self._variables = variables or {}
        self._policies: list[tuple[A2APolicyConfig, ASTNode]] = []

        for policy in config.policies:
            try:
                ast = compile_expression(policy.condition)
            except ExpressionError as e:
                raise ExpressionError(
                    f"Error in A2A policy '{policy.name}': {e}",
                ) from e
            problems = condition_errors(policy.condition, self._variables)
            if problems:
                raise ExpressionError(f"Error in A2A policy '{policy.name}': {'; '.join(problems)}")
            self._policies.append((policy, ast))

    def may_reach(self, from_agent: str, to_agent: str) -> bool:
        """Whether any action from ``from_agent`` to ``to_agent`` could be allowed: an allow
        policy matching both agents, or a default of allow."""
        if self._default == "allow":
            return True
        return any(
            p.effect == "allow"
            and fnmatch.fnmatch(from_agent, p.from_agent)
            and fnmatch.fnmatch(to_agent, p.to_agent)
            for p, _ in self._policies
        )

    def evaluate(
        self,
        from_agent: str,
        to_agent: str,
        action: str,
        context: dict[str, object] | None = None,
    ) -> tuple[bool, str]:
        """Evaluate A2A policies for a communication request.

        Parameters
        ----------
        from_agent : str
            Source agent initiating the communication.
        to_agent : str
            Target agent receiving the communication.
        action : str
            The action being performed.
        context : dict, optional
            Additional context for condition evaluation.

        Returns
        -------
        tuple[bool, str]
            (allowed, reason) — whether communication is allowed and why.
        """
        eval_context: dict[str, object] = dict(context or {})
        eval_context["from_agent"] = from_agent
        eval_context["to_agent"] = to_agent
        eval_context["action"] = action

        # Track deny and allow matches separately
        deny_reason: str | None = None
        allow_reason: str | None = None

        for policy, ast in self._policies:
            # Check agent patterns
            # Deny policies match agents and action regardless of case (fail closed); allow
            # policies match them exactly.
            if policy.effect == "deny":
                if not (
                    fnmatch.fnmatchcase(from_agent.casefold(), policy.from_agent.casefold())
                    and fnmatch.fnmatchcase(to_agent.casefold(), policy.to_agent.casefold())
                    and fnmatch.fnmatchcase(action.casefold(), policy.action.casefold())
                ):
                    continue
            elif not (
                fnmatch.fnmatchcase(from_agent, policy.from_agent)
                and fnmatch.fnmatchcase(to_agent, policy.to_agent)
                and fnmatch.fnmatchcase(action, policy.action)
            ):
                continue

            # Evaluate condition. A deny condition ignores case like its patterns: it is
            # evaluated on the request as written and with action and agents in lower case,
            # and denies if either matches.
            contexts = [eval_context]
            if policy.effect == "deny":
                lowered = {
                    **eval_context,
                    "from_agent": from_agent.casefold(),
                    "to_agent": to_agent.casefold(),
                    "action": action.casefold(),
                }
                if lowered != eval_context:
                    contexts.append(lowered)
            result = False
            for ctx in contexts:
                try:
                    result = bool(eval_expr(ast, context=ctx, variables=self._variables))
                except ExpressionError:
                    # Fail closed: a deny policy that cannot be evaluated denies; an allow
                    # policy that cannot be evaluated grants nothing.
                    result = policy.effect == "deny"
                if result:
                    break

            if not result:
                continue

            # Policy matched
            reason = policy.description or policy.name

            if policy.effect == "deny" and deny_reason is None:
                deny_reason = f"Denied by A2A policy: {reason}"

            if policy.effect == "allow" and allow_reason is None:
                allow_reason = f"Allowed by A2A policy: {reason}"

        # Deny takes precedence over allow
        if deny_reason is not None:
            return (False, deny_reason)

        if allow_reason is not None:
            return (True, allow_reason)

        # Fall through to default
        if self._default == "allow":
            return (True, "Allowed by default A2A policy")

        return (False, "Denied by default A2A policy")
