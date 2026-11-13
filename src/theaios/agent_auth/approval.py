"""Approval tier evaluation based on conditional policies."""

from __future__ import annotations

from theaios.agent_auth.expressions import (
    ExpressionError,
    compile_expression,
)
from theaios.agent_auth.casefold import Restriction, fold_context
from theaios.agent_auth.config import condition_errors
from theaios.agent_auth.types import TIER_ORDER, ApprovalPolicyConfig


class ApprovalEvaluator:
    """Evaluates approval policies to determine the required approval tier.

    Policies are evaluated in order. The first match determines the tier,
    but if multiple policies match, the most restrictive tier wins.
    """

    def __init__(
        self,
        policies: list[ApprovalPolicyConfig],
        variables: dict[str, object] | None = None,
    ) -> None:
        self._policies: list[tuple[ApprovalPolicyConfig, Restriction]] = []
        self._variables = variables or {}

        for policy in policies:
            try:
                ast = compile_expression(policy.condition)
            except ExpressionError as e:
                raise ExpressionError(
                    f"Error in approval policy '{policy.name}': {e}",
                ) from e
            problems = condition_errors(policy.condition, self._variables)
            if problems:
                raise ExpressionError(
                    f"Error in approval policy '{policy.name}': {'; '.join(problems)}"
                )
            self._policies.append((policy, Restriction(ast, self._variables)))

    def evaluate(
        self,
        action: str,
        context: dict[str, object],
        default_tier: str = "autonomous",
    ) -> str:
        """Evaluate approval policies and return the required tier.

        Parameters
        ----------
        action : str
            The action being authorized.
        context : dict
            Evaluation context (agent, user, resource, metadata, etc.).
        default_tier : str
            Default tier if no policies match.

        Returns
        -------
        str
            The required approval tier ("autonomous", "soft", or "strong").
        """
        return self.explain(action, context, default_tier)[0]

    def explain(
        self,
        action: str,
        context: dict[str, object],
        default_tier: str = "autonomous",
    ) -> tuple[str, str, str | None]:
        """Like :meth:`evaluate`, also returning the name of the policy that set the tier
        (empty if the default applies) and, if that policy's condition could not be
        evaluated, the error (the policy then applies: fail closed)."""
        eval_context: dict[str, object] = dict(context)
        eval_context["action"] = action
        # Conditions apply regardless of case (see casefold.py).
        folded_context = fold_context(eval_context)

        most_restrictive = default_tier
        deciding = ""
        deciding_error: str | None = None

        for policy, restriction in self._policies:
            error: str | None = None
            try:
                result = restriction.holds(eval_context, folded_context)
            except ExpressionError as exc:
                # Fail closed: a policy that cannot be evaluated applies its tier. Skipping it
                # would let an action that needs approval run autonomously.
                result, error = True, str(exc)

            if not result:
                continue

            if TIER_ORDER.get(policy.tier, 0) > TIER_ORDER.get(most_restrictive, 0):
                most_restrictive = policy.tier
                deciding, deciding_error = policy.name, error

        return most_restrictive, deciding, deciding_error
