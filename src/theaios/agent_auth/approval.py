"""Approval tier evaluation based on conditional policies."""

from __future__ import annotations

from theaios.agent_auth.expressions import (
    ASTNode,
    ExpressionError,
    compile_expression,
    evaluate as eval_expr,
)
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
        self._policies: list[tuple[ApprovalPolicyConfig, ASTNode]] = []
        self._variables = variables or {}

        for policy in policies:
            try:
                ast = compile_expression(policy.condition)
            except ExpressionError as e:
                raise ExpressionError(
                    f"Error in approval policy '{policy.name}': {e}",
                ) from e
            self._policies.append((policy, ast))

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
        # Build context with action
        eval_context: dict[str, object] = dict(context)
        eval_context["action"] = action

        most_restrictive = default_tier

        for policy, ast in self._policies:
            try:
                result = eval_expr(
                    ast,
                    context=eval_context,
                    variables=self._variables,
                )
            except ExpressionError:
                continue  # Skip policies with evaluation errors

            if not result:
                continue

            # Policy matched — check if this tier is more restrictive
            policy_tier = policy.tier
            if TIER_ORDER.get(policy_tier, 0) > TIER_ORDER.get(most_restrictive, 0):
                most_restrictive = policy_tier

        return most_restrictive
