"""Case-insensitive evaluation of restrictions.

A restriction (an approval condition, an A2A deny condition) applies if **some reading** of it
matches, where each comparison may be read as written or with every string folded on both
sides (the request's values, the condition's literals, the config's variables). Under ``not``
the choice flips: a negated comparison counts only if it holds in both readings. This is the
reading most favourable to the restriction, comparison by comparison, so a request cannot
escape by spelling one field so that the positive part matches only when folded and the
exception only as written.

``action == "deleteUser"`` covers ``DELETEUSER``; ``action == "db:drop" and resource !=
"scratch"`` covers ``db:DROP`` on ``Scratch``; ``action != "getReport"`` stays false for
``getReport``. Grants never use this: they match exactly.
"""

from __future__ import annotations

from collections.abc import Mapping

from theaios.agent_auth.expressions import (
    ASTNode,
    BinaryOp,
    ListLiteral,
    StringLiteral,
    UnaryOp,
    evaluate as eval_expr,
)

# Values nested deeper than this are compared as written only (no recursion error).
MAX_FOLD_DEPTH = 64


def fold_value(value: object, _depth: int = 0) -> object:
    """``value`` with every string casefolded, inside dicts, lists and tuples too."""
    if isinstance(value, str):
        return value.casefold()
    if _depth >= MAX_FOLD_DEPTH:
        return value
    if isinstance(value, Mapping):
        return {k: fold_value(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [fold_value(v, _depth + 1) for v in value]
    if isinstance(value, tuple):
        return tuple(fold_value(v, _depth + 1) for v in value)
    return value


def fold_ast(node: ASTNode) -> ASTNode:
    """A copy of ``node`` with its string literals casefolded. Field names, variable names and
    the matcher name of ``matches`` are left alone (they are names, not values)."""
    if isinstance(node, StringLiteral):
        return StringLiteral(node.value.casefold())
    if isinstance(node, ListLiteral):
        return ListLiteral(tuple(fold_ast(i) for i in node.items))  # type: ignore[arg-type]
    if isinstance(node, BinaryOp):
        right = node.right if node.op == "matches" else fold_ast(node.right)  # type: ignore[arg-type]
        return BinaryOp(node.op, fold_ast(node.left), right)  # type: ignore[arg-type]
    if isinstance(node, UnaryOp):
        return UnaryOp(node.op, fold_ast(node.operand))  # type: ignore[arg-type]
    return node


class Restriction:
    """A compiled restriction condition, evaluated case-insensitively (see module doc)."""

    def __init__(self, ast: ASTNode, variables: dict[str, object]) -> None:
        self._ast = ast
        self._folded = fold_ast(ast)
        self._variables = variables  # the config's mapping, not a copy
        self._folded_variables = {k: fold_value(v) for k, v in self._variables.items()}

    def holds(self, context: dict[str, object], folded_context: dict[str, object]) -> bool:
        """Whether the restriction applies. ``folded_context`` is ``fold_context(context)``,
        computed once per decision. Raises ExpressionError like the plain evaluator."""
        return self._eval(self._ast, self._folded, context, folded_context, positive=True)

    def _eval(
        self,
        node: object,
        folded: object,
        ctx: dict[str, object],
        fctx: dict[str, object],
        positive: bool,
    ) -> bool:
        if isinstance(node, BinaryOp) and node.op in ("and", "or"):
            assert isinstance(folded, BinaryOp)
            left = self._eval(node.left, folded.left, ctx, fctx, positive)
            if node.op == "and" and not left:
                return False
            if node.op == "or" and left:
                return True
            return self._eval(node.right, folded.right, ctx, fctx, positive)
        if isinstance(node, UnaryOp) and node.op == "not":
            assert isinstance(folded, UnaryOp)
            return not self._eval(node.operand, folded.operand, ctx, fctx, not positive)
        # A comparison (or a bare value): read it both ways.
        as_written = bool(eval_expr(node, context=ctx, variables=self._variables))  # type: ignore[arg-type]
        if as_written == positive:  # already the reading that favours the restriction
            return as_written
        return bool(eval_expr(folded, context=fctx, variables=self._folded_variables))  # type: ignore[arg-type]


def fold_context(context: Mapping[str, object]) -> dict[str, object]:
    """The folded copy of an evaluation context, for :meth:`Restriction.holds`."""
    return {k: fold_value(v) for k, v in context.items()}
