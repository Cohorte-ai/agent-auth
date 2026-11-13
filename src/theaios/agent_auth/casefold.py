"""Case-insensitive evaluation of restrictions.

Restrictions (approval conditions, A2A deny conditions) are evaluated twice: on the request as
written, and with every string folded on both sides (the request's values, the condition's
literals and the config's variables). A restriction applies if either evaluation matches, so
``action == "deleteUser"`` also covers ``DELETEUSER``, and ``from_agent != "Billing"`` stays
false for ``billing``. Grants never use this: they match exactly.
"""

from __future__ import annotations

from collections.abc import Mapping

from theaios.agent_auth.expressions import ASTNode, BinaryOp, ListLiteral, StringLiteral, UnaryOp


def fold_value(value: object) -> object:
    """``value`` with every string casefolded, inside dicts, lists and tuples too."""
    if isinstance(value, str):
        return value.casefold()
    if isinstance(value, Mapping):
        return {k: fold_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [fold_value(v) for v in value]
    if isinstance(value, tuple):
        return tuple(fold_value(v) for v in value)
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
