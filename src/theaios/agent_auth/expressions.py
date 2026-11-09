"""Safe expression language for agent-auth conditions.

The implementation lives in ``theaios.core.expressions`` (package theaios-core), shared by
the theaios libraries. This module re-exports it so existing imports keep working.
"""

from theaios.core.expressions import (
    ASTNode,
    BinaryOp,
    BoolLiteral,
    ExpressionError,
    FieldAccess,
    ListLiteral,
    MAX_EXPRESSION_LENGTH,
    MAX_NESTING_DEPTH,
    MatcherProtocol,
    NullLiteral,
    NumberLiteral,
    StringLiteral,
    Token,
    TokenType,
    UnaryOp,
    Variable,
    compile_expression,
    evaluate,
    tokenize,
)

__all__ = [
    "ASTNode",
    "BinaryOp",
    "BoolLiteral",
    "ExpressionError",
    "FieldAccess",
    "ListLiteral",
    "MAX_EXPRESSION_LENGTH",
    "MAX_NESTING_DEPTH",
    "MatcherProtocol",
    "NullLiteral",
    "NumberLiteral",
    "StringLiteral",
    "Token",
    "TokenType",
    "UnaryOp",
    "Variable",
    "compile_expression",
    "evaluate",
    "tokenize",
]
