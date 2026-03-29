"""Safe expression language for agent-auth policy conditions.

Supports field access, comparisons, boolean logic, pattern matching,
and variable substitution. No eval(), no arbitrary code execution.

Grammar::

    expression  -> or_expr
    or_expr     -> and_expr ("or" and_expr)*
    and_expr    -> not_expr ("and" not_expr)*
    not_expr    -> "not" not_expr | comparison
    comparison  -> primary (comp_op primary)?
    comp_op     -> "==" | "!=" | ">" | "<" | ">=" | "<="
                 | "matches" | "contains" | "starts_with" | "ends_with"
                 | "in" | "not" "in"
    primary     -> STRING | NUMBER | BOOL | NULL | variable | field | list | "(" expression ")"
    variable    -> "$" IDENTIFIER
    field       -> IDENTIFIER ("." IDENTIFIER)*
    list        -> "[" (expression ("," expression)*)? "]"

Usage::

    ast = compile_expression('action == "send_email" and user.role != $admin_role')
    result = evaluate(ast, context=request_data, variables=policy_variables, matchers=matcher_dict)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol


# ---------------------------------------------------------------------------
# Matcher protocol — matchers implement this to support the `matches` operator
# ---------------------------------------------------------------------------


class MatcherProtocol(Protocol):
    """Protocol for matchers used in `matches` expressions."""

    def match(self, text: str, pattern_name: str | None = None) -> bool: ...


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------


class TokenType:
    STRING = "STRING"
    NUMBER = "NUMBER"
    BOOL = "BOOL"
    NULL = "NULL"
    IDENT = "IDENT"
    DOLLAR = "DOLLAR"
    DOT = "DOT"
    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    LBRACKET = "LBRACKET"
    RBRACKET = "RBRACKET"
    COMMA = "COMMA"
    EQ = "EQ"
    NEQ = "NEQ"
    GT = "GT"
    LT = "LT"
    GTE = "GTE"
    LTE = "LTE"
    AND = "AND"
    OR = "OR"
    NOT = "NOT"
    IN = "IN"
    MATCHES = "MATCHES"
    CONTAINS = "CONTAINS"
    STARTS_WITH = "STARTS_WITH"
    ENDS_WITH = "ENDS_WITH"
    EOF = "EOF"


@dataclass(frozen=True)
class Token:
    type: str
    value: str
    pos: int


_KEYWORDS: dict[str, str] = {
    "and": TokenType.AND,
    "or": TokenType.OR,
    "not": TokenType.NOT,
    "in": TokenType.IN,
    "matches": TokenType.MATCHES,
    "contains": TokenType.CONTAINS,
    "starts_with": TokenType.STARTS_WITH,
    "ends_with": TokenType.ENDS_WITH,
    "true": TokenType.BOOL,
    "false": TokenType.BOOL,
    "null": TokenType.NULL,
    "none": TokenType.NULL,
}

_TOKEN_PATTERNS = [
    (r'"[^"]*"', TokenType.STRING),
    (r"'[^']*'", TokenType.STRING),
    (r"\d+(?:\.\d+)?", TokenType.NUMBER),
    (r"==", TokenType.EQ),
    (r"!=", TokenType.NEQ),
    (r">=", TokenType.GTE),
    (r"<=", TokenType.LTE),
    (r">", TokenType.GT),
    (r"<", TokenType.LT),
    (r"\$", TokenType.DOLLAR),
    (r"\.", TokenType.DOT),
    (r"\(", TokenType.LPAREN),
    (r"\)", TokenType.RPAREN),
    (r"\[", TokenType.LBRACKET),
    (r"\]", TokenType.RBRACKET),
    (r",", TokenType.COMMA),
    (r"[a-zA-Z_][a-zA-Z0-9_]*", TokenType.IDENT),
]

_COMPILED_PATTERNS = [(re.compile(p), t) for p, t in _TOKEN_PATTERNS]
_WHITESPACE = re.compile(r"\s+")


class ExpressionError(Exception):
    """Raised when an expression cannot be parsed or evaluated."""

    def __init__(self, message: str, source: str = "", pos: int = -1) -> None:
        self.source = source
        self.pos = pos
        if pos >= 0 and source:
            marker = " " * pos + "^"
            super().__init__(f"{message}\n  {source}\n  {marker}")
        else:
            super().__init__(message)


def tokenize(source: str) -> list[Token]:
    """Tokenize an expression string into a list of tokens."""
    tokens: list[Token] = []
    pos = 0

    while pos < len(source):
        # Skip whitespace
        m = _WHITESPACE.match(source, pos)
        if m:
            pos = m.end()
            continue

        matched = False
        for pattern, token_type in _COMPILED_PATTERNS:
            m = pattern.match(source, pos)
            if m:
                value = m.group(0)
                # Check if an identifier is actually a keyword
                if token_type == TokenType.IDENT and value.lower() in _KEYWORDS:
                    token_type = _KEYWORDS[value.lower()]
                    value = value.lower()
                tokens.append(Token(type=token_type, value=value, pos=pos))
                pos = m.end()
                matched = True
                break

        if not matched:
            raise ExpressionError(f"Unexpected character '{source[pos]}'", source=source, pos=pos)

    tokens.append(Token(type=TokenType.EOF, value="", pos=pos))
    return tokens


# ---------------------------------------------------------------------------
# AST nodes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StringLiteral:
    value: str


@dataclass(frozen=True)
class NumberLiteral:
    value: float


@dataclass(frozen=True)
class BoolLiteral:
    value: bool


@dataclass(frozen=True)
class NullLiteral:
    pass


@dataclass(frozen=True)
class ListLiteral:
    items: tuple[object, ...]


@dataclass(frozen=True)
class FieldAccess:
    parts: tuple[str, ...]


@dataclass(frozen=True)
class Variable:
    name: str


@dataclass(frozen=True)
class BinaryOp:
    op: str
    left: object
    right: object


@dataclass(frozen=True)
class UnaryOp:
    op: str
    operand: object


# AST type alias
ASTNode = (
    StringLiteral
    | NumberLiteral
    | BoolLiteral
    | NullLiteral
    | ListLiteral
    | FieldAccess
    | Variable
    | BinaryOp
    | UnaryOp
)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class _Parser:
    """Recursive descent parser for the expression grammar."""

    def __init__(self, tokens: list[Token], source: str) -> None:
        self._tokens = tokens
        self._source = source
        self._pos = 0

    def _peek(self) -> Token:
        return self._tokens[self._pos]

    def _advance(self) -> Token:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def _expect(self, token_type: str) -> Token:
        tok = self._peek()
        if tok.type != token_type:
            raise ExpressionError(
                f"Expected {token_type}, got {tok.type} ('{tok.value}')",
                source=self._source,
                pos=tok.pos,
            )
        return self._advance()

    def parse(self) -> ASTNode:
        node = self._or_expr()
        if self._peek().type != TokenType.EOF:
            tok = self._peek()
            raise ExpressionError(
                f"Unexpected token '{tok.value}'", source=self._source, pos=tok.pos
            )
        return node

    def _or_expr(self) -> ASTNode:
        left = self._and_expr()
        while self._peek().type == TokenType.OR:
            self._advance()
            right = self._and_expr()
            left = BinaryOp(op="or", left=left, right=right)
        return left

    def _and_expr(self) -> ASTNode:
        left = self._not_expr()
        while self._peek().type == TokenType.AND:
            self._advance()
            right = self._not_expr()
            left = BinaryOp(op="and", left=left, right=right)
        return left

    def _not_expr(self) -> ASTNode:
        if self._peek().type == TokenType.NOT:
            self._advance()
            # Check for "not in"
            if self._peek().type == TokenType.IN:
                # Put back — handled in comparison
                self._pos -= 1
                return self._comparison()
            operand = self._not_expr()
            return UnaryOp(op="not", operand=operand)
        return self._comparison()

    def _comparison(self) -> ASTNode:
        left = self._primary()

        comp_ops = {
            TokenType.EQ,
            TokenType.NEQ,
            TokenType.GT,
            TokenType.LT,
            TokenType.GTE,
            TokenType.LTE,
            TokenType.MATCHES,
            TokenType.CONTAINS,
            TokenType.STARTS_WITH,
            TokenType.ENDS_WITH,
            TokenType.IN,
        }

        if self._peek().type in comp_ops:
            op_tok = self._advance()
            right = self._primary()
            return BinaryOp(op=op_tok.value, left=left, right=right)

        # Handle "not in"
        if self._peek().type == TokenType.NOT:
            next_pos = self._pos + 1
            if next_pos < len(self._tokens) and self._tokens[next_pos].type == TokenType.IN:
                self._advance()  # consume 'not'
                self._advance()  # consume 'in'
                right = self._primary()
                return BinaryOp(op="not_in", left=left, right=right)

        return left

    def _primary(self) -> ASTNode:
        tok = self._peek()

        if tok.type == TokenType.STRING:
            self._advance()
            # Strip quotes
            return StringLiteral(value=tok.value[1:-1])

        if tok.type == TokenType.NUMBER:
            self._advance()
            val = float(tok.value)
            if val == int(val):
                return NumberLiteral(value=int(val))
            return NumberLiteral(value=val)

        if tok.type == TokenType.BOOL:
            self._advance()
            return BoolLiteral(value=tok.value == "true")

        if tok.type == TokenType.NULL:
            self._advance()
            return NullLiteral()

        if tok.type == TokenType.DOLLAR:
            self._advance()
            name_tok = self._expect(TokenType.IDENT)
            return Variable(name=name_tok.value)

        if tok.type == TokenType.IDENT:
            return self._field_access()

        if tok.type == TokenType.LPAREN:
            self._advance()
            expr = self._or_expr()
            self._expect(TokenType.RPAREN)
            return expr

        if tok.type == TokenType.LBRACKET:
            return self._list_literal()

        raise ExpressionError(f"Unexpected token '{tok.value}'", source=self._source, pos=tok.pos)

    def _field_access(self) -> FieldAccess:
        parts: list[str] = []
        parts.append(self._expect(TokenType.IDENT).value)
        while self._peek().type == TokenType.DOT:
            self._advance()
            parts.append(self._expect(TokenType.IDENT).value)
        return FieldAccess(parts=tuple(parts))

    def _list_literal(self) -> ListLiteral:
        self._expect(TokenType.LBRACKET)
        items: list[ASTNode] = []
        if self._peek().type != TokenType.RBRACKET:
            items.append(self._or_expr())
            while self._peek().type == TokenType.COMMA:
                self._advance()
                items.append(self._or_expr())
        self._expect(TokenType.RBRACKET)
        return ListLiteral(items=tuple(items))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def compile_expression(source: str) -> ASTNode:
    """Parse an expression string into an AST. Parse once, evaluate many times."""
    if not source.strip():
        return BoolLiteral(value=True)  # empty condition = always true
    tokens = tokenize(source)
    parser = _Parser(tokens, source)
    return parser.parse()


def evaluate(
    ast: ASTNode,
    context: dict[str, object],
    variables: dict[str, object] | None = None,
    matchers: dict[str, MatcherProtocol] | None = None,
) -> object:
    """Evaluate a compiled AST against a context dict.

    Parameters
    ----------
    ast : ASTNode
        Compiled expression from ``compile_expression()``.
    context : dict
        Request data (flat or nested dict). Fields are accessed via dot notation.
    variables : dict, optional
        Policy variables (``$var_name`` references).
    matchers : dict, optional
        Named matchers for the ``matches`` operator.
    """
    vars_ = variables or {}
    matchers_ = matchers or {}

    def _eval(node: object) -> object:
        if isinstance(node, StringLiteral):
            return node.value

        if isinstance(node, NumberLiteral):
            return node.value

        if isinstance(node, BoolLiteral):
            return node.value

        if isinstance(node, NullLiteral):
            return None

        if isinstance(node, ListLiteral):
            return [_eval(item) for item in node.items]

        if isinstance(node, Variable):
            if node.name not in vars_:
                raise ExpressionError(f"Undefined variable '${node.name}'")
            return vars_[node.name]

        if isinstance(node, FieldAccess):
            return _resolve_field(context, node.parts)

        if isinstance(node, UnaryOp):
            if node.op == "not":
                return not _eval(node.operand)
            raise ExpressionError(f"Unknown unary operator '{node.op}'")  # pragma: no cover

        if isinstance(node, BinaryOp):
            return _eval_binary(node)

        raise ExpressionError(f"Unknown AST node: {type(node)}")  # pragma: no cover

    def _eval_binary(node: BinaryOp) -> object:
        op = node.op

        # Short-circuit boolean operators
        if op == "and":
            left = _eval(node.left)
            if not left:
                return False
            return bool(_eval(node.right))

        if op == "or":
            left = _eval(node.left)
            if left:
                return True
            return bool(_eval(node.right))

        left = _eval(node.left)
        right = _eval(node.right)

        if op == "==":
            return left == right
        if op == "!=":
            return left != right
        if op == ">":
            return _compare(left, right) > 0
        if op == "<":
            return _compare(left, right) < 0
        if op == ">=":
            return _compare(left, right) >= 0
        if op == "<=":
            return _compare(left, right) <= 0

        if op == "in":
            if isinstance(right, list):
                return left in right
            if isinstance(right, str) and isinstance(left, str):
                return left in right
            return False

        if op == "not_in":
            if isinstance(right, list):
                return left not in right
            if isinstance(right, str) and isinstance(left, str):
                return left not in right
            return True

        if op == "contains":
            if isinstance(left, str) and isinstance(right, str):
                return right in left
            return False

        if op == "starts_with":
            if isinstance(left, str) and isinstance(right, str):
                return left.startswith(right)
            return False

        if op == "ends_with":
            if isinstance(left, str) and isinstance(right, str):
                return left.endswith(right)
            return False

        if op == "matches":
            # Right side should be a matcher name — extract it from the AST node
            # directly, not from the evaluated value (which would resolve against context)
            matcher_name = _extract_matcher_name(node.right)
            if matcher_name not in matchers_:
                raise ExpressionError(f"Unknown matcher '{matcher_name}'")
            text = str(left) if left is not None else ""
            return matchers_[matcher_name].match(text)

        raise ExpressionError(f"Unknown operator '{op}'")  # pragma: no cover

    return _eval(ast)


def _extract_matcher_name(node: object) -> str:
    """Extract matcher name from AST node (for the `matches` operator)."""
    if isinstance(node, FieldAccess):
        return ".".join(node.parts)
    if isinstance(node, StringLiteral):
        return node.value
    raise ExpressionError(f"'matches' operator requires a matcher name, got {type(node).__name__}")


def _resolve_field(data: dict[str, object], parts: tuple[str, ...]) -> object:
    """Resolve a dot-notation field path against a nested dict."""
    current: object = data
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _compare(left: object, right: object) -> int:
    """Compare two values, handling type mismatches gracefully."""
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        if left < right:
            return -1
        if left > right:
            return 1
        return 0
    # String comparison
    left_str = str(left) if left is not None else ""
    right_str = str(right) if right is not None else ""
    if left_str < right_str:
        return -1
    if left_str > right_str:
        return 1
    return 0
