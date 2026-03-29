# Expression Syntax

The safe expression language for policy conditions.

---

## Overview

`agent-auth` uses a custom expression language for approval policy conditions and A2A rule conditions. It is **not** Python `eval()` — it is a purpose-built, safe DSL that cannot access the filesystem, network, or arbitrary code.

Expressions are compiled once (`compile_expression()`) and evaluated many times (`evaluate()`).

---

## Grammar

```
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
```

---

## Available operators

| Operator | Example | Description |
|---|---|---|
| `==` | `action == "deploy"` | Equality |
| `!=` | `user != "admin"` | Inequality |
| `>`, `<`, `>=`, `<=` | `score > 0.5` | Numeric/string comparison |
| `starts_with` | `resource starts_with "/prod"` | String prefix check |
| `ends_with` | `resource ends_with ".csv"` | String suffix check |
| `contains` | `resource contains "/sensitive/"` | Substring check |
| `in` | `action in ["deploy", "delete"]` | Membership in list |
| `not in` | `user not in ["bot", "system"]` | Non-membership |
| `matches` | `input matches pii_detector` | Named matcher pattern |
| `and` | `a == "x" and b == "y"` | Logical AND |
| `or` | `a == "x" or b == "y"` | Logical OR |
| `not` | `not action == "read"` | Logical NOT |

---

## Values

| Type | Syntax | Examples |
|---|---|---|
| String | `"..."` or `'...'` | `"deploy"`, `'admin'` |
| Number | digits, optional decimal | `42`, `3.14` |
| Boolean | `true`, `false` | `true` |
| Null | `null`, `none` | `null` |
| List | `[...]` | `["read", "write"]` |

---

## Variables

Reference config variables with `$`:

```yaml
# In agent_auth.yaml
variables:
  env: production
  admin_role: admin

# In a condition
condition: '$env == "production"'
```

Undefined variables raise an `ExpressionError`.

---

## Field access

Access context fields with dot notation:

```
action           # Top-level field
metadata.key     # Nested field
```

Available context fields depend on where the expression is used:

### Approval policy conditions

| Field | Type | Description |
|---|---|---|
| `action` | `str` | The requested action |
| `resource` | `str` | The target resource path |
| `agent` | `str` | The agent name |
| `user` | `str` | The user name |
| `scope` | `str` | The scope |

### A2A rule conditions

| Field | Type | Description |
|---|---|---|
| `action` | `str` | The requested action |
| `from_agent` | `str` | Source agent name |
| `to_agent` | `str` | Target agent name |

---

## Empty conditions

An empty condition string (or whitespace-only) always evaluates to `true`. This is useful for catch-all policies:

```yaml
approval_policies:
  - name: catch_all
    condition: ""           # Always matches
    tier: soft
```

---

## Examples

### Production deploy requires strong approval

```yaml
- name: prod_deploy
  condition: 'action == "deploy" and resource starts_with "/prod"'
  tier: strong
```

### Destructive actions

```yaml
- name: destructive
  condition: 'action == "delete" or action == "rollback"'
  tier: strong
```

### Environment-based escalation

```yaml
- name: prod_escalation
  condition: '$env == "production"'
  tier: soft
```

### A2A: scanner can only scan

```yaml
policies:
  - name: scanner-only
    from_agent: scanner
    to_agent: "*"
    action: scan
    effect: allow
    condition: 'action == "scan"'
```

---

## Safety

The expression language:

- Has no access to the filesystem, network, or OS
- Cannot import modules
- Cannot call arbitrary functions
- Uses a compiled AST — no `eval()` or `exec()`
- Raises `ExpressionError` on parse failures

Malformed expressions raise an `ExpressionError` at compile time.
