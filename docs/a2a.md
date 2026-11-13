# Agent-to-Agent (A2A) Authorization

Controlling which agents can invoke which other agents.

---

## Why A2A?

In multi-agent systems, agents often need to call each other: a copilot asks a reviewer to check code, a deployer invokes a scanner before deploying. Without A2A rules, any agent could invoke any other agent — creating uncontrolled lateral movement.

A2A authorization answers: **"Can agent X ask agent Y to do Z?"**

---

## Configuration

A2A rules live under `a2a:` in `agent_auth.yaml`:

```yaml
a2a:
  default: deny           # What happens when no rule matches
  policies:
    - name: copilot-to-reviewer
      from_agent: copilot
      to_agent: reviewer
      action: read
      effect: allow

    - name: copilot-deploy-deny
      from_agent: copilot
      to_agent: deployer
      action: deploy
      effect: deny

    - name: any-to-logger
      from_agent: "*"
      to_agent: logger
      action: log
      effect: allow

    - name: admin-wildcard
      from_agent: admin-bot
      to_agent: "*"
      action: "*"
      effect: allow
```

---

## Policy fields

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | `str` | Yes | Unique policy name |
| `from_agent` | `str` | No | Source agent. `"*"` = any. Default: `"*"` |
| `to_agent` | `str` | No | Target agent. `"*"` = any. Default: `"*"` |
| `action` | `str` | No | Action covered. `"*"` = any. Default: `"*"` |
| `effect` | `str` | Yes | `"allow"` or `"deny"` |
| `condition` | `str` | No | Expression string for conditional matching |
| `description` | `str` | No | Human-readable description |

---

## Evaluation logic

The `A2AEvaluator` evaluates all policies when `target_agent` is set on an `AuthRequest`:

1. Iterate through all policies
2. For each policy, check if `from_agent` matches (fnmatch)
3. Check if `to_agent` matches (fnmatch)
4. Check if `action` matches (fnmatch)
5. If all match, evaluate the condition (if any)
6. Collect all matching deny and allow policies
7. **Deny overrides allow** — if any deny policy matches, the result is deny
8. If only allow policies match, the result is allow
9. If no policies match, use `a2a.default`

---

## Wildcards

| Pattern | Meaning |
|---|---|
| `from_agent: "*"` | Any agent can be the source |
| `to_agent: "*"` | Any agent can be the target |
| `action: "*"` | Any action is covered |

Wildcards use `fnmatch` matching. A policy with `"*"` in all three fields effectively becomes a global allow or deny.

---

## Conditions

Conditions use the safe expression language. Available variables:

| Variable | Type | Description |
|---|---|---|
| `action` | `str` | The requested action |
| `from_agent` | `str` | Source agent name |
| `to_agent` | `str` | Target agent name |
| `user`, `resource`, `scope`, `identity` | `str` | The request's own fields (0.2; metadata cannot override them) |
| `agent` | `str` | The agent making the request (in a sub-agent chain, the last one: use `from_agent`/`to_agent` for the hop) |
| `metadata.<key>` | any | Request metadata |

Deny policies match agents and the action regardless of case; allow policies match them
exactly.

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

## Default behavior

The `default` field controls what happens when no policy matches:

| Default | Behavior |
|---|---|
| `"deny"` | Unknown interactions are blocked (recommended for production) |
| `"allow"` | Unknown interactions are permitted (useful for development) |

---

## Triggering A2A in code

Set `target_agent` on the `AuthRequest`:

```python
from theaios.agent_auth.types import AuthRequest

request = AuthRequest(
    agent="copilot",
    user="system",
    action="read",
    target_agent="reviewer",  # This triggers A2A evaluation
)

decision = engine.authorize(request)
```

If `target_agent` is `None`, there is no agent-to-agent call to check, except for a sub-agent
(0.2): a request decided with `authorize(..., resolved=engine.delegate(...))` is checked against
the A2A policies for every hop of its chain, and `engine.delegate` gives no access unless the
policies let the parent reach the child. See [Resolution](resolution.md).
