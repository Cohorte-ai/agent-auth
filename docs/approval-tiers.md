# Approval Tiers

The three-tier approval model gives agents clear guidance on when to act and when to ask.

---

## The three tiers

| Tier | Value | Meaning |
|---|---|---|
| Autonomous | `autonomous` | Agent proceeds without external approval |
| Soft | `soft` | Another agent or automated system should approve |
| Strong | `strong` | A human must explicitly approve the action |

### Tier hierarchy

```
strong      (most restrictive)
   |
  soft
   |
autonomous  (least restrictive)
```

When multiple approval policies match a single request, **escalation** applies: the most restrictive tier wins.

---

## Defining approval policies

Approval policies are a **list** under `approval_policies:` in `agent_auth.yaml`:

```yaml
approval_policies:
  - name: prod_deploy
    condition: 'action == "deploy" and resource starts_with "/prod"'
    tier: strong

  - name: staging_deploy
    condition: 'action == "deploy" and resource starts_with "/staging"'
    tier: soft

  - name: destructive
    condition: 'action == "delete" or action == "rollback"'
    tier: strong
```

---

## Policy evaluation

The `ApprovalEvaluator` evaluates all policies and returns the most restrictive tier:

1. For each policy, evaluate the `condition` expression
2. If the condition is true (or empty), the policy matches
3. Among all matching policies, pick the most restrictive tier
4. If no policies match, use the profile's `default_tier`

### Expression evaluation

Conditions use the agent-auth safe expression language (not Python `eval()`). Available context:

| Variable | Type | Description |
|---|---|---|
| `action` | `str` | The requested action |
| `resource` | `str` | The target resource path |
| `agent` | `str` | The agent name |
| `user` | `str` | The user name |
| `$var_name` | any | Variables from the config `variables` section |

Expression operators: `==`, `!=`, `>`, `<`, `>=`, `<=`, `starts_with`, `ends_with`, `contains`, `matches`, `in`, `not in`, `and`, `or`, `not`.

See [Expressions](expressions.md) for the full syntax.

---

## Escalation example

Request: `action=deploy, resource=/prod/api`

Matching policies:

| Policy | Tier | Condition | Match? |
|---|---|---|---|
| `prod_deploy` | `strong` | resource starts_with "/prod" -> True | Yes |
| `staging_deploy` | `soft` | resource starts_with "/staging" -> False | No |

Result: `strong`.

Now consider: `resource=/staging/api`

| Policy | Tier | Condition | Match? |
|---|---|---|---|
| `prod_deploy` | `strong` | resource starts_with "/prod" -> False | No |
| `staging_deploy` | `soft` | resource starts_with "/staging" -> True | Yes |

Result: `soft`.

---

## AuthDecision properties

The `AuthDecision` returned by `engine.authorize()` includes:

| Property | Type | Description |
|---|---|---|
| `allowed` | `bool` | Whether the action is permitted |
| `requires_approval` | `bool` | Whether approval is needed (tier is `soft` or `strong`) |
| `approval_policy` | `str` | Name of the matching policy |
| `tier` | `str` | The approval tier |
| `is_autonomous` | `bool` | `allowed and tier == "autonomous" and not requires_approval` |
| `is_denied` | `bool` | `not allowed` |

Key distinction:

- **Denied** (`is_denied`): the agent does not have permission at all
- **Requires approval** (`requires_approval`): the agent has permission but needs sign-off

---

## Default behavior

Each agent profile has a `default_tier` (defaults to `"autonomous"`). If no approval policy matches, the profile's default tier is used.

To set a catch-all policy, use an empty condition:

```yaml
approval_policies:
  - name: catch_all
    condition: ""
    tier: soft
    description: Everything requires at least soft approval
```
