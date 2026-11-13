# Delegation

Temporary permission grants from users to agents.

---

## What is delegation?

Delegation allows a user to temporarily grant an agent permissions it would not otherwise have, **when the agent acts for that user**. Alice's delegation to `assistant` applies to requests where `user="alice"`; it never lets the assistant do the same for Bob. This is useful for:

- One-off tasks that exceed the agent's normal permissions
- Time-bounded access for maintenance or cleanup operations
- User-initiated escalation without changing the base config

---

## Creating a delegation

### Python API

```python
grant = engine.create_delegation(
    from_user="alice",
    to_agent="assistant",
    actions=["deploy"],
    duration=3600,           # seconds
    reason="One-off deployment",
)
print(grant.delegation_id)
```

### CLI

```bash
agent-auth -c agent_auth.yaml delegate \
    --from-user alice \
    --to-agent assistant \
    --actions deploy \
    --duration 3600 \
    --reason "One-off deployment"
```

---

## DelegationGrant fields

| Field | Type | Description |
|---|---|---|
| `delegation_id` | `str` | Unique identifier (UUID) |
| `from_user` | `str` | User who granted the delegation |
| `to_agent` | `str` | Agent receiving the permissions |
| `actions` | `list[str]` | Actions granted |
| `granted_at` | `str` | ISO 8601 timestamp |
| `expires_at` | `str` | ISO 8601 timestamp |
| `reason` | `str` | Why the delegation was created (default: `""`) |
| `status` | `str` | `"active"`, `"revoked"`, or `"expired"` |

---

## Rules and constraints

Delegation is controlled by the `delegation` section in `agent_auth.yaml`:

```yaml
delegation:
  enabled: true
  default_duration: 3600      # 1 hour
  max_duration: 86400         # 24 hours
  rules:
    - name: admin-delegation
      roles: [admin]                   # who may delegate under this rule (0.2)
      allowed_actions: [read, write, deploy]
      max_duration: 86400
    - name: editor-delegation
      roles: [editor]
      allowed_actions: [read, write]
      max_duration: 14400
      require_reason: true
```

| Constraint | Description |
|---|---|
| `enabled` | If `false`, new delegations are refused **and existing ones stop applying** |
| `max_duration` | Global maximum in seconds |
| `rules` | Additional constraints (per-rule allowed_actions, max_duration, require_reason, roles) |

If a delegation request violates any constraint, a `ValueError` is raised. The constraints are
checked again every time a delegation is used: tightening a rule, or disabling delegation,
takes effect on delegations that already exist.

### Who may delegate what (0.2)

Without rules, **any user may delegate any action** to an agent for their own requests (denials
and code limits still apply): a sales user could delegate `approve_invoice`, a finance-only
grant, to their assistant. Say who may delegate with `roles`:

```yaml
delegation:
  rules:
    - name: finance-delegates
      roles: [finance]                 # the delegating user's roles (from user_roles)
      allowed_actions: [approve_invoice, "read:*"]
    - name: everyone-reads
      roles: [sales, finance]
      allowed_actions: ["read:*"]
```

- Rules **with** `roles`: when any exist, the delegating user must hold a role of at least one of
  them that allows every delegated action. Checked with the user's *current* roles at each use:
  a user who leaves finance loses the effect of their finance delegations.
- Rules **without** `roles` apply to everyone, all of them (as in 0.1).
- Action patterns are compared without reading wildcards as text: a rule allowing
  `read:[!s]*` refuses a delegation of `read:*`.
- `engine.create_delegation` refuses an agent with no profile. The CLI's `--from-user` is not
  authenticated: whoever can run it can delegate as anyone. Expose delegation to users through
  your application, after authenticating them.

Delegations are stored in `delegations.jsonl` next to the audit log; every engine reading that
directory sees them, and a revocation in one process takes effect in the others.

---

## Expiry

Delegations are automatically invalid once `expires_at` is in the past. The `DelegationManager.check()` verifies this on every call — no background process needed.

---

## Revocation

### Python API

```python
engine.revoke_delegation(grant.delegation_id)  # Returns True on success
```

### CLI

```bash
agent-auth -c agent_auth.yaml delegations --revoke <DELEGATION_ID>
```

---

## Listing delegations

### CLI

```bash
agent-auth -c agent_auth.yaml delegations --list
```

---

## How delegation interacts with resolution

A user's active delegations to an agent are part of what the agent may do **for that user**
(see [Resolution](resolution.md)): `baseline ∪ grants ∪ delegations`, then minus the profile's
`deny` and the code limits. Denials and limits always win over a delegation; a delegation never
applies to another user or to a service request.
