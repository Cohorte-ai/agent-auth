# Delegation

Temporary permission grants from users to agents.

---

## What is delegation?

Delegation allows a user to temporarily grant an agent permissions it would not otherwise have. This is useful for:

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
      allowed_actions: [read, write, deploy]
      max_duration: 86400
    - name: editor-delegation
      allowed_actions: [read, write]
      max_duration: 14400
      require_reason: true
```

| Constraint | Description |
|---|---|
| `enabled` | If `false`, all delegation requests are rejected |
| `max_duration` | Global maximum in seconds |
| `rules` | Additional constraints (per-rule allowed_actions, max_duration, require_reason) |

If a delegation request violates any constraint, a `ValueError` is raised.

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

## How delegation interacts with the pipeline

In the authorization pipeline, delegation is checked at **step 5** — after session validation, profile deny check, and profile allow check, but before user permissions and A2A. If an active delegation grants the requested action to the agent, the action is allowed.

```
[4] Check profile allow list
        |
        v
[5] Check delegations  <-- active grant? allow the action
        |
        v
[6] Check user permissions
```
