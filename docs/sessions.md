# Sessions

Time-limited, scope-bound authorization contexts.

---

## What are sessions?

A session represents a bounded authorization context: a specific agent, acting on behalf of a specific user, within a specific scope, for a limited time.

Sessions answer: **"Is this agent currently authorized to operate?"**

---

## Session lifecycle

```
Create ──> Active ──> Expired (automatic, duration elapsed)
                  |
                  └──> Revoked (explicit revocation)
```

### Creating a session

**Python API:**

```python
session = engine.create_session(
    agent="assistant",
    user="alice",
    scope="project:acme",
    duration=3600,       # optional, seconds
)
print(session.session_id)   # UUID4
print(session.expires_at)   # ISO 8601
```

**CLI:**

```bash
agent-auth -c agent_auth.yaml sessions --create \
    --agent assistant \
    --user alice \
    --scope "project:acme" \
    --duration 3600
```

### Using a session

Include the `session_id` in the `AuthRequest`:

```python
request = AuthRequest(
    agent="assistant",
    user="alice",
    action="read",
    session_id=session.session_id,
)
decision = engine.authorize(request)
```

### Revoking a session

**Python API:**

```python
engine.revoke_session(session.session_id)  # Returns True on success
```

**CLI:**

```bash
agent-auth -c agent_auth.yaml sessions --revoke <SESSION_ID>
```

---

## Session fields

| Field | Type | Description |
|---|---|---|
| `session_id` | `str` | Unique identifier (UUID4) |
| `agent` | `str` | Agent this session is for |
| `user` | `str` | User on whose behalf the agent acts |
| `scope` | `str` | Session scope |
| `created_at` | `str` | ISO 8601 timestamp |
| `expires_at` | `str` | ISO 8601 timestamp |
| `status` | `str` | `"active"`, `"revoked"`, or `"expired"` |

---

## Session validation

When a request includes a `session_id`, the engine:

1. Looks up the session
2. Checks the session is `active` (not revoked or expired)
3. Checks the session has not passed its `expires_at`
4. Verifies the session `agent` matches the request `agent`
5. Verifies the session `user` matches the request `user`

If any check fails, the request is denied with a descriptive reason.

---

## Configuration

```yaml
sessions:
  default_duration: 3600      # Default duration in seconds (1 hour)
  max_duration: 86400          # Max duration in seconds (24 hours)
  cleanup_interval: 300        # Cleanup interval in seconds (5 minutes)
```

When creating a session via the engine, if no duration is specified, the engine uses the profile's `max_session_duration` (if the agent has a profile) or `sessions.default_duration`. The duration is clamped to `sessions.max_duration`.

---

## Listing sessions

**CLI:**

```bash
agent-auth -c agent_auth.yaml sessions --list
```

---

## Session storage

Sessions are persisted to a JSONL file (`.agent_auth/sessions.jsonl`) for durability across restarts.
