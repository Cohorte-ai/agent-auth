# API Reference

Python classes and methods for `theaios-agent-auth`.

---

## Config

### `load_config(path: str = "agent_auth.yaml") -> AuthConfig`

Load and validate a YAML config file.

```python
from theaios.agent_auth.config import load_config

config = load_config("agent_auth.yaml")
```

**Raises:**

| Exception | When |
|---|---|
| `FileNotFoundError` | File does not exist |
| `ConfigError` | Invalid YAML, missing fields, bad references |

### `AuthConfig`

Top-level configuration dataclass:

| Attribute | Type | Description |
|---|---|---|
| `version` | `str` | Config format version (e.g., `"1.0"`) |
| `metadata` | `AuthMetadata` | Name, description, author |
| `variables` | `dict[str, object]` | Resolved key-value pairs |
| `roles` | `dict[str, RoleConfig]` | Role definitions |
| `profiles` | `dict[str, AgentProfileConfig]` | Agent profile definitions |
| `approval_policies` | `list[ApprovalPolicyConfig]` | Approval policies |
| `delegation` | `DelegationConfig` | Delegation configuration |
| `a2a` | `A2AConfig` | A2A configuration |
| `sessions` | `SessionConfig` | Session configuration |
| `audit` | `AuditConfig` | Audit configuration |

### `ConfigError`

Raised when config loading or validation fails. Has an `errors` attribute (list of strings).

---

## Engine

### `AuthEngine(config, user_permissions_provider=None)`

The core authorization engine.

```python
from theaios.agent_auth.engine import AuthEngine

engine = AuthEngine(config)
engine = AuthEngine(config, user_permissions_provider=my_callback)
```

**Parameters:**

| Name | Type | Description |
|---|---|---|
| `config` | `AuthConfig` | Loaded configuration |
| `user_permissions_provider` | `Callable[[str], set[str]] \| UserPermissionsProvider \| None` | Optional callback for user permissions |

### `engine.authorize(request) -> AuthDecision`

Evaluate an authorization request through the 8-step pipeline.

### `engine.create_session(agent, user, scope="", duration=None) -> Session`

Create a new session. Duration in seconds (defaults to profile or config default).

### `engine.revoke_session(session_id) -> bool`

Revoke an active session. Returns `True` if revoked, `False` if not found.

### `engine.create_delegation(from_user, to_agent, actions, duration=None, reason="") -> DelegationGrant`

Create a delegation grant. Duration in seconds. Raises `ValueError` on constraint violations.

### `engine.revoke_delegation(delegation_id) -> bool`

Revoke an active delegation. Returns `True` if revoked, `False` if not found.

### `engine.authorize_async(request) -> AuthDecision`

Async version of authorize (runs in thread).

---

## Types

### `AuthRequest`

```python
from theaios.agent_auth.types import AuthRequest

request = AuthRequest(
    agent="assistant",
    user="alice",
    action="read",
    resource="/projects/acme",
    session_id=None,
    scope="",
    target_agent=None,
    metadata={},
)
```

| Field | Type | Default | Description |
|---|---|---|---|
| `agent` | `str` | *(required)* | Agent name |
| `user` | `str` | *(required)* | User on whose behalf the agent acts |
| `action` | `str` | *(required)* | Action to authorize |
| `resource` | `str` | `""` | Target resource path |
| `session_id` | `str \| None` | `None` | Session ID for session-gated auth |
| `scope` | `str` | `""` | Resource scope |
| `target_agent` | `str \| None` | `None` | Target agent for A2A authorization |
| `metadata` | `dict[str, object]` | `{}` | Arbitrary metadata |

### `AuthDecision`

| Field | Type | Default | Description |
|---|---|---|---|
| `allowed` | `bool` | *(required)* | Whether the action is permitted |
| `tier` | `str` | `"autonomous"` | Approval tier |
| `reason` | `str` | `""` | Human-readable explanation |
| `requires_approval` | `bool` | `False` | Whether approval is needed |
| `approval_policy` | `str` | `""` | Name of the matching approval policy |
| `evaluation_time_ms` | `float` | `0.0` | Evaluation time in milliseconds |

**Properties:**

| Property | Type | Description |
|---|---|---|
| `is_denied` | `bool` | `not allowed` |
| `is_autonomous` | `bool` | `allowed and tier == "autonomous" and not requires_approval` |

### `Session`

| Field | Type | Default | Description |
|---|---|---|---|
| `session_id` | `str` | *(required)* | Unique ID (UUID4) |
| `agent` | `str` | *(required)* | Agent name |
| `user` | `str` | *(required)* | User name |
| `scope` | `str` | `""` | Session scope |
| `created_at` | `str` | `""` | ISO 8601 timestamp |
| `expires_at` | `str` | `""` | ISO 8601 timestamp |
| `status` | `str` | `"active"` | `"active"`, `"revoked"`, or `"expired"` |

### `DelegationGrant`

| Field | Type | Default | Description |
|---|---|---|---|
| `delegation_id` | `str` | *(required)* | Unique ID |
| `from_user` | `str` | *(required)* | User who granted the delegation |
| `to_agent` | `str` | *(required)* | Agent receiving permissions |
| `actions` | `list[str]` | `[]` | Delegated actions |
| `granted_at` | `str` | `""` | ISO 8601 timestamp |
| `expires_at` | `str` | `""` | ISO 8601 timestamp |
| `reason` | `str` | `""` | Reason for delegation |
| `status` | `str` | `"active"` | `"active"`, `"revoked"`, or `"expired"` |

---

## Config types

### `RoleConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | `str` | *(required)* | Role name |
| `actions` | `list[str]` | `[]` | Actions this role grants |
| `extends` | `str` | `""` | Parent role name |
| `description` | `str` | `""` | Description |

### `AgentProfileConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | `str` | *(required)* | Profile name |
| `role` | `str` | `""` | Role to assign |
| `allow` | `list[str]` | `[]` | Extra actions to allow |
| `deny` | `list[str]` | `[]` | Actions to deny |
| `scopes` | `list[str]` | `[]` | Allowed scope patterns |
| `max_session_duration` | `int` | `3600` | Max session duration (seconds) |
| `default_tier` | `str` | `"autonomous"` | Default approval tier |
| `description` | `str` | `""` | Description |

### `ApprovalPolicyConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | `str` | *(required)* | Policy name |
| `condition` | `str` | `""` | Expression string |
| `tier` | `str` | `"soft"` | Approval tier |
| `description` | `str` | `""` | Description |

---

## Enums

### `ApprovalTier`

```python
ApprovalTier.AUTONOMOUS   # "autonomous"
ApprovalTier.SOFT          # "soft"
ApprovalTier.STRONG        # "strong"
```

### `A2ADefault`

```python
A2ADefault.ALLOW   # "allow"
A2ADefault.DENY    # "deny"
```

### `SessionStatus`

```python
SessionStatus.ACTIVE    # "active"
SessionStatus.REVOKED   # "revoked"
SessionStatus.EXPIRED   # "expired"
```

### `DelegationStatus`

```python
DelegationStatus.ACTIVE    # "active"
DelegationStatus.REVOKED   # "revoked"
DelegationStatus.EXPIRED   # "expired"
```

---

## Constants

| Constant | Type | Description |
|---|---|---|
| `VALID_TIERS` | `set[str]` | `{"autonomous", "soft", "strong"}` |
| `VALID_A2A_DEFAULTS` | `set[str]` | `{"allow", "deny"}` |
| `VALID_SESSION_STATUSES` | `set[str]` | `{"active", "revoked", "expired"}` |
| `VALID_DELEGATION_STATUSES` | `set[str]` | `{"active", "revoked", "expired"}` |
| `TIER_ORDER` | `dict[str, int]` | `{"autonomous": 0, "soft": 1, "strong": 2}` |

---

## Adapters

### `GuardrailsAuthAdapter`

```python
from theaios.agent_auth.adapters.guardrails import GuardrailsAuthAdapter

adapter = GuardrailsAuthAdapter(
    auth_config=config,
    guardrails_engine=engine,
    default_user="system",
)
decision = adapter.evaluate(event, user="alice")
```

---

## Exceptions

| Exception | Module | Description |
|---|---|---|
| `ConfigError` | `theaios.agent_auth.config` | Config loading/validation failure |
| `ExpressionError` | `theaios.agent_auth.expressions` | Expression parse/evaluation failure |
| `ValueError` | (builtin) | Delegation constraint violation |
