# Config Syntax

Complete YAML reference for `agent_auth.yaml`.

---

## Top-level structure

```yaml
version: "1.0"                  # Required. Config format version.

metadata:                       # Optional. Descriptive metadata.
  name: my-config
  description: Auth policy for my agent fleet
  author: team@example.com

variables:                      # Optional. Key-value pairs, supports ${ENV_VAR}.
  env: production
  region: ${AWS_REGION}

roles:                          # Required. Role definitions.
  ...

profiles:                       # Required. Agent profile definitions.
  ...

approval_policies:              # Optional. Approval tier policies (list).
  ...

delegation:                     # Optional. Delegation configuration.
  ...

a2a:                            # Optional. Agent-to-agent authorization.
  ...

sessions:                       # Optional. Session configuration.
  ...

audit:                          # Optional. Audit logging configuration.
  ...
```

---

## `version`

| Field | Type | Required | Description |
|---|---|---|---|
| `version` | `string` | Yes | Config format version. Currently `"1.0"`. |

---

## `metadata`

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | `string` | No | Human-readable config name |
| `description` | `string` | No | What this config is for |
| `author` | `string` | No | Team or individual responsible |

---

## `variables`

Key-value pairs available for reference in expressions via `$variable_name`. Supports environment variable interpolation with `${ENV_VAR}` syntax.

```yaml
variables:
  env: ${DEPLOY_ENV}       # Resolved from environment at load time
  admin_role: admin        # Static value, referenced in expressions as $admin_role
```

If an environment variable is not set, the placeholder is kept as-is.

---

## `roles`

Each role is a named entry under `roles:`.

| Field | Type | Required | Description |
|---|---|---|---|
| `actions` | `list[string]` | Yes | Actions this role grants |
| `extends` | `string` | No | Single parent role to inherit actions from |
| `description` | `string` | No | Human-readable description |

```yaml
roles:
  viewer:
    actions: [read, list]
    description: Read-only access

  editor:
    extends: viewer
    actions: [write, update]
    description: Can modify resources

  admin:
    extends: editor
    actions: [delete, manage]
```

**Inheritance** follows a single-parent chain via `extends`. Circular inheritance is detected and raises a `ConfigError`.

---

## `profiles`

Each agent profile is a named entry under `profiles:`.

| Field | Type | Required | Description |
|---|---|---|---|
| `role` | `string` | No | Role name to assign |
| `allow` | `list[string]` | No | Additional actions to allow (added to role actions) |
| `deny` | `list[string]` | No | Actions to explicitly deny (overrides role + allow) |
| `scopes` | `list[string]` | No | Scope patterns limiting access. Empty = all scopes. |
| `max_session_duration` | `int` | No | Max session duration in seconds. Default: `3600` |
| `default_tier` | `string` | No | Default approval tier. Default: `"autonomous"` |
| `description` | `string` | No | Human-readable description |

```yaml
profiles:
  copilot:
    role: editor
    allow: [suggest]
    deny: [delete]
    scopes: ["project:*"]
    default_tier: autonomous
    description: Developer copilot
```

**Scope matching** uses `fnmatch` glob syntax:
- `project:*` matches `project:acme` and `project:beta`
- An empty `scopes` list means all scopes are allowed

**Deny overrides** are applied after role resolution and allow additions. If an action is in both the effective actions and the deny list, it is denied.

---

## `approval_policies`

A **list** of policy objects (not a dict).

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | `string` | Yes | Unique policy name |
| `condition` | `string` | No | Expression string. Empty = always matches. |
| `tier` | `string` | Yes | One of: `autonomous`, `soft`, `strong` |
| `description` | `string` | No | Human-readable description |

```yaml
approval_policies:
  - name: prod_deploy
    condition: 'action == "deploy" and resource starts_with "/prod"'
    tier: strong

  - name: low_risk
    condition: ""
    tier: autonomous
```

**Escalation**: if multiple policies match a request, the most restrictive tier wins:
`strong > soft > autonomous`.

**Conditions** use the safe expression language. See [Expressions](expressions.md).

---

## `delegation`

| Field | Type | Required | Description |
|---|---|---|---|
| `enabled` | `bool` | No | Whether delegation is enabled. Default: `true` |
| `default_duration` | `int` | No | Default duration in seconds. Default: `3600` |
| `max_duration` | `int` | No | Maximum duration in seconds. Default: `86400` |
| `rules` | `list[object]` | No | Additional delegation rules |

Each rule in `rules`:

| Field | Type | Description |
|---|---|---|
| `name` | `string` | Unique rule name |
| `allowed_actions` | `list[string]` | Actions that can be delegated |
| `max_duration` | `int` | Max duration in seconds for this rule |
| `require_reason` | `bool` | Whether a reason must be provided |
| `description` | `string` | Human-readable description |

```yaml
delegation:
  enabled: true
  default_duration: 3600
  max_duration: 86400
  rules:
    - name: admin-delegation
      allowed_actions: [read, write, deploy]
      max_duration: 86400
    - name: editor-delegation
      allowed_actions: [read, write]
      max_duration: 14400
      require_reason: true
```

---

## `a2a`

| Field | Type | Required | Description |
|---|---|---|---|
| `default` | `string` | Yes | Default behavior: `"allow"` or `"deny"` |
| `policies` | `list[object]` | No | A2A authorization policies |

Each policy:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | `string` | Yes | Unique policy name |
| `from_agent` | `string` | No | Source agent. `"*"` = any. Default: `"*"` |
| `to_agent` | `string` | No | Target agent. `"*"` = any. Default: `"*"` |
| `action` | `string` | No | Action covered. `"*"` = any. Default: `"*"` |
| `effect` | `string` | Yes | `"allow"` or `"deny"` |
| `condition` | `string` | No | Expression string |
| `description` | `string` | No | Human-readable description |

```yaml
a2a:
  default: deny
  policies:
    - name: copilot-to-reviewer
      from_agent: copilot
      to_agent: reviewer
      action: read
      effect: allow
    - name: any-to-logger
      from_agent: "*"
      to_agent: logger
      action: log
      effect: allow
```

---

## `sessions`

| Field | Type | Required | Description |
|---|---|---|---|
| `default_duration` | `int` | No | Default session duration in seconds. Default: `3600` |
| `max_duration` | `int` | No | Maximum session duration in seconds. Default: `86400` |
| `cleanup_interval` | `int` | No | Stale session cleanup interval in seconds. Default: `300` |

```yaml
sessions:
  default_duration: 3600
  max_duration: 86400
  cleanup_interval: 300
```

---

## `audit`

| Field | Type | Required | Description |
|---|---|---|---|
| `enabled` | `bool` | No | Whether audit logging is active. Default: `true` |
| `path` | `string` | No | Path to the JSONL log file. Default: `.agent_auth/audit.jsonl` |
| `retention_days` | `int` | No | How long to keep logs. Default: `90` |

```yaml
audit:
  enabled: true
  path: .agent_auth/audit.jsonl
  retention_days: 90
```

Audit logs are written as one JSON object per line. Each entry includes the request, the decision, and a timestamp.
