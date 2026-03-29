# Concepts

How agent-auth evaluates authorization requests, and the mental model behind every decision.

---

## The authorization pipeline

Every call to `engine.authorize(request)` goes through an 8-step pipeline:

```
Request
  |
  v
[1] Session validation (if session_id provided)
  |  - Is the session active and not expired?
  |  - Does the session agent/user match the request?
  |
  v
[2] Resolve agent profile
  |  - Look up the profile by agent name
  |
  v
[3] Check profile deny list
  |  - Is the action explicitly denied?
  |  - Does the scope match allowed scopes?
  |
  v
[4] Check profile allow list
  |  - Is the action in the effective_actions?
  |
  v
[5] Check delegations
  |  - Is there an active delegation granting this action?
  |
  v
[6] Check user permissions (if provider configured)
  |  - Does the user have this action in their IAM?
  |
  v
[7] A2A check (if target_agent is set)
  |  - Match against a2a.policies
  |  - Fall back to a2a.default
  |
  v
[8] Approval policy evaluation
  |  - Do any policies match this action?
  |  - What tier is required?
  |  - Escalation: pick the most restrictive tier
  |
  v
Decision (AuthDecision)
```

## Permission model

Permissions in agent-auth are **additive from roles** and **subtractive from profiles**.

1. **Roles** define sets of allowed actions. Roles can inherit from one parent via `extends`.
2. **Agent profiles** assign a role to an agent and optionally:
   - **Allow** additional actions beyond the role
   - **Deny** specific actions (overrides role + allow)
   - **Scope** the agent to resource patterns

The resolved set of permissions is:

```
effective_actions = (role_actions + allow_list) - deny_list
```

A request is permitted only if:

- The action is in `effective_actions` (via fnmatch matching)
- The action is **not** matched by `denied_actions`
- The scope (if provided) matches the profile's `allowed_scopes`

## Roles vs. profiles

| | Role | Agent profile |
|---|---|---|
| **Defines** | A set of actions | An agent's identity + constraints |
| **Inheritance** | Roles inherit via `extends` (single parent) | Profiles reference one role |
| **Allow** | Actions list | Can add extra actions |
| **Deny** | N/A | Can deny specific actions |
| **Scope** | N/A | Limits resource access via fnmatch |
| **Quantity** | Few (3-5 typical) | One per agent |

## Sessions

Sessions add a **time dimension** to authorization:

- A session is created for a specific agent + user + scope
- The session has a duration in seconds (default from config)
- When a request includes a `session_id`, the engine validates that the session is active and the agent/user match
- Sessions can be revoked before expiry
- Session IDs are UUID4

Sessions are optional. Requests without a `session_id` are evaluated normally.

## Approval tiers

Not every action should be autonomous. The three-tier model:

| Tier | Value | Meaning |
|---|---|---|
| Autonomous | `autonomous` | Agent can proceed without asking |
| Soft | `soft` | Another agent or automated system should approve |
| Strong | `strong` | A human must explicitly approve |

See [Approval Tiers](approval-tiers.md) for the full model.

## Delegation

Users can temporarily grant agents additional permissions:

- Scoped to specific actions
- Time-limited (duration in seconds, cannot exceed `delegation.max_duration`)
- Constrained by `delegation.rules`
- Revocable at any time

See [Delegation](delegation.md) for details.

## Agent-to-agent (A2A)

When one agent invokes another, A2A rules control the interaction:

- Rules specify `from_agent`, `to_agent`, `action`, and `effect` (allow/deny)
- Wildcards (`*`) match any agent or action
- Conditions use the safe expression language
- A default (allow/deny) applies when no rule matches
- Deny overrides allow when both match

See [A2A Authorization](a2a.md) for details.
