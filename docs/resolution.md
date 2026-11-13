# Resolution: what an agent may do, for whom, and why

Since 0.2, agent-auth answers one question before every decision: **what may this agent do for
this principal right now?** The answer is a `ResolvedAgent`: every permission with where it
came from, every denial with why. `authorize` checks requests against it; `preview` shows it to
an administrator; tokens carry its fingerprint.

```
access(agent, principal)?           no -> denied before anything else
          | yes
baseline(agent) ∪ grants[agent][role] for each of the principal's roles ∪ the user's delegations
          minus the profile's deny and the limits set in code
          = ResolvedAgent
```

---

## Principals: one identity per request

An agent acts **for a user** (`identity="on_behalf_of"`, the default) or **as a service**, for
no one (`identity="service"`). A request is one or the other; agent-auth never mixes them.

| | For a user | As a service |
|---|---|---|
| Baseline (role + allow) | yes | yes |
| Grants for the user's roles | yes | no |
| The user's delegations | yes | no |
| `user` on the request | required | must be empty |

```python
engine.authorize(AuthRequest(agent="assistant", user="alice", action="approve_invoice"))
engine.authorize(AuthRequest(agent="nightly-report", user="", action="read:sales",
                             identity="service"))
```

The user's roles come from your application (your identity provider), not from the config:

```python
engine = AuthEngine(config, user_roles=lambda user: idp.roles_of(user))
```

---

## Access and grants

```yaml
profiles:
  assistant:
    role: reader                 # baseline: what it may do for anyone it serves
    deny: ["read:secrets"]
    access: [finance, sales]     # who may use it: principal roles or user names; "service"
                                 # admits service requests. Absent: everyone (0.1 behaviour).
    grants:                      # what it may additionally do for a role
      finance: [approve_invoice, "export:ledger"]
      sales: [send_quote]
```

`grants` keys are the **user's** roles, from `user_roles`. They are unrelated to the top-level
`roles:` section, which defines bundles of actions for agents.

Grants replace the 0.1 `user_permissions_provider`, which let an agent do anything its user may
do, far beyond the agent's own profile. That union still works in 0.2, with a
`DeprecationWarning` the first time it decides something; turn it off now with
`resolution: {user_permissions: ignore}`. It is removed in 1.0.

---

## Limits that no config can widen

Some things must never happen whatever the YAML says. Declare them in code:

```python
engine = AuthEngine(config, limits={"*": ["payments:*"], "intern-bot": ["delete_*"]})
```

Limits apply after everything, including grants and delegations. A config change, a grant or a
delegation cannot lift them.

---

## See it: preview, explain, provenance

```python
r = engine.preview("assistant", engine.principal("alice"))
r.capabilities    # {"read:*": ["baseline"], "approve_invoice": ["grant:finance"]}
r.denials         # {"read:secrets": ["deny"], "payments:*": ["limit"]}
r.fingerprint     # changes whenever what the agent may do for alice changes

d = engine.explain(request)   # the decision authorize would make; logs and records nothing
d.provenance                  # ["grant:finance:approve_invoice"]
```

```bash
agent-auth -c agent_auth.yaml preview --agent assistant --user alice --roles finance
agent-auth -c agent_auth.yaml check --agent assistant --user alice --roles finance \
    --action approve_invoice          # prints "Because: grant:finance:approve_invoice"
```

Every `AuthDecision` carries `provenance`: `baseline:<pattern>`, `grant:<role>:<pattern>`,
`delegation:<id>:<pattern>`, `deny:<pattern>`, `limit:<pattern>`, `access`, `scope`,
`separation_of_duties` or `user_permissions`.

---

## Sub-agents: delegation by attenuation

When an agent hands work to a sub-agent, the sub-agent may do only what **both** may do, for
the same principal:

```python
parent = engine.resolve("assistant", engine.principal("alice"))
child = engine.delegate(parent, "researcher")   # intersection of both resolutions
child.chain                                     # ["assistant"]
```

A pattern is kept when one side covers the other (`read:*` and `read:docs` give `read:docs`);
both sides' denials apply; if both declare scopes and none is shared, the sub-agent has no
access. A sub-agent never gets more than its parent.

---

## Tokens for tool servers

A tool server (an MCP server, an internal API) must know who is calling and what they may do.
The agent runtime issues a short-lived token for that audience; the tool server verifies it.

```python
engine = AuthEngine(config, user_roles=..., token_key=os.environb[b"AGENT_AUTH_KEY"])  # >= 32 bytes

token = engine.issue_token(child, audience="mcp://ledger", ttl=300)   # at most 3600 s
# ... the tool server, with the same config and key:
verified = engine.verify_token(token, audience="mcp://ledger")
allowed, why = verified.resolved.check("export:ledger")
```

Verification refuses a bad signature, another audience, an expired token, and a token whose
resolution changed since it was issued: a policy edit, a user who lost a role, a revoked
delegation. The token is signed (HMAC-SHA256), not encrypted: it carries the user name and
roles. There is no revocation list; keep tokens short-lived.

---

## Separation of duties

```yaml
separation_of_duties:
  - name: payments
    actions: [create_payment, approve_payment]
```

The same user cannot perform two of these actions on the same `resource`: after Alice creates
payment `inv-1`, Alice approving `inv-1` is denied (Bob may approve it). Recorded from allowed
decisions in the engine's memory: it holds for the engine's lifetime, not across restarts or
several engine processes. `explain` records nothing.

---

## Approval

Approval tiers (`approval_policies`) work as in 0.1. For new code, prefer
[theaios-guardrails flow control](https://github.com/Cohorte-ai/guardrails/blob/main/docs/flow-control.md):
its proposals are frozen to the call's arguments, decided once and executed once.
