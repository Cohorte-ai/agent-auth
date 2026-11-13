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

engine.principal("alice")          # a user principal, roles from user_roles
engine.principal(service=True)     # the service principal (for resolve and preview)
```

`user_roles` must return a collection of role names. If it raises, returns `None` or returns a
string, the request is denied with the reason (the identity provider failed: fail closed).

---

## Access and grants

```yaml
profiles:
  assistant:
    role: reader                 # baseline: what it may do for anyone it serves
    deny: ["read:secrets"]
    access: [finance, sales, "user:carol"]   # role names; "user:<name>" for one user;
                                 # "service" for service requests. Absent: everyone (0.1).
    grants:                      # what it may additionally do for a role
      finance: [approve_invoice, "export:ledger"]
      sales: [send_quote]
```

`grants` keys are the **user's** roles, from `user_roles`. They are unrelated to the top-level
`roles:` section, which defines bundles of actions for agents.

A plain entry in `access` is always a role, never a user name: a user called `finance` or
`service` does not match them.

Grants replace the 0.1 `user_permissions_provider`, which let an agent do anything its user may
do, far beyond the agent's own profile. That union still works in 0.2: its actions appear in
`preview` with the source `user_permissions`, and a `FutureWarning` names the agent, action and
user the first time it decides each (agent, action) pair. Turn it off now with
`resolution: {user_permissions: ignore}`. It is removed in 1.0.

If a grant does not apply, the denial says why: `(granted to roles finance; 'bob' has sales)`
or `('alice' has no roles: no user_roles was given to the engine)`.

---

## Limits that no config can widen

Some things must never happen whatever the YAML says. Declare them in code:

```python
engine = AuthEngine(config, limits={"*": ["payments:*"], "intern-bot": ["delete_*"]})
```

Limits apply after everything, including grants and delegations. A config change, a grant or a
delegation cannot lift them. They are checked when the engine is built: keys must be `"*"` or
an agent that has a profile (no other wildcard), values lists of patterns.

Denials and limits match **regardless of case** (`payments:*` blocks `PAYMENTS:transfer`);
capabilities match exactly. Use one spelling for your actions. An action that is empty or
surrounded by spaces is refused.

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
`delegation:<id>:<pattern>`, `user_permissions:<pattern>`, `deny:<pattern>`,
`limit:<pattern>`, `access`, `scope`, `a2a` or `separation_of_duties`. For a sub-agent,
sources inherited from the parent end in `@<parent>` (`grant:finance@assistant`).

---

## Sub-agents: delegation by attenuation

When an agent hands work to a sub-agent, the sub-agent may do only what **both** may do, for
the same principal:

```python
parent = engine.resolve("assistant", engine.principal("alice"))
child = engine.delegate(parent, "researcher")   # intersection of both resolutions
child.chain                                     # ["assistant"]
```

A pattern is kept when one side provably covers the other (`read:*` and `read:docs` give
`read:docs`). Wildcards are never read as text: a parent limited to `read:[!s]*` gives a child
holding `read:*` nothing for reading, rather than `read:*`. Both sides' denials apply; if both
declare scopes and none is shared, the sub-agent has no access. A sub-agent never gets more
than its parent.

The hand-off itself is agent-to-agent: `delegate` gives no access unless the A2A rules let the
parent reach the child (`a2a.default` is `deny` unless you allow it), and each action the child
takes is checked against the A2A policies from parent to child.

At run time, decide the sub-agent's requests **against its attenuated resolution**, not afresh:

```python
engine.authorize(AuthRequest(agent="researcher", user="alice", action="read:docs"),
                 resolved=child)
```

`authorize` on its own resolves the sub-agent from scratch, as if no parent existed.

With `resolved=`, `authorize` re-derives the chain and refuses a resolution that is **stale**
(a delegation revoked, a role lost, a policy edited since it was derived): derive it again per
task, or keep it short-lived. Every hop of the chain is checked against the A2A policies for
the action; the request's scope must fit the scopes of every agent in the chain; and the
approval tier is the strictest of the chain's (a parent that needs strong approval passes that
on to its sub-agents).

---

## Tokens for tool servers

A tool server (an MCP server, an internal API) must know who is calling and what they may do.
The agent runtime issues a short-lived token for that audience; the tool server verifies it.

```python
engine = AuthEngine(config, user_roles=..., limits=...,
                    token_key=os.environb[b"AGENT_AUTH_KEY"])   # bytes, at least 32

token = engine.issue_token(child, audience="mcp://ledger", ttl=300)   # at most 3600 s

# The tool server, built with the same config, limits, user_roles and key:
verified = engine.verify_token(token, audience="mcp://ledger")
decision = engine.authorize(
    AuthRequest(agent=verified.claims.agent, user=verified.claims.user, action="export:ledger",
                resource="ledger-2026", identity=verified.claims.identity),
    resolved=verified.resolved,
)
if decision.is_autonomous: ...            # approval tiers, scopes and separation of duties apply
```

Use `authorize(..., resolved=verified.resolved)`, not `verified.resolved.check(action)`:
`check` answers only "is this action in the resolution" and knows nothing of approval tiers,
scopes or separation of duties.

Verification refuses a bad or non-canonical encoding, a bad signature, another audience, a
token issued in the future (issuer clock ahead), a lifetime over an hour, an expired token, and
a token whose resolution differs from the verifier's: a policy edit, a user who lost (or
gained) a role, a revoked delegation, or a verifier whose config, limits or `user_roles` differ
from the issuer's. `leeway=` (seconds of clock tolerance) is at most 300.

- **Key rotation**: `token_key=[new_key, old_key]` signs with the first and verifies with all.
- **Size**: about 300 bytes, plus the user's role names (hundreds of roles exceed HTTP header
  limits).
- The token is signed (HMAC-SHA256), not encrypted: it carries the user name and roles. There
  is no revocation list; keep tokens short-lived.

---

## Separation of duties

```yaml
separation_of_duties:
  - name: payments
    actions: [create_payment, approve_payment]
```

The same user cannot perform two of these actions on the same `resource`: after Alice creates
payment `inv-1`, Alice approving `inv-1` is denied (Bob may approve it).

- Actions and resources are compared regardless of case and surrounding spaces (`INV-1`,
  ` inv-1 `). A request without a resource counts as one shared resource: send the resource.
- Recorded when `authorize` allows the action (including "allowed, requires approval"), in the
  engine's memory: it holds for the engine's lifetime, not across restarts or several engine
  processes. `explain` records nothing.

---

## Approval

Approval tiers (`approval_policies`) work as in 0.1. For new code, prefer
[theaios-guardrails flow control](https://github.com/Cohorte-ai/guardrails/blob/main/docs/flow-control.md):
its proposals are frozen to the call's arguments, decided once and executed once.

---

## Several processes

Delegations and sessions live in files next to the audit log (`delegations.jsonl`,
`sessions.jsonl`). Every engine reloads them when another process changed them, so a revocation
in one process takes effect in a long-running verifier. Two processes writing at the same
moment can still lose one write; create and revoke from one place. Separation of duties is
per process (above).

