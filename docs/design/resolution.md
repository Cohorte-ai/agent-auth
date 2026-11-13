# Design: agent-auth 0.2, resolution

Status: implemented in 0.2.0 (2026-11-13). Owner: maintainers.

## Problem

0.1 answers "may this agent do X?" by OR-ing four sources: the agent's profile, a delegation,
the user's own permissions (`user_permissions_provider`) and A2A rules. Two consequences:

- **Identities mix silently.** With a user-permissions provider, an agent acting for an admin
  can do everything the admin can, far beyond its own profile. A request has no way to say "I
  act as a service, not for anyone".
- **Nobody can see what an agent may do.** There is no answer to "what can Alice's assistant
  do right now, and why?" without replaying the code.

(A third, a delegation that applied to every user, was a bug and is fixed in 0.1.4.)

## Threat model

Protects against:
- an agent doing more for a principal than the config, the user's roles, the user's own
  delegations and the code limits allow;
- identities mixing: one user's grants or delegations applying to another user, or to a
  service request;
- a sub-agent getting more than the agent that delegated to it;
- a token used against another audience, after expiry, after tampering, or after the
  permissions it stood for changed.

Trusts (out of scope): the application code calling the engine (it can call tools directly);
the `user_roles` function (it is the identity provider); the config file and the code limits;
the secrecy of the token key; the clock. The engine decides; it does not authenticate users.

In the adapters, the application builds the request's identity (agent, user, session,
target agent, scope; in token mode, the token); what the model can influence (the tool name,
action and resource of a guardrails event; the HTTP method, path and headers) is checked.

## The model

```
access(agent, principal)?           no  -> denied, before anything else
          | yes
baseline(agent) ∪ grants[agent][role] for each of the principal's roles     (additive)
          - deny(agent)                                                      (config)
          - limits(agent)            code-declared: config can never widen them
          ∪ delegations from this principal to this agent (also bounded by limits)
          = ResolvedAgent: every capability with its provenance
```

- **Principal**: who the agent acts for. `on_behalf_of` a user (with roles), or `service`
  (no user: the agent's own baseline only, no grants, no delegations). A request is one or the
  other; nothing is ever OR-ed across them.
- **Baseline**: what the agent may do for anyone it serves: today's profile (role + allow).
- **Access**: which principals may use the agent at all (`access: [roles or users]`; absent
  means everyone, as in 0.1).
- **Grants**: what the agent may additionally do for a principal holding a role
  (`grants: {finance: [approve_invoice]}`). This replaces the user-permissions union: the
  config says, per agent, what each role unlocks, instead of the agent inheriting everything
  the user can do.
- **Limits**: deny patterns passed in code (`AuthEngine(config, limits={...})`). They apply
  after everything, including delegations, and a config file cannot remove them. For the
  things that must never happen whatever the YAML says.
- **ResolvedAgent**: agent, principal, identity mode, roles, capabilities (pattern → list of
  provenance: `baseline`, `grant:<role>`, `delegation:<id>`), denials (pattern → provenance:
  `deny`, `limit`), scopes, and a fingerprint of all of it.

## API

```python
engine = AuthEngine(config, limits={"*": ["payments:*"]}, user_roles=lambda u: idp.roles(u))

resolved = engine.resolve("assistant", engine.principal("alice"))   # or principal(service=True)
resolved.capabilities["read:*"]     # ["baseline", ...]  (source strings)
engine.explain(request)             # decision + the capability or denial that decided it
engine.preview("assistant", Principal.for_user("alice", roles=["finance"]))  # for admins
```

`authorize(request)` keeps its signature. A request carries `user` (on behalf of) as today, or
`identity="service"`.

## Delegation to sub-agents (attenuation)

`engine.delegate(parent, child_agent)` gives the child a ResolvedAgent containing only actions
that both the child's own resolution and the parent's allow, for the same principal, never more
(patterns intersected conservatively: a wildcard is never read as text). The hand-off needs an
A2A allow; at run time every hop is checked per action, scopes must fit every agent in the
chain, and the approval tier is the chain's strictest. `authorize(request, resolved=...)`
re-derives the chain and refuses a stale resolution. Tokens carry the chain.

## Tokens

`engine.issue_token(resolved, audience, ttl)` returns a short-lived token (HMAC-SHA256 with a key
the application provides) carrying agent, principal, identity mode, audience, expiry and the
capability fingerprint. `engine.verify_token(token, audience)` refuses a wrong audience, an
expired token, a token issued in the future or living over an hour, a non-canonical encoding,
a bad signature, or a fingerprint that no longer matches the current resolution. Key rotation:
a list of keys, the first signs. Tool servers then call `authorize(..., resolved=...)` so
approval tiers, scopes and separation of duties apply.

## Separation of duties

`separation_of_duties: [{name, actions: [create_payment, approve_payment]}]`: the same principal
cannot perform two of the listed actions on the same resource (actions and resources compared
regardless of case and surrounding spaces; a missing resource is one shared resource). Recorded
from allowed decisions in the engine's memory, per process.

## Approval

Approval tiers stay in agent-auth 0.2 unchanged (compatibility). New code should use
guardrails flow control proposals; the docs say so. Removal not before 1.0.

## Compatibility

- Every 0.1 config loads and decides the same way, except the security fixes listed in the
  CHANGELOG (delegations bound to the user, A2A conditions on request fields, case-insensitive
  denials, session scopes, duplicate keys refused).
- `user_permissions_provider` keeps its 0.1 behaviour with a `FutureWarning` the first time it
  decides each (agent, action) pair, pointing to `grants`.
  `resolution: {user_permissions: ignore}` turns the union off now; 1.0 removes it.
- New config keys are optional: `access`, `grants` (per profile), `separation_of_duties`,
  `resolution`.

## Not in 0.2

- Per-resource ABAC beyond scopes and approval conditions (the expression language covers the
  common cases).
- An identity provider integration: `user_roles` is a function the application supplies.
- Token revocation lists: tokens are short-lived by design.
