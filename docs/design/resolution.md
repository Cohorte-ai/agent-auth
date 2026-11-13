# Design: agent-auth 0.2, resolution

Status: draft for 0.2 (2026-11-11). Owner: maintainers.

## Problem

0.1 answers "may this agent do X?" by OR-ing four sources: the agent's profile, a delegation,
the user's own permissions (`user_permissions_provider`) and A2A rules. Two consequences:

- **Identities mix silently.** With a user-permissions provider, an agent acting for an admin
  can do everything the admin can, far beyond its own profile. A request has no way to say "I
  act as a service, not for anyone".
- **Nobody can see what an agent may do.** There is no answer to "what can Alice's assistant
  do right now, and why?" without replaying the code.

(A third, a delegation that applied to every user, was a bug and is fixed in 0.1.4.)

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

resolved = engine.resolve("assistant", Principal.user("alice"))      # or Principal.service()
resolved.capabilities["read:*"]     # [Provenance("baseline"), ...]
engine.explain(request)             # decision + the capability or denial that decided it
engine.preview("assistant", Principal.user("alice", roles=["finance"]))  # for admins
```

`authorize(request)` keeps its signature. A request carries `user` (on behalf of) as today, or
`identity="service"`.

## Delegation to sub-agents (attenuation)

`resolved.attenuate(child_agent, actions)` gives the child a ResolvedAgent containing only
actions that both the child's own resolution and the parent's allow, for the same principal,
never more. Tokens carry the chain, so a tool can see who delegated to whom.

## Tokens

`engine.issue_token(resolved, audience, ttl)` returns a short-lived token (HMAC-SHA256 with a key
the application provides) carrying agent, principal, identity mode, audience, expiry and the
capability fingerprint. `engine.verify_token(token, audience)` refuses a wrong audience, an
expired token, a bad signature, or a fingerprint that no longer matches the current policy
(the policy changed since it was issued). For tool servers (MCP) that must check the caller.

## Separation of duties

`separation_of_duties: [{name, actions: [create_payment, approve_payment], per: resource}]`:
the same principal cannot perform two of the listed actions on the same resource. Recorded
from allowed decisions in the engine (and its audit log when enabled).

## Approval

Approval tiers stay in agent-auth 0.2 unchanged (compatibility). New code should use
guardrails flow control proposals; the docs say so. Removal not before 1.0.

## Compatibility

- Every 0.1 config loads and decides the same way, except the 0.1.4 delegation fix.
- `user_permissions_provider` keeps its 0.1 behaviour with a `DeprecationWarning` the first
  time it grants something the agent's own resolution would not, pointing to `grants`.
  `resolution: {user_permissions: ignore}` turns the union off now; 1.0 removes it.
- New config keys are optional: `access`, `grants` (per profile), `separation_of_duties`,
  `resolution`.

## Not in 0.2

- Per-resource ABAC beyond scopes and approval conditions (the expression language covers the
  common cases).
- An identity provider integration: `user_roles` is a function the application supplies.
- Token revocation lists: tokens are short-lived by design.
