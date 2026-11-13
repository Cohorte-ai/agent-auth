# Changelog

All notable changes to `theaios-agent-auth` will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] - 2026-11-13

### Added

- **Resolution** (`theaios.agent_auth.resolution`): what an agent may do for a principal, as a `ResolvedAgent` where every capability and denial carries its provenance (`baseline`, `grant:<role>`, `delegation:<id>`, `deny`, `limit`). `engine.resolve`, `engine.preview`, and `engine.explain(request)` (the decision without logging or recording). Every `AuthDecision` has `provenance`.
- Per-profile `access` (which user roles or users may use the agent; `service` admits service requests) and `grants` (what the agent may additionally do for a user role). User roles come from `AuthEngine(..., user_roles=...)`.
- **Limits in code**: `AuthEngine(..., limits={"*": ["payments:*"]})`. They apply after everything, including grants and delegations; no config can widen them.
- **One identity per request**: `AuthRequest(identity="service")` for an agent acting for no one (baseline only, no grants or delegations); a service request with a user is refused.
- **Sub-agents**: `engine.delegate(parent, child_agent)` returns the intersection of both resolutions, with the delegation chain.
- **Tokens**: `engine.issue_token(resolved, audience, ttl)` and `engine.verify_token(token, audience)`, HMAC-SHA256 with a key you provide, short-lived (at most an hour), audience-bound, and refused when the agent's permissions changed since issue.
- **Separation of duties**: `separation_of_duties: [{name, actions}]` prevents the same user from performing two of the listed actions on the same resource.
- CLI: `agent-auth preview`; `check --roles`, `check --service`, and the provenance of each decision.
- Docs: [Resolution](docs/resolution.md); design notes in `docs/design/resolution.md`.

### Changed (from the pre-release test, before 0.2.0 shipped)

Three testers (a newcomer, a red team, a platform engineer) tested the first 0.2 build. Fixed, each with a regression test (`tests/test_resolution_findings.py`):

- **Delegations**: rules can say who may delegate (`roles:`), checked with the delegating user's current roles at every use; disabling delegation or tightening a rule stops existing delegations; delegation rules and sub-agent attenuation no longer read wildcards as text (`read:[!s]*` no longer accepts `read:*`); no delegation to an agent without a profile. Also in 0.1.x: any user could delegate any action.
- **A2A** conditions see the request's `user`, `resource`, `scope` (they saw only caller metadata: a deny on `/prod` never fired, and `metadata.user` could impersonate). Sub-agent hand-offs (`delegate`) need an A2A allow.
- **Tool servers**: `authorize(request, resolved=...)` decides against a token's or sub-agent's resolution with approval tiers, scopes and separation of duties; the docs no longer recommend `ResolvedAgent.check` for that.
- **Access** entries: roles by name, users as `user:<name>`, `service` as a keyword (a user named `finance` or `service` matched them).
- **Matching**: denials and limits ignore case; separation of duties normalises actions and resources and treats a missing resource as one shared resource.
- **Limits** are validated when the engine is built (a string or a misspelled agent silently disabled them).
- **Tokens**: canonical encoding only; refused if issued in the future or living over an hour; `leeway` at most 300 s; key rotation (`token_key=[new, old]`); str keys and short keys refused at construction; clearer mismatch errors.
- **Sessions**: a session's scope binds its requests. Delegation and session files are reloaded when another process changes them.
- **Identity provider**: a `user_roles` that fails or returns a non-collection denies the request. `principal(user, service=True)` and CLI `--service --user` are refused.
- **Config**: duplicate YAML keys are refused; precise errors for grant values and separation-of-duties actions.
- Unknown agents have no access (except through the deprecated union, for compatibility); `preview` shows union actions; the audit log is private (0600) and records identity and provenance.

An independent re-verification then confirmed those fixes (76 of 79 checks; 17,280 0.1 decisions unchanged) and found more, also fixed with tests:

- `authorize(..., resolved=...)` re-derives the resolution and refuses a stale one (revoked delegation, lost role, policy edit); it checks A2A on every hop of a sub-agent chain, the scopes of every agent in the chain, and uses the chain's strictest approval tier.
- Limits given as a generator were consumed by validation and silently empty.
- Actions empty or surrounded by spaces are refused; A2A deny policies ignore case; approval conditions see `identity` (metadata cannot override it); delegations never apply to agents without a profile; a separation-of-duties action listed twice is a config error.

A second re-verification confirmed all of those and found more, also fixed with tests:

- Approval policies are evaluated as each agent of a sub-agent chain (a parent's policy requiring strong approval applied only to the parent); `authorize_async` takes `resolved=`.
- The HTTP middleware has a token mode (`audience=`: Bearer token, `verify_token`, `authorize` with the token's resolution); header mode, which trusts `X-Agent-Name`/`X-User-Name`, is documented as trusted-gateway only.
- Separation of duties holds under concurrency (one lock around check and record) and normalises user names.
- Actions with control, invisible or look-alike characters are refused; chains are limited to 16 agents; the user's roles are looked up once per resolution, not once per delegation; reasons name the parent agent for inherited denials and grants.

A final red-team pass found the core held (resolution, attenuation, tokens, identity separation) and broke two integration paths, now fixed with tests:

- The token-mode middleware used the full URL (caller-controlled host and query string) as the resource, so resource-based approval policies never fired and separation of duties could be split with `?x=1`: it now uses the request path, or `resource=` supplied by the application.
- The guardrails adapter built a bare engine from the config (no code limits, no user roles, separate separation-of-duties state) and attributed user-less events to a user called `system` (and that account's delegations): it now accepts the application's `AuthEngine`, and an event without a user is a service request.
- Approval conditions and A2A deny policies (agents and action) ignore case; request scopes containing wildcards are refused; sessions, delegations and the audit log never share a file when the audit path is custom (they used to overwrite each other).

A re-check of the integration paths confirmed those fixes (token-mode middleware, Flask decorator, guardrails adapter, 150 concurrent separation-of-duties races) and found more, also fixed with tests:

- The guardrails adapter checked a `tool_call` event as the action `tool_call`, never the tool: denials, limits and approval policies on tool names did not apply to tool calls from guardrails' LangChain and OpenAI Agents adapters. It now checks `data["tool_name"]` (or `data["action"]`; an event whose two differ is denied), denies a tool call without a tool name and non-string fields. Also in 0.1.x.
- The guardrails adapter passed the event type (`input`, `tool_call`...) as the agent-auth scope: an agent with `scopes:` was denied every event, and an event with an empty type skipped scope checks. The scope now comes from the application: `evaluate(event, user, scope=...)`.
- A sub-agent escaped its parent's approval policy by changing the action's case (`db:DROP`); A2A deny conditions now ignore case like their patterns.
- The FastAPI middleware decides `HEAD` as `get` (HEAD runs the GET handler, so a denial on `get:/admin*` did not cover it).

A re-verification of those fixes confirmed all five and found more, also fixed with tests:

- An event whose tool name and action differ is denied (one action per event): checking both could leave a separation-of-duties record for an action that was refused.
- Restriction conditions (approval, A2A deny) ignore case on both sides: a mixed-case literal (`action == "deleteUser"`) missed `DELETEUSER`.
- Actions with a character whose upper case folds differently (dotless `ı`: `drop_ındex` escaped a `drop_index` limit, while `upper()` makes it `DROP_INDEX`) are refused.
- The docs warn that the HTTP middleware does not see WebSocket connections, and that the guardrails adapter decides a sub-agent on its own resolution.

A further re-verification confirmed those and found more, also fixed with tests:

- Evaluating a restriction in two uniform passes (as written, all folded) let a request split spellings: `db:DROP` on `Scratch` escaped `action == "db:drop" and resource != "scratch"`, and a `!=` against a mixed-case literal denied the value it names. Each comparison is now read as written or folded, whichever makes the restriction apply (flipped under `not`); a randomized test checks it never drops what the condition as written applies.
- Denial and limit patterns, A2A deny patterns and separation-of-duties actions match the action as written or case-folded: folding alone let `db:drop_ß` escape `db:drop_?` and `cfg:ADMIN` escape `cfg:[!a-z]*` (denied in 0.1.4).
- Deeply nested metadata no longer raises `RecursionError`; restriction checks fold the request once per decision (200 A2A deny policies: 0.8 ms).
- Scopes, delegations and allow patterns match exactly on every platform (`fnmatch.fnmatch` ignored case on Windows).

A last re-verification confirmed those against a brute-force reference (80,000 random conditions) and found one more gap, fixed with tests:

- `DB:DROP_ß` still escaped `db:drop_?` (neither the written nor the folded reading matched): deny patterns now also try the lower- and upper-cased action; a test checks every cased Unicode character.
- A restriction whose condition raises an error as written now always applies (fail closed); long `and`/`or` chains no longer exhaust the recursion limit when the engine is built.

A final round found the same gap with two special characters together (`DB:DROP_ßİ` escaped `db:drop_??`). Deny patterns also match character by character ignoring case (`re.IGNORECASE`), which closes the class (no inconsistency in 300,000 random combinations of every cased character) and makes `İ` an `i` (`DB:DROP_İNDEX` is a `db:drop_index`). Long chains inside a single comparison no longer exhaust the recursion limit.

The last round found nothing exploitable. Its remaining notes are closed too: actions with a case-unstable character (one that case mapping splits or merges, such as `ß`, `ẞ`, `İ`; about 88 characters) are refused, since a `?` in a pattern counts characters and two spellings of the same action could get different verdicts; a target agent name is validated like an action (surrounding spaces, invisible characters); the compiled-pattern cache is no longer capped at 1,024 patterns.

### Deprecated

- `user_permissions_provider` union (an agent may do anything its user may do): emits a `FutureWarning` naming the agent, action and user the first time it decides each (agent, action) pair. Use `grants`; set `resolution: {user_permissions: ignore}` to turn it off now. Removed in 1.0.
- Approval tiers keep working; new code should prefer theaios-guardrails flow control proposals.

### Compatibility

Every 0.1 config loads and decides as before (all 0.1 tests pass unchanged); new keys are optional. Two adapter changes can deny what 0.1 allowed: the guardrails adapter checks tool calls as their tool (an agent allowed `tool_call` needs the tools), and the FastAPI middleware checks `HEAD` as `get`.

## [0.1.4] - 2026-11-11

### Security

- A delegation applied to every request of the agent, whoever it acted for: after Bob delegated `send_report` to `assistant`, the assistant could `send_report` on behalf of Alice too. A delegation now applies only to requests from the user who granted it. `DelegationManager.check` takes an optional `user` (the engine always passes it).

## [0.1.3] - 2026-11-09

### Security

- An approval or A2A condition that named an undefined `$variable` (a typo such as `$protectd`) passed validation and was then silently skipped at every evaluation: an action that needed approval ran autonomously, and an A2A deny policy never denied. Such configs are now rejected when they load, with a "did you mean" suggestion. **If your config stops loading after upgrading, it had a policy that never applied.**
- Conditions using `matches` are rejected too: agent-auth defines no matchers, so they always failed. The operator table no longer lists it.
- A condition that cannot be evaluated now fails closed: an approval policy applies its tier, an A2A deny policy denies, and an A2A allow policy grants nothing.

- Mistakes in a config's structure no longer load silently. Each of these used to be accepted and change what the config does. They are now rejected, by name and with a suggestion where one exists:
  - `approval_policies` written as a mapping loaded zero policies, so deletes that needed strong approval ran autonomously; any list section in the wrong shape is now an error;
  - unknown keys everywhere: an A2A policy with guardrails-style `from:`/`to:` became a wildcard `allow` that overrode `default: deny`; `conditon:` made a policy match every action; `profils:` loaded zero profiles;
  - values of the wrong type: `condition: 42`, `enabled: "false"` in quotes, a string where a list or integer is expected.
- `AuthEngine(...)` built from an `AuthConfig` in code now runs the same validation as `load_config` and raises `ConfigError`.
- Request `metadata` could overwrite the fields an approval policy checks: `metadata={"resource": "/tmp"}` on a delete of `/ledger/main` made `resource == $protected` false, so the delete ran autonomously. The request's own fields (`agent`, `user`, `action`, `resource`, `scope`) now always win.
- `metadata.key` in a condition, as shown in docs/expressions.md, never matched (metadata keys were only reachable at the top level), so `metadata.amount > $cap` never required approval. Both forms now work, in approval and A2A conditions.
- `==`, `!=`, `in` and `not in` treat `"1001"` and `1001` as equal (theaios-core 0.1.1).
- String values that spell numbers now compare as numbers in conditions (`"10000" > 5000`), and comparing a number with a non-number fails closed (theaios-core 0.1.1).

### Fixed

- `approval_policy` on a decision named the first policy with the same tier, which could be one that did not match; it now names the policy that set the tier, and the reason names it too. When that policy's condition could not be evaluated, the reason says so.
- `agent-auth check`, `inspect`, `sessions`, `delegations` and `audit` printed text in square brackets as terminal markup, so names and conditions could disappear; all text is now shown verbatim.
- Unknown-key suggestions: `when:` suggests `condition`, guardrails-style `from:`/`to:` suggest `from_agent`/`to_agent`.
- YAML syntax errors, a directory or a non-UTF-8 file passed as the config raise `ConfigError` with the file and line instead of a Python traceback.
- README quick start: it now says to gate execution on `is_autonomous`. An action that needs approval is `allowed=True` with `requires_approval=True`; a copy of the old example would have run it without asking.
- The docs called theaios-guardrails "TrustGate"; they are different libraries.

### Changed

- Requires theaios-core 0.1.1 or later.

## [0.1.2] - 2026-11-09

### Changed

- The expression engine, `${VAR}` interpolation and the audit log writer now come from [theaios-core](https://github.com/Cohorte-ai/theaios-core), a new dependency shared by the theaios libraries. The four libraries carried identical copies of the engine; it now lives in one place. Existing configs, imports (`theaios.agent_auth.expressions` still works) and audit files are unchanged.

### Fixed

- Expressions longer than 10,000 characters or nested deeper than 64 levels now raise `ExpressionError` instead of crashing with a Python `RecursionError`. Long `and` / `or` chains no longer hit the recursion limit.

## [0.1.1] - 2026-09-10

### Changed

- CI toolchain pinned to verified versions (ruff 0.15.x, mypy 1.19.x, pytest <10)
- README badges aligned with the theaios suite; docs social icon fixed

---

## [0.1.0] - 2026-03-29

### Added

- **Core authorization engine** (`AuthEngine`) with 8-step evaluation pipeline: session validation, profile resolution, deny check, allow check, delegation check, user permissions, A2A evaluation, approval policy evaluation.
- **YAML-driven configuration** (`agent_auth.yaml`) with validation, environment variable interpolation (`${ENV_VAR}`), and schema enforcement via typed dataclasses.
- **Role-based access control** with single-parent inheritance via `extends` — circular inheritance is detected and rejected.
- **Agent profiles** — assign a role, add extra `allow` actions, `deny` specific actions (deny overrides all), scope to resource patterns via `fnmatch`.
- **Three-tier approval model** — `autonomous`, `soft`, `strong` — with condition-based policy matching and escalation (most restrictive tier wins when multiple policies match).
- **Safe expression language** — custom DSL for policy conditions with operators (`==`, `!=`, `starts_with`, `ends_with`, `contains`, `in`, `not in`, `matches`, `and`, `or`, `not`), field access, variables (`$var`), lists. No `eval()`, no arbitrary code execution.
- **Sessions** — time-limited authorization contexts with UUID4 IDs, create/validate/revoke lifecycle, JSONL persistence, configurable duration in seconds.
- **Delegation** — temporary permission grants from users to agents, constrained by `max_duration`, delegation rules with `allowed_actions`, `require_reason`, revocable, JSONL persistence.
- **Agent-to-agent (A2A) authorization** — policy-based control over inter-agent interactions using `A2AEvaluator`, fnmatch wildcard support, configurable default (allow/deny), condition expressions, deny overrides allow.
- **Audit logging** — JSONL format via `AuditLog` class, append-only writes, filtered reads (by agent, user, action, timestamp), clear operation.
- **CLI** (`agent-auth`) with commands: `version`, `validate`, `inspect`, `check` (with `-o json`), `sessions` (`--create`/`--list`/`--revoke`), `delegate`, `delegations` (`--list`/`--revoke`), `audit` (with filters and JSON export). Config specified via `-c` on the group.
- **Guardrails adapter** (`GuardrailsAuthAdapter`) — wraps `AuthConfig` + guardrails `Engine`, runs authorization before guardrails evaluation, returns deny/require_approval/allow decisions.
- **User permissions provider** — optional callback or `UserPermissionsProvider` protocol to integrate with external IAM systems.
- **Async support** — `engine.authorize_async()` and `adapter.evaluate_async()` for async frameworks.
- **Type system** — dataclasses (`AuthRequest`, `AuthDecision`, `Session`, `DelegationGrant`, `RoleConfig`, `AgentProfileConfig`, `ApprovalPolicyConfig`, `AuthConfig`, etc.) with enums (`ApprovalTier`, `A2ADefault`, `SessionStatus`, `DelegationStatus`) and validation constants.
- **Rich console reporting** — colored terminal output for auth decisions, config summaries, session/delegation lists, audit summaries.
- **Full test suite** — unit tests for types, config, roles, profiles, sessions, delegation, approval, A2A, audit, engine; adapter tests; end-to-end integration tests.
- **Documentation** — MkDocs Material site with concept guides, complete YAML reference, CLI reference, API reference, expression syntax, integration guide.
- **Example configs** — minimal and enterprise YAML policies.
- **Example scripts** — quickstart, delegation, A2A, session lifecycle.
- **End-to-end test guide** — 20-step manual verification walkthrough for macOS, Linux, and Windows.

[0.1.0]: https://github.com/Cohorte-ai/agent-auth/releases/tag/v0.1.0
