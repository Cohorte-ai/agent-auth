# Changelog

All notable changes to `theaios-agent-auth` will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.5] - 2026-11-13

### Security

- The guardrails adapter checked a `tool_call` event as the action `tool_call`, never the tool: a profile's `deny` (and approval policies) on tool names did not apply to tool calls from guardrails' LangChain and OpenAI Agents adapters. It now checks `data["tool_name"]`, or `data["action"]` (an event whose two differ is denied). A `tool_call` without a tool name, and a non-string `tool_name`, `action` or `resource`, are denied (they were converted with `str()`). An agent allowed `tool_call` now needs the tools themselves in its profile.
- The FastAPI middleware decides `HEAD` as `get` (HEAD runs the GET handler, so a denial on `get:/admin*` did not cover it).

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
