# Changelog

All notable changes to `theaios-agent-auth` will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
