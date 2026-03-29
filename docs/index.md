# theaios-agent-auth

**Agent-specific identity and access management for AI agents.**

---

## What is agent-auth?

When AI agents operate in enterprise environments, the question is no longer *"Can this user do X?"* but **"Can this agent, acting on behalf of this user, do X, right now, on this resource?"**

`agent-auth` answers that question. It is a lightweight, YAML-driven authorization engine purpose-built for AI agent systems. No cloud service. No vendor lock-in. Just a Python library and a CLI.

## Core capabilities

- **Role-based access control** with inheritance — define roles, compose them via `extends`
- **Agent profiles** with allow/deny overrides and scoped resources — constrain what each agent can touch
- **Three-tier approval model** — autonomous, soft, strong — so agents know when to act and when to ask
- **Sessions** — time-limited, scope-bound authorization contexts
- **Delegation** — temporary permission grants from users to agents
- **Agent-to-agent (A2A) authorization** — control which agents can invoke which
- **Audit logging** — every decision recorded in JSONL for compliance and debugging
- **CLI** — validate configs, check permissions, manage sessions and delegations from the terminal
- **Safe expression language** — custom DSL for policy conditions (no `eval()`, no arbitrary code)

## Quick links

| | |
|---|---|
| [Concepts](concepts.md) | How the auth pipeline works |
| [Config syntax](config-syntax.md) | Complete YAML reference |
| [CLI reference](cli.md) | All commands |
| [API reference](api-reference.md) | Python classes and methods |
| [Integration guide](integration.md) | Guardrails adapter, HTTP middleware |

## Installation

```bash
pip install theaios-agent-auth
```

With optional extras:

```bash
pip install "theaios-agent-auth[guardrails]"   # TrustGate adapter
pip install "theaios-agent-auth[middleware]"    # HTTP middleware
pip install "theaios-agent-auth[all]"           # Everything
```

## Ecosystem

`agent-auth` is part of the [theaios](https://theaios.xyz) platform:

| Package | Purpose |
|---|---|
| `theaios-guardrails` | Input/output guardrails (TrustGate) |
| `theaios-context-router` | Intelligent context routing |
| `theaios-agent-monitor` | Runtime observability |
| **`theaios-agent-auth`** | **Identity and access management** |
