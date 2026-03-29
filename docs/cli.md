# CLI Reference

All `agent-auth` commands. The config file is specified with `-c` on the group.

---

## Global option

| Option | Description |
|---|---|
| `-c`, `--config` | Path to `agent_auth.yaml`. Default: `agent_auth.yaml`. |

The `-c` flag goes **before** the subcommand:

```bash
agent-auth -c agent_auth.yaml <command> [options]
```

---

## `version`

Print the installed version.

```bash
agent-auth version
```

No config file required.

---

## `validate`

Validate the config file — checks syntax, schema, role references, tier values, and A2A defaults.

```bash
agent-auth -c agent_auth.yaml validate
```

Exit code 0 on success, non-zero on error with details printed to stderr.

---

## `inspect`

Pretty-print a summary of the loaded config: roles, profiles, policies, A2A rules, session settings.

```bash
agent-auth -c agent_auth.yaml inspect
```

---

## `check`

Evaluate an authorization request and print the decision.

```bash
agent-auth -c agent_auth.yaml check \
    --agent <AGENT> \
    --user <USER> \
    --action <ACTION> \
    [--resource <RESOURCE>] \
    [--scope <SCOPE>] \
    [--target-agent <TARGET_AGENT>] \
    [--output console|json]
```

### Options

| Option | Required | Description |
|---|---|---|
| `--agent`, `-a` | Yes | Agent name |
| `--user`, `-u` | Yes | User name |
| `--action` | Yes | Action to check |
| `--resource`, `-r` | No | Resource path |
| `--scope`, `-s` | No | Scope |
| `--target-agent` | No | Target agent for A2A check |
| `--output`, `-o` | No | Output format: `console` (default) or `json` |

### Examples

```bash
# Basic permission check
agent-auth -c agent_auth.yaml check --agent assistant --user alice --action read

# With resource
agent-auth -c agent_auth.yaml check --agent assistant --user alice --action read -r /projects/acme

# A2A check
agent-auth -c agent_auth.yaml check --agent copilot --user system --action read --target-agent reviewer

# JSON output
agent-auth -c agent_auth.yaml check --agent assistant --user alice --action read -o json
```

### Exit codes

- `0`: allowed
- `1`: denied

---

## `sessions`

Manage sessions. Use flags to specify the operation.

### Create a session

```bash
agent-auth -c agent_auth.yaml sessions --create \
    --agent <AGENT> \
    --user <USER> \
    [--scope <SCOPE>] \
    [--duration <SECONDS>]
```

### List active sessions

```bash
agent-auth -c agent_auth.yaml sessions --list \
    [--agent <AGENT>] \
    [--user <USER>]
```

### Revoke a session

```bash
agent-auth -c agent_auth.yaml sessions --revoke <SESSION_ID>
```

---

## `delegate`

Create a delegation grant.

```bash
agent-auth -c agent_auth.yaml delegate \
    --from-user <USER> \
    --to-agent <AGENT> \
    --actions <ACTION1,ACTION2,...> \
    [--duration <SECONDS>] \
    [--reason <REASON>]
```

| Option | Required | Description |
|---|---|---|
| `--from-user` | Yes | User granting the delegation |
| `--to-agent` | Yes | Agent receiving the permissions |
| `--actions` | Yes | Comma-separated list of actions |
| `--duration`, `-d` | No | Duration in seconds |
| `--reason` | No | Why the delegation is being created |

### Example

```bash
agent-auth -c agent_auth.yaml delegate \
    --from-user alice \
    --to-agent assistant \
    --actions read,write \
    --duration 7200 \
    --reason "Sprint review access"
```

---

## `delegations`

Manage delegations. Use flags to specify the operation.

### List active delegations

```bash
agent-auth -c agent_auth.yaml delegations --list \
    [--agent <AGENT>]
```

### Revoke a delegation

```bash
agent-auth -c agent_auth.yaml delegations --revoke <DELEGATION_ID>
```

---

## `audit`

View the audit log.

```bash
agent-auth -c agent_auth.yaml audit \
    [--since <ISO_TIMESTAMP>] \
    [--agent <AGENT>] \
    [--user <USER>] \
    [--action <ACTION>] \
    [--limit <N>] \
    [--output console|json] \
    [--output-file <PATH>]
```

Prints recent authorization decisions from the JSONL audit log.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success (or allowed for `check`) |
| `1` | Error or denied |
| `2` | Usage error (missing required option) |
