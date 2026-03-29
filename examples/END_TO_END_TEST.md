# End-to-End Test Guide

Manual verification of every `agent-auth` feature — from installation to audit log inspection.

Works on **macOS**, **Linux**, and **Windows** (PowerShell).

---

## Prerequisites

- Python 3.10+
- A terminal (bash/zsh on macOS/Linux, PowerShell on Windows)

---

## Step 1: Install from source

```bash
# macOS / Linux
git clone https://github.com/Cohorte-ai/agent-auth.git
cd agent-auth
pip install -e ".[dev]"
```

```powershell
# Windows (PowerShell)
git clone https://github.com/Cohorte-ai/agent-auth.git
cd agent-auth
pip install -e ".[dev]"
```

## Step 2: Verify installation

```bash
agent-auth version
```

Expected: version number (e.g. `agent-auth 0.1.0`).

## Step 3: Create a test config

Copy the minimal example:

```bash
cp examples/policies/minimal.yaml agent_auth.yaml
```

## Step 4: Validate the config

```bash
agent-auth -c agent_auth.yaml validate
```

Expected: `Config is valid: 2 roles, 1 profiles, 1 approval policies, 0 A2A policies`.

## Step 5: Inspect the config

```bash
agent-auth -c agent_auth.yaml inspect
```

Expected: pretty-printed summary of roles, profiles, policies.

## Step 6: Check — allow a read

```bash
agent-auth -c agent_auth.yaml check --agent assistant --user alice --action read
```

Expected: `ALLOWED` — the assistant has `read` via the editor role.

## Step 7: Check — deny an unknown action

```bash
agent-auth -c agent_auth.yaml check --agent assistant --user alice --action admin
```

Expected: `DENIED` — the `admin` action is not in the editor role.

## Step 8: Check with JSON output

```bash
agent-auth -c agent_auth.yaml check --agent assistant --user alice --action read -o json
```

Expected: JSON object with `allowed`, `tier`, `reason`, etc.

## Step 9: Check with resource

```bash
agent-auth -c agent_auth.yaml check --agent assistant --user alice --action read --resource /projects/acme
```

Expected: `ALLOWED`.

## Step 10: Use the enterprise config

```bash
cp examples/policies/enterprise.yaml agent_auth.yaml
```

## Step 11: Check A2A — allowed

```bash
agent-auth -c agent_auth.yaml check --agent copilot --user system --action read --target-agent code-reviewer
```

Expected: `ALLOWED` — the A2A rule permits copilot to read from code-reviewer.

## Step 12: Check A2A — denied

```bash
agent-auth -c agent_auth.yaml check --agent copilot --user system --action deploy --target-agent deploy-bot
```

Expected: `DENIED` — the A2A rule explicitly denies this.

## Step 13: Create a session

```bash
agent-auth -c agent_auth.yaml sessions --create --agent copilot --user alice --scope "project:acme"
```

Expected: prints session ID and details.

## Step 14: List sessions

```bash
agent-auth -c agent_auth.yaml sessions --list
```

Expected: table showing the session from step 13.

## Step 15: Create a delegation

```bash
agent-auth -c agent_auth.yaml delegate --from-user alice --to-agent copilot --actions read,write --duration 3600 --reason "Sprint review"
```

Expected: prints delegation ID and details.

## Step 16: List delegations

```bash
agent-auth -c agent_auth.yaml delegations --list
```

Expected: table showing the delegation from step 15.

## Step 17: Revoke the delegation

```bash
agent-auth -c agent_auth.yaml delegations --revoke <DELEGATION_ID>
```

Replace `<DELEGATION_ID>` with the ID from step 15. Expected: `Delegation <ID> revoked`.

## Step 18: View audit log

```bash
agent-auth -c agent_auth.yaml audit
```

Expected: recent authorization decisions in chronological order.

## Step 19: Run the test suite

```bash
pytest tests/ -v
```

Expected: all tests pass.

## Step 20: Run the quick-start example

```bash
python examples/quickstart.py
```

Expected: prints authorization decisions showing allowed read and denied admin action.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `command not found: agent-auth` | Run `pip install -e ".[dev]"` again |
| `FileNotFoundError` on config | Ensure `agent_auth.yaml` exists in the working directory |
| Tests fail with import errors | Ensure you installed with `pip install -e ".[dev]"` |
| Permission denied on `.agent_auth/` | Check directory write permissions |

---

## Platform Notes

### Windows (PowerShell)

All commands work the same except:
- Use `copy` instead of `cp`
- Use `\` in paths or quote them: `"examples\policies\minimal.yaml"`

### macOS / Linux

No special notes. All commands work as shown.
