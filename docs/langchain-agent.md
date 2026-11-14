# LangChain agents (middleware)

For agents built with LangChain 1.x `create_agent` or with Deep Agents, authorization runs as
middleware: every tool call the model makes is authorized, as the agent, for the user the run
is for, before it runs.

```bash
pip install "theaios-agent-auth[langchain-agent]"
```

```python
from dataclasses import dataclass
from langchain.agents import create_agent
from langgraph.checkpoint.memory import InMemorySaver
from theaios.agent_auth import AuthEngine, load_config
from theaios.agent_auth.adapters.langchain_agent import AgentAuthMiddleware

engine = AuthEngine(load_config("agent_auth.yaml"), user_roles=idp.roles_of,
                    limits={"*": ["payments:*"]})

@dataclass
class Ctx:
    user_id: str | None    # who the run is for; None = a service run

agent = create_agent(
    "openai:gpt-4.1-mini", tools=[read_docs, approve_invoice],
    middleware=[AgentAuthMiddleware(engine)],
    context_schema=Ctx,
    checkpointer=InMemorySaver(),   # needed only if an approval policy can pause the run
    name="assistant",               # the agent profile this graph runs as
)
agent.invoke({"messages": [...]}, {"configurable": {"thread_id": "t1"}}, context=Ctx("alice"))
```

The action authorized is the **tool name**: profiles, grants, limits and approval policies are
written in tool names.

## What happens to each tool call

| Decision | The tool | The model sees | The run |
|---|---|---|---|
| allowed | runs | the result | continues |
| denied | does not run | an error `ToolMessage` with the reason | continues |
| approval policy matches | does not run yet | nothing yet | pauses (`interrupt`) |

A denial's decision is in the `ToolMessage`'s `artifact["theaios"]`, with its provenance
(`grant:finance:approve_invoice`, `limit:payments:*`...), and is not sent to the model.

## Who is who

- **User**: `runtime.context.user_id` (or `context["user_id"]`), or `user=lambda request: ...`.
  No user means a **service** run: the agent's baseline only, no grants, no delegations.
- **Agent**: `AgentAuthMiddleware(engine, agent="...")`, or the graph's name.
- **Resource and scope**: `resource=lambda request: request.tool_call["args"].get("invoice")`,
  `scope=...`. They feed separation of duties, scopes and approval conditions. Read them from
  the arguments only when the model choosing them is acceptable; without `resource`, separation
  of duties treats every call as the same resource (stricter).

The model chooses the tool and its arguments; it never chooses the user or the agent.

## Approving

An approval policy pauses the run with one interrupt:

```python
out = agent.invoke(..., version="v2")
ask = out.interrupts[0].value
# {"type": "theaios.approval", "component": "agent-auth", "proposal_id": "aa-...",
#  "agent": "assistant", "user": "alice", "tool": "db:drop", "args": {...},
#  "tier": "strong", "reasons": [...]}
agent.invoke(Command(resume={"proposal_id": ask["proposal_id"], "approve": True, "by": "carol"}),
             config, context=Ctx("alice"), version="v2")
```

The decision must name the proposal, say who decided, and `approve` must be `True` or `False`.
Anything else is refused and the tool does not run. Nothing is recorded (audit log,
separation of duties) until the call really runs, and the call is authorized again when it
does: if a role or a policy changed while it waited, it is refused.

For approvals with a durable record (frozen arguments, decided once, executed once, survives
restarts), use theaios-guardrails' `FlowMiddleware`.

## Sub-agents (Deep Agents)

Deep Agents does not pass the main agent's middleware to its sub-agents. Give each sub-agent
its own, with `delegated_by`, so it decides with the parent's attenuated resolution: a
sub-agent never gets more than the agent that handed it the work, for the same user.

```python
subagents = [{"name": "researcher", "description": "...", "tools": [web_search],
              "middleware": [AgentAuthMiddleware(engine, delegated_by="assistant")]}]
agent = create_deep_agent(model, tools, subagents=subagents, context_schema=Ctx,
                          middleware=[AgentAuthMiddleware(engine)], name="assistant")
```

The hand-off needs an A2A allow (`a2a: {policies: [{from_agent: assistant, to_agent:
researcher, effect: allow}]}`); without it the sub-agent may do nothing.

## With guardrails and agent-monitor

```python
middleware=[MonitorMiddleware(monitor), AgentAuthMiddleware(engine), FlowMiddleware(guard)]
```

The first in the list is the outermost: the monitor sees every outcome, authorization decides
who may call the tool, flow control decides whether the session may call it now.
