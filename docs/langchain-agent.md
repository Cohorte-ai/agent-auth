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
    checkpointer=InMemorySaver(),
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
| approval policy matches | does not run | an error `ToolMessage` pointing to guardrails | continues |

A denial's decision is in the `ToolMessage`'s `artifact["theaios"]`, with its provenance
(`limit:payments:*`, `deny:...`; empty when nothing granted the action), and is not sent to
the model.

## Who is who

- **User**: `runtime.context.user_id` (or `context["user_id"]`), or `user=lambda request: ...`.
  No user means a **service** run: the agent's baseline only, no grants, no delegations.
- **Agent**: `AgentAuthMiddleware(engine, agent="...")`, or the graph's name.
- **Resource and scope**: `resource=lambda request: request.tool_call["args"].get("invoice")`,
  `scope=...`. They feed separation of duties, scopes and approval conditions. Read them from
  the arguments only when the model choosing them is acceptable; without `resource`, separation
  of duties treats every call as the same resource (stricter).

The model chooses the tool and its arguments; it never chooses the user or the agent.

## Approvals

agent-auth decides who may do what; it does not pause agents for a person. When an approval
policy matches, the call is refused, and the reason says so. In agents, approvals go through
theaios-guardrails' `FlowMiddleware`: frozen arguments, decided once, executed once, durable
across restarts. Write the condition as a guardrails rule:

```yaml
rules:
  - name: drop-needs-approval
    scope: tool_call
    when: tool_name == "db:drop"
    then: require_approval
    tier: strong
```

The separation-of-duties record of an allowed call is kept only if the call really ran: when
a check inside this middleware refuses it, or the run pauses before it ran, the record is
released, so it cannot block the user's next legitimate action.

## Sub-agents (Deep Agents)

Deep Agents does not pass the main agent's middleware to its sub-agents. Give each sub-agent
its own, with `delegated_by`, so it decides with the parent's attenuated resolution: a
sub-agent never gets more than the agent that handed it the work, for the same user. A
sub-agent's middleware without `delegated_by` refuses every call.

```python
subagents = [{"name": "researcher", "description": "...", "tools": [web_search],
              "middleware": [AgentAuthMiddleware(engine, delegated_by="assistant")]}]
agent = create_deep_agent(model, tools, subagents=subagents, context_schema=Ctx,
                          middleware=[AgentAuthMiddleware(engine)], name="assistant")
```

**A sub-agent of a sub-agent** lists every agent above it, outermost first, so it is
attenuated through all of them: `AgentAuthMiddleware(engine, delegated_by=["assistant",
"researcher"])` for `helper`, handed work by `researcher`, itself handed work by `assistant`.
Every hop needs its A2A allow.

**Hand-offs are authorized.** A `task` call is authorized as the action `task` (grant it to the
agent) *and* as a hand-off to the sub-agent it names: the sub-agent needs a profile and an A2A
allow (`a2a: {policies: [{from_agent: assistant, to_agent: researcher, effect: allow}]}`).
Deep Agents adds a `general-purpose` sub-agent with all the main agent's tools; without a
profile and an A2A allow it cannot be reached. If you allow it, give it the middlewares like
any other sub-agent.

Deep Agents' built-in tools (`ls`, `read_file`, `write_file`, `edit_file`, `delete`, `glob`,
`grep`, `task`, `execute`) are authorized like any tool: grant the ones the agent needs.

## With guardrails and agent-monitor

```python
middleware=[MonitorMiddleware(monitor), AgentAuthMiddleware(engine), FlowMiddleware(guard)]
```

The first in the list is the outermost: the monitor sees every outcome, authorization decides
who may call the tool, flow control decides whether the session may call it now and asks a
person last, so nobody approves a call authorization would refuse.
