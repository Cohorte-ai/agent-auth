# Integration Guide

Using agent-auth with guardrails, HTTP middleware, and custom systems. For LangChain 1.x and
Deep Agents, see [LangChain agents](langchain-agent.md).

---

## Guardrails adapter

The `GuardrailsAuthAdapter` integrates `agent-auth` with [theaios-guardrails](https://github.com/Cohorte-ai/guardrails). It runs authorization **before** the guardrails evaluation, ensuring that only permitted agents can invoke guardrail-protected operations.

### Installation

```bash
pip install "theaios-agent-auth[guardrails]"
```

### Usage

```python
from theaios.agent_auth.adapters.guardrails import GuardrailsAuthAdapter
from theaios.agent_auth.config import load_config as load_auth_config
from theaios.guardrails.config import load_policy
from theaios.guardrails.engine import Engine

auth_engine = AuthEngine(load_auth_config("agent_auth.yaml"), user_roles=..., limits=...)
policy = load_policy("guardrails.yaml")

adapter = GuardrailsAuthAdapter(
    auth_config=auth_engine,          # your engine: its limits, roles and state apply
    guardrails_engine=Engine(policy),
)

# This checks auth first, then evaluates guardrails
decision = adapter.evaluate(event, user="alice")
decision = adapter.evaluate(event)    # no user: a service request (the agent's baseline only)
```

Pass your application's `AuthEngine`, not just its config: given a config, the adapter builds a
bare engine of its own, without your code limits, `user_roles` or separation-of-duties state.
Since 0.2, an event without a user is a service request; 0.1 attributed it to a user called
`system` (and that account's delegations). Set `default_user=` to name one explicitly.

### How it works

```
GuardEvent
  |
  v
GuardrailsAuthAdapter.evaluate(event, user)
  |
  v
AuthEngine.authorize(request)  -->  AuthDecision
  |
  v
If denied: return deny Decision (skip guardrails)
If requires_approval: return require_approval Decision
If allowed: run guardrails_engine.evaluate(event)
```

The adapter:

1. Extracts agent identity, action, resource, session, and target agent from the `GuardEvent`
2. Builds an `AuthRequest` and calls `AuthEngine.authorize()`
3. If auth is denied, returns a guardrails `Decision(outcome="deny")` without running guardrails
4. If auth requires approval, returns `Decision(outcome="require_approval")`
5. If auth passes, delegates to the guardrails engine

**Which action is checked.** For a `tool_call` event, the tool: `data["tool_name"]`, as
guardrails' LangChain and OpenAI Agents adapters send it. For an event with `data["action"]`,
that action. An event whose `tool_name` and `action` differ is denied (one action per event).
Other events (`input`, `output`) are checked as their type, as in 0.1.
A `tool_call` without `tool_name`, or a non-string `tool_name`, `action` or `resource`, is
denied. Since 0.2 a tool call is checked as its tool: an agent that was allowed `tool_call` in
0.1 now needs the tools themselves in its profile.

**Scope.** The event's `scope` is its type (`input`, `tool_call`...), not an agent-auth scope.
Pass the request's scope yourself: `adapter.evaluate(event, user="alice", scope="project:acme")`.
Without one, scope checks are skipped, as for any request without a scope.

**Sub-agents.** The adapter decides each event on the agent's own resolution: it does not know
the chain a sub-agent was delegated through. For sub-agents, call
`engine.authorize(request, resolved=child)` yourself (see [resolution](resolution.md)).

**What the adapter trusts.** The agent, session and target agent come from the event as your
code builds it; the tool name, action and resource may come from the model and are checked.

---

## HTTP middleware

For web applications and API servers, `agent-auth` can be used as HTTP middleware to gate incoming requests.

!!! warning "HTTP only"
    `@app.middleware("http")` never sees WebSocket connections. Check WebSocket endpoints
    yourself (verify the token and call `authorize` in the handler).

!!! warning "Who is calling?"
    The pattern below takes the agent and user from request headers. Anyone who can reach the
    service can then claim any agent and any user: use it only behind a gateway that
    authenticates the caller and sets those headers itself. Otherwise use **token mode**
    (0.2): the shipped `fastapi_auth_middleware(engine, request, call_next, audience="...")`
    and `flask_auth_decorator(engine, audience="...")` require `Authorization: Bearer <token>`
    (from `engine.issue_token`), verify it, and decide with the token's resolution, so the
    caller's identity, sub-agent chain, approval tiers and separation of duties apply. The
    decision's `resource` is the request path (never the caller-controlled host or query);
    pass `resource=` (a function of the request) to use your business identifier, such as the
    invoice id. The middleware passes no scope.
    See [Resolution](resolution.md#tokens-for-tool-servers).

### Installation

```bash
pip install "theaios-agent-auth[middleware]"
```

### Pattern

```python
from theaios.agent_auth.config import load_config
from theaios.agent_auth.engine import AuthEngine
from theaios.agent_auth.types import AuthRequest

config = load_config("agent_auth.yaml")
engine = AuthEngine(config)


async def auth_middleware(request, call_next):
    """Extract agent identity from headers and authorize."""
    agent = request.headers.get("X-Agent-Name", "")
    user = request.headers.get("X-User-Id", "")
    session_id = request.headers.get("X-Session-Id")

    auth_request = AuthRequest(
        agent=agent,
        user=user,
        action=request_method_to_action(request.method),
        resource=request.url.path,
        session_id=session_id,
    )

    decision = engine.authorize(auth_request)

    if decision.is_denied:
        return JSONResponse(
            status_code=403,
            content={"error": "Forbidden", "reason": decision.reason},
        )

    if decision.requires_approval:
        return JSONResponse(
            status_code=202,
            content={
                "status": "approval_required",
                "tier": decision.tier,
                "policy": decision.approval_policy,
            },
        )

    response = await call_next(request)
    return response


def request_method_to_action(method: str) -> str:
    return {
        "GET": "read",
        "POST": "write",
        "PUT": "update",
        "PATCH": "update",
        "DELETE": "delete",
    }.get(method.upper(), "unknown")
```

---

## Custom integration

For any system, the integration pattern is:

1. **Load config** once at startup
2. **Create engine** once
3. **Build AuthRequest** from your system's context
4. **Call `engine.authorize()`** and act on the `AuthDecision`

```python
from theaios.agent_auth.config import load_config
from theaios.agent_auth.engine import AuthEngine
from theaios.agent_auth.types import AuthRequest, AuthDecision

config = load_config("agent_auth.yaml")
engine = AuthEngine(config)

def authorize_agent_action(
    agent: str, user: str, action: str, resource: str = ""
) -> AuthDecision:
    request = AuthRequest(agent=agent, user=user, action=action, resource=resource)
    return engine.authorize(request)
```

---

## User permissions provider

!!! warning "Deprecated in 0.2"
    `user_permissions_provider` lets an agent do anything its user may do, beyond the agent's
    own profile. In 0.2, give the engine the user's roles (`user_roles=`) and declare per agent
    what each role unlocks (`grants:`); see [Resolution](resolution.md). The provider still
    works, with a warning naming the agent, action and user the first time it decides each
    (agent, action) pair;
    `resolution: {user_permissions: ignore}` turns it off. It is removed in 1.0.

By default, `agent-auth` does not check user-level permissions — it focuses on agent authorization. To integrate with an existing IAM system, provide a `user_permissions_provider` callback:

```python
def get_user_permissions(user: str) -> set[str]:
    """Fetch user permissions from your IAM system."""
    return {"read", "write", "deploy"}

engine = AuthEngine(config, user_permissions_provider=get_user_permissions)
```

The callback can also implement the `UserPermissionsProvider` protocol:

```python
class MyProvider:
    def get_user_actions(self, user: str) -> set[str]:
        return db.get_permissions(user)

engine = AuthEngine(config, user_permissions_provider=MyProvider())
```

When provided, user permissions are checked at step 6 of the pipeline — if the agent's profile and delegations don't cover the action, the engine checks if the user has the permission.
