# Integration Guide

Using agent-auth with guardrails, HTTP middleware, and custom systems.

---

## Guardrails adapter

The `GuardrailsAuthAdapter` integrates `agent-auth` with [theaios-guardrails](https://github.com/Cohorte-ai/guardrails) (TrustGate). It runs authorization **before** the guardrails evaluation, ensuring that only permitted agents can invoke guardrail-protected operations.

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

auth_config = load_auth_config("agent_auth.yaml")
policy = load_policy("guardrails.yaml")

adapter = GuardrailsAuthAdapter(
    auth_config=auth_config,
    guardrails_engine=Engine(policy),
)

# This checks auth first, then evaluates guardrails
decision = adapter.evaluate(event, user="alice")
```

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

---

## HTTP middleware

For web applications and API servers, `agent-auth` can be used as HTTP middleware to gate incoming requests.

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
