"""HTTP middleware stubs for FastAPI and Flask integration.

These are reference implementations showing how to integrate agent-auth
into web frameworks. Copy and adapt to your application.

Two modes:

- **Token** (recommended, 0.2): pass ``audience=``. The caller sends
  ``Authorization: Bearer <token>`` issued by ``engine.issue_token`` for that audience; the
  middleware verifies it and decides with ``engine.authorize(..., resolved=...)``, so the
  caller's identity, sub-agent chain, approval tiers, scopes and separation of duties all apply.
- **Headers** (0.1, no ``audience``): the agent and user come from ``X-Agent-Name`` and
  ``X-User-Name``. **Anyone who can reach the service can claim any agent and any user**: use
  this mode only behind a gateway that authenticates the caller and sets those headers itself.

The ``resource`` of each decision is the request **path** (never the host or the query string,
which the caller controls). Pass ``resource=`` (a function of the request) to use your own
resource identifier, for example the invoice id, so that approval policies and separation of
duties see the business object rather than a route.

FastAPI example::

    from fastapi import FastAPI, Request, HTTPException
    from theaios.agent_auth.adapters.middleware import fastapi_auth_middleware
    from theaios.agent_auth.config import load_config
    from theaios.agent_auth.engine import AuthEngine

    app = FastAPI()
    config = load_config("agent_auth.yaml")
    engine = AuthEngine(config)

    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        return await fastapi_auth_middleware(engine, request, call_next)

Flask example::

    from flask import Flask, request, jsonify
    from theaios.agent_auth.adapters.middleware import flask_auth_decorator
    from theaios.agent_auth.config import load_config
    from theaios.agent_auth.engine import AuthEngine

    app = Flask(__name__)
    config = load_config("agent_auth.yaml")
    engine = AuthEngine(config)
    require_auth = flask_auth_decorator(engine)

    @app.route("/api/action")
    @require_auth(action="perform_action")
    def action_endpoint():
        return jsonify({"status": "ok"})
"""

from __future__ import annotations

from typing import Any, Callable

from theaios.agent_auth.engine import AuthEngine
from theaios.agent_auth.tokens import TokenError
from theaios.agent_auth.types import AuthDecision, AuthRequest


def _decide(
    engine: AuthEngine,
    headers: Any,
    action: str,
    resource: str,
    audience: str | None,
    agent_header: str,
    user_header: str,
    session_header: str,
) -> tuple[int, dict[str, object]] | None:
    """``None`` to proceed, or ``(status, body)`` to answer with."""
    if audience is not None:
        auth = str(headers.get("Authorization", ""))
        if not auth.startswith("Bearer "):
            return 401, {"error": "a Bearer token is required"}
        try:
            verified = engine.verify_token(auth[len("Bearer ") :], audience)
        except TokenError as exc:
            return 401, {"error": "invalid token", "reason": str(exc)}
        claims = verified.claims
        decision = engine.authorize(
            AuthRequest(
                agent=claims.agent,
                user=claims.user,
                action=action,
                resource=resource,
                identity=claims.identity,
            ),
            resolved=verified.resolved,
        )
    else:
        agent = str(headers.get(agent_header, ""))
        user = str(headers.get(user_header, ""))
        if not agent or not user:
            return 400, {"error": f"{agent_header} and {user_header} headers are required"}
        decision = engine.authorize(
            AuthRequest(
                agent=agent,
                user=user,
                action=action,
                resource=resource,
                session_id=headers.get(session_header),
            )
        )
    return _answer(decision)


def _answer(decision: AuthDecision) -> tuple[int, dict[str, object]] | None:
    if decision.is_denied:
        return 403, {"error": "Authorization denied", "reason": decision.reason}
    if decision.requires_approval:
        return 403, {
            "error": "Approval required",
            "tier": decision.tier,
            "reason": decision.reason,
            "approval_policy": decision.approval_policy,
        }
    return None


async def fastapi_auth_middleware(
    engine: AuthEngine,
    request: Any,
    call_next: Callable[..., Any],
    audience: str | None = None,
    resource: Callable[[Any], str] | None = None,
) -> Any:
    """FastAPI middleware that checks agent-auth before processing requests.

    Extracts agent, user, and action from request headers:
    - X-Agent-Name: agent identifier
    - X-User-Name: user identifier
    - X-Session-Id: optional session ID

    The action is derived from the request method + path.

    Parameters
    ----------
    engine : AuthEngine
        Initialized auth engine.
    request : Request
        FastAPI request object.
    call_next : callable
        Next middleware/handler in the chain.

    Returns
    -------
    Response
        The response from the next handler, or a 403 JSON error.
    """
    # Import here to avoid hard dependency on FastAPI
    try:
        from starlette.responses import JSONResponse
    except ImportError as e:
        raise ImportError(
            "FastAPI/Starlette is required for this middleware. "
            "Install it with: pip install fastapi"
        ) from e

    import asyncio

    # HEAD runs the GET handler: decide it as GET, so a rule on get:<path> covers it.
    method = "get" if request.method.upper() == "HEAD" else request.method.lower()
    action = f"{method}:{request.url.path}"
    answer = await asyncio.to_thread(
        _decide,
        engine,
        request.headers,
        action,
        resource(request) if resource else request.url.path,
        audience,
        "X-Agent-Name",
        "X-User-Name",
        "X-Session-Id",
    )
    if answer is not None:
        return JSONResponse(status_code=answer[0], content=answer[1])

    response = await call_next(request)
    return response


def flask_auth_decorator(
    engine: AuthEngine,
    agent_header: str = "X-Agent-Name",
    user_header: str = "X-User-Name",
    session_header: str = "X-Session-Id",
    audience: str | None = None,
    resource: Callable[[Any], str] | None = None,
) -> Callable[..., Callable[..., Any]]:
    """Create a Flask decorator factory for agent-auth checks.

    Parameters
    ----------
    engine : AuthEngine
        Initialized auth engine.
    agent_header : str
        Header name for agent identifier.
    user_header : str
        Header name for user identifier.
    session_header : str
        Header name for session ID.

    Returns
    -------
    callable
        A decorator factory: ``@require_auth(action="do_thing")``.
    """
    import functools

    def decorator_factory(action: str) -> Callable[..., Any]:
        def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
            @functools.wraps(f)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                # Import here to avoid hard dependency on Flask
                try:
                    from flask import jsonify, request
                except ImportError as e:
                    raise ImportError(
                        "Flask is required for this decorator. Install it with: pip install flask"
                    ) from e

                answer = _decide(
                    engine,
                    request.headers,
                    action,
                    resource(request) if resource else request.path,
                    audience,
                    agent_header,
                    user_header,
                    session_header,
                )
                if answer is not None:
                    return jsonify(answer[1]), answer[0]

                return f(*args, **kwargs)

            return wrapper

        return decorator

    return decorator_factory
