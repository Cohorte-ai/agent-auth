"""HTTP middleware stubs for FastAPI and Flask integration.

These are reference implementations showing how to integrate agent-auth
into web frameworks. Copy and adapt to your application.

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
from theaios.agent_auth.types import AuthRequest


async def fastapi_auth_middleware(
    engine: AuthEngine,
    request: Any,
    call_next: Callable[..., Any],
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

    agent = request.headers.get("X-Agent-Name", "")
    user = request.headers.get("X-User-Name", "")
    session_id = request.headers.get("X-Session-Id")

    if not agent or not user:
        return JSONResponse(
            status_code=400,
            content={"error": "X-Agent-Name and X-User-Name headers are required"},
        )

    action = f"{request.method.lower()}:{request.url.path}"

    auth_request = AuthRequest(
        agent=agent,
        user=user,
        action=action,
        resource=str(request.url),
        session_id=session_id,
    )

    decision = await engine.authorize_async(auth_request)

    if decision.is_denied:
        return JSONResponse(
            status_code=403,
            content={
                "error": "Authorization denied",
                "reason": decision.reason,
            },
        )

    if decision.requires_approval:
        return JSONResponse(
            status_code=403,
            content={
                "error": "Approval required",
                "tier": decision.tier,
                "reason": decision.reason,
                "approval_policy": decision.approval_policy,
            },
        )

    response = await call_next(request)
    return response


def flask_auth_decorator(
    engine: AuthEngine,
    agent_header: str = "X-Agent-Name",
    user_header: str = "X-User-Name",
    session_header: str = "X-Session-Id",
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

                agent = request.headers.get(agent_header, "")
                user = request.headers.get(user_header, "")
                session_id = request.headers.get(session_header)

                if not agent or not user:
                    return (
                        jsonify(
                            {"error": f"{agent_header} and {user_header} headers are required"}
                        ),
                        400,
                    )

                auth_request = AuthRequest(
                    agent=agent,
                    user=user,
                    action=action,
                    resource=request.url,
                    session_id=session_id,
                )

                decision = engine.authorize(auth_request)

                if decision.is_denied:
                    return (
                        jsonify({"error": "Authorization denied", "reason": decision.reason}),
                        403,
                    )

                if decision.requires_approval:
                    return (
                        jsonify(
                            {
                                "error": "Approval required",
                                "tier": decision.tier,
                                "reason": decision.reason,
                                "approval_policy": decision.approval_policy,
                            }
                        ),
                        403,
                    )

                return f(*args, **kwargs)

            return wrapper

        return decorator

    return decorator_factory
