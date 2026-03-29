"""Quick-start example: load config, create session, authorize, print decision.

Usage:
    python examples/quickstart.py
"""
from __future__ import annotations

from pathlib import Path

from theaios.agent_auth.config import load_config
from theaios.agent_auth.engine import AuthEngine
from theaios.agent_auth.types import AuthRequest


def main() -> None:
    # 1. Load the auth configuration
    config_path = Path(__file__).parent / "policies" / "minimal.yaml"
    config = load_config(str(config_path))
    print(f"Loaded config: {config.metadata.name}")

    # 2. Create the auth engine
    engine = AuthEngine(config)

    # 3. Create a session for the agent
    session = engine.create_session(
        agent="assistant",
        user="alice",
        scope="project:acme",
    )
    print(f"Session created: {session.session_id}")

    # 4. Build an authorization request
    request = AuthRequest(
        agent="assistant",
        user="alice",
        action="read",
        resource="/projects/acme",
        session_id=session.session_id,
    )

    # 5. Authorize
    decision = engine.authorize(request)

    # 6. Print the result
    print(f"\nAuthorization Decision:")
    print(f"  Allowed:           {decision.allowed}")
    print(f"  Tier:              {decision.tier}")
    print(f"  Requires Approval: {decision.requires_approval}")
    print(f"  Reason:            {decision.reason or '(none)'}")
    print(f"  Is Autonomous:     {decision.is_autonomous}")
    print(f"  Is Denied:         {decision.is_denied}")
    print(f"  Evaluation Time:   {decision.evaluation_time_ms:.2f} ms")

    # 7. Try a denied action (delete triggers strong approval)
    denied_request = AuthRequest(
        agent="assistant",
        user="alice",
        action="admin_action",
        resource="/projects/acme",
    )
    denied_decision = engine.authorize(denied_request)
    print(f"\nAdmin action request:")
    print(f"  Allowed:           {denied_decision.allowed}")
    print(f"  Is Denied:         {denied_decision.is_denied}")
    print(f"  Reason:            {denied_decision.reason}")


if __name__ == "__main__":
    main()
