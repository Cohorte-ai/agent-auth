"""Session lifecycle example.

Demonstrates:
- Creating a scoped session
- Authorizing within session scope
- Revoking a session

Usage:
    python examples/session_example.py
"""
from __future__ import annotations

from pathlib import Path

from theaios.agent_auth.config import load_config
from theaios.agent_auth.engine import AuthEngine
from theaios.agent_auth.types import AuthRequest


def main() -> None:
    config_path = Path(__file__).parent / "policies" / "minimal.yaml"
    config = load_config(str(config_path))
    engine = AuthEngine(config)

    print("=== Session Lifecycle ===\n")

    # 1. Create a session scoped to project:acme
    session = engine.create_session(
        agent="assistant",
        user="alice",
        scope="project:acme",
    )
    print(f"Session created:")
    print(f"  ID:      {session.session_id}")
    print(f"  Agent:   {session.agent}")
    print(f"  User:    {session.user}")
    print(f"  Scope:   {session.scope}")
    print(f"  Status:  {session.status}")
    print(f"  Expires: {session.expires_at}")

    # 2. Authorize a request with the session
    req = AuthRequest(
        agent="assistant",
        user="alice",
        action="read",
        session_id=session.session_id,
    )
    decision = engine.authorize(req)
    print(f"\nRead with session: allowed={decision.allowed}")

    # 3. Revoke the session
    revoked = engine.revoke_session(session.session_id)
    print(f"\nSession revoked: {revoked}")

    # 4. Try to authorize with the revoked session
    decision_revoked = engine.authorize(req)
    print(f"Read after revocation: allowed={decision_revoked.allowed}")
    print(f"  Reason: {decision_revoked.reason}")


if __name__ == "__main__":
    main()
