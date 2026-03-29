"""Delegation example: grant temporary permissions to an agent.

Demonstrates:
- Creating a delegation grant
- Authorizing with delegated permissions
- Revoking a delegation

Usage:
    python examples/delegation_example.py
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

    print("=== Delegation Example ===\n")

    # 1. Try to use an action the agent doesn't have (deploy is not in editor role)
    req = AuthRequest(agent="assistant", user="alice", action="deploy")
    decision = engine.authorize(req)
    print(f"Deploy without delegation: allowed={decision.allowed}")
    print(f"  Reason: {decision.reason}")

    # 2. Alice delegates "deploy" to the assistant for 1 hour (3600 seconds)
    grant = engine.create_delegation(
        from_user="alice",
        to_agent="assistant",
        actions=["deploy"],
        duration=3600,
        reason="One-off deployment",
    )
    print(f"\nDelegation created: {grant.delegation_id}")
    print(f"  From:    {grant.from_user}")
    print(f"  To:      {grant.to_agent}")
    print(f"  Actions: {grant.actions}")
    print(f"  Expires: {grant.expires_at}")

    # 3. Try again with delegation in place
    decision2 = engine.authorize(req)
    print(f"\nDeploy with delegation: allowed={decision2.allowed}")
    print(f"  Reason: {decision2.reason}")

    # 4. Revoke the delegation
    revoked = engine.revoke_delegation(grant.delegation_id)
    print(f"\nDelegation revoked: {revoked}")

    # 5. Try once more after revocation
    decision3 = engine.authorize(req)
    print(f"Deploy after revocation: allowed={decision3.allowed}")


if __name__ == "__main__":
    main()
