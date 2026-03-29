"""Agent-to-Agent (A2A) authorization example.

Demonstrates:
- One agent requesting action on behalf of another
- A2A rules: allow, deny, and default behavior

Usage:
    python examples/a2a_example.py
"""
from __future__ import annotations

from pathlib import Path

from theaios.agent_auth.config import load_config
from theaios.agent_auth.engine import AuthEngine
from theaios.agent_auth.types import AuthRequest


def main() -> None:
    config_path = Path(__file__).parent / "policies" / "enterprise.yaml"
    config = load_config(str(config_path))
    engine = AuthEngine(config)

    print("=== Agent-to-Agent Authorization ===\n")

    # 1. Copilot -> Code Reviewer (read): should be ALLOWED
    req1 = AuthRequest(
        agent="copilot",
        user="system",
        action="read",
        target_agent="code-reviewer",
    )
    d1 = engine.authorize(req1)
    print(f"copilot -> code-reviewer (read): allowed={d1.allowed}")

    # 2. Copilot -> Deploy Bot (deploy): should be DENIED
    req2 = AuthRequest(
        agent="copilot",
        user="system",
        action="deploy",
        target_agent="deploy-bot",
    )
    d2 = engine.authorize(req2)
    print(f"copilot -> deploy-bot (deploy):  allowed={d2.allowed}")

    # 3. Admin Bot -> Any Agent (any action): should be ALLOWED
    req3 = AuthRequest(
        agent="admin-bot",
        user="system",
        action="manage",
        target_agent="copilot",
    )
    d3 = engine.authorize(req3)
    print(f"admin-bot -> copilot (manage):   allowed={d3.allowed}")

    # 4. Unknown -> Unknown: should use default (deny)
    req4 = AuthRequest(
        agent="rogue-bot",
        user="system",
        action="read",
        target_agent="copilot",
    )
    d4 = engine.authorize(req4)
    print(f"rogue-bot -> copilot (read):     allowed={d4.allowed}")


if __name__ == "__main__":
    main()
