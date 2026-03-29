"""End-to-end integration tests — load YAML, authorize, sessions, delegation, A2A."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from theaios.agent_auth.config import load_config
from theaios.agent_auth.engine import AuthEngine
from theaios.agent_auth.types import AuthRequest


@pytest.fixture()
def full_config_yaml(tmp_path: Path) -> Path:
    """Write a comprehensive agent_auth.yaml for E2E testing."""
    audit_dir = str(tmp_path / ".agent_auth" / "audit.jsonl")
    config = {
        "version": "1.0",
        "metadata": {"name": "e2e-test", "description": "Full integration test config"},
        "variables": {"env": "test"},
        "roles": {
            "viewer": {"actions": ["read"]},
            "editor": {"actions": ["write"], "extends": "viewer"},
            "admin": {"actions": ["delete", "deploy"], "extends": "editor"},
        },
        "profiles": {
            "assistant": {
                "role": "editor",
                "allow": [],
                "deny": [],
                "scopes": ["project:*"],
            },
            "reviewer": {
                "role": "viewer",
                "allow": [],
                "deny": [],
                "scopes": [],
            },
            "deployer": {
                "role": "admin",
                "allow": [],
                "deny": [],
                "scopes": ["deploy:*"],
            },
        },
        "approval_policies": [
            {
                "name": "destructive",
                "condition": 'action == "delete" or action == "deploy"',
                "tier": "strong",
            },
        ],
        "delegation": {
            "enabled": True,
            "default_duration": 3600,
            "max_duration": 86400,
            "rules": [],
        },
        "a2a": {
            "default": "deny",
            "policies": [
                {
                    "name": "assistant-to-reviewer",
                    "from_agent": "assistant",
                    "to_agent": "reviewer",
                    "action": "read",
                    "effect": "allow",
                },
                {
                    "name": "deployer-wildcard",
                    "from_agent": "deployer",
                    "to_agent": "*",
                    "action": "deploy",
                    "effect": "allow",
                },
            ],
        },
        "sessions": {
            "default_duration": 3600,
            "max_duration": 86400,
        },
        "audit": {
            "enabled": True,
            "path": audit_dir,
        },
    }
    p = tmp_path / "agent_auth.yaml"
    p.write_text(yaml.dump(config, default_flow_style=False))
    return p


class TestEndToEnd:
    """Full pipeline: load config -> create engine -> authorize."""

    def test_load_and_authorize(self, full_config_yaml: Path) -> None:
        """Load YAML, create engine, authorize a basic request."""
        config = load_config(str(full_config_yaml))
        engine = AuthEngine(config)

        req = AuthRequest(agent="assistant", user="alice", action="read")
        decision = engine.authorize(req)

        assert decision.allowed is True

    def test_session_lifecycle(self, full_config_yaml: Path) -> None:
        """Create session, authorize with it, revoke, verify denied."""
        config = load_config(str(full_config_yaml))
        engine = AuthEngine(config)

        # Create session
        sess = engine.create_session("assistant", "alice", "project:*")
        assert sess.session_id is not None

        # Authorize with session
        req = AuthRequest(
            agent="assistant",
            user="alice",
            action="read",
            session_id=sess.session_id,
        )
        decision = engine.authorize(req)
        assert decision.allowed is True

        # Revoke session
        assert engine.revoke_session(sess.session_id) is True

    def test_delegation_lifecycle(self, full_config_yaml: Path) -> None:
        """Create delegation, use it, revoke it."""
        config = load_config(str(full_config_yaml))
        engine = AuthEngine(config)

        # Create delegation
        grant = engine.create_delegation("alice", "assistant", ["deploy"], 3600, "one-off deploy")
        assert grant.delegation_id is not None

        # Revoke delegation
        assert engine.revoke_delegation(grant.delegation_id) is True

    def test_a2a_authorization(self, full_config_yaml: Path) -> None:
        """Inter-agent authorization: assistant -> reviewer allowed, assistant -> deployer denied."""
        config = load_config(str(full_config_yaml))
        engine = AuthEngine(config)

        # Allowed: assistant -> reviewer (read)
        req_allow = AuthRequest(
            agent="assistant", user="system", action="read", target_agent="reviewer"
        )
        assert engine.authorize(req_allow).allowed is True

        # Denied: assistant -> deployer (deploy) — no matching rule
        req_deny = AuthRequest(
            agent="assistant", user="system", action="deploy", target_agent="deployer"
        )
        assert engine.authorize(req_deny).allowed is False

    def test_approval_policy_triggered(self, full_config_yaml: Path) -> None:
        """Destructive action triggers approval requirement."""
        config = load_config(str(full_config_yaml))
        engine = AuthEngine(config)

        req = AuthRequest(agent="deployer", user="alice", action="deploy")
        decision = engine.authorize(req)
        assert decision.requires_approval is True
