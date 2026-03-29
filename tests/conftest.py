"""Shared fixtures for theaios-agent-auth test suite."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from theaios.agent_auth.types import (
    A2AConfig,
    A2APolicyConfig,
    AgentProfileConfig,
    ApprovalPolicyConfig,
    AuditConfig,
    AuthConfig,
    AuthMetadata,
    AuthRequest,
    DelegationConfig,
    RoleConfig,
    SessionConfig,
)


# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_dir(tmp_path: Path) -> Path:
    """Return a clean temporary directory for each test."""
    return tmp_path


# ---------------------------------------------------------------------------
# Config object (no disk I/O)
# ---------------------------------------------------------------------------


@pytest.fixture()
def basic_config() -> AuthConfig:
    """Return a minimal but complete AuthConfig object.

    Includes:
    - Two roles: viewer (read), editor (inherits viewer + write)
    - One profile: assistant (role=editor, deny=[delete], scopes=[project:*])
    - One approval policy: destructive (condition matches action=="delete", tier=strong)
    """
    return AuthConfig(
        version="1.0",
        metadata=AuthMetadata(
            name="test-config",
            description="Config used by test suite",
        ),
        variables={"env": "test"},
        roles={
            "viewer": RoleConfig(name="viewer", actions=["read"]),
            "editor": RoleConfig(name="editor", actions=["write"], extends="viewer"),
        },
        profiles={
            "assistant": AgentProfileConfig(
                name="assistant",
                role="editor",
                allow=[],
                deny=["delete"],
                scopes=["project:*"],
                default_tier="autonomous",
            ),
        },
        approval_policies=[
            ApprovalPolicyConfig(
                name="destructive",
                condition='action == "delete"',
                tier="strong",
            ),
        ],
        delegation=DelegationConfig(
            enabled=True,
            default_duration=3600,
            max_duration=86400,
            rules=[],
        ),
        a2a=A2AConfig(
            default="deny",
            policies=[
                A2APolicyConfig(
                    name="assistant-to-reviewer",
                    from_agent="assistant",
                    to_agent="reviewer",
                    action="read",
                    effect="allow",
                ),
            ],
        ),
        sessions=SessionConfig(
            default_duration=3600,
            max_duration=86400,
        ),
        audit=AuditConfig(
            enabled=True,
            path=".agent_auth/audit.jsonl",
        ),
    )


# ---------------------------------------------------------------------------
# YAML on disk
# ---------------------------------------------------------------------------


@pytest.fixture()
def basic_yaml(tmp_dir: Path) -> Path:
    """Write a valid agent_auth.yaml and return its path."""
    cfg_dict = {
        "version": "1.0",
        "metadata": {
            "name": "test-config",
            "description": "Config used by test suite",
        },
        "variables": {"env": "test"},
        "roles": {
            "viewer": {"actions": ["read"]},
            "editor": {"actions": ["write"], "extends": "viewer"},
        },
        "profiles": {
            "assistant": {
                "role": "editor",
                "allow": [],
                "deny": ["delete"],
                "scopes": ["project:*"],
                "default_tier": "autonomous",
            },
        },
        "approval_policies": [
            {
                "name": "destructive",
                "condition": 'action == "delete"',
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
            ],
        },
        "sessions": {
            "default_duration": 3600,
            "max_duration": 86400,
        },
        "audit": {
            "enabled": True,
            "path": str(tmp_dir / ".agent_auth" / "audit.jsonl"),
        },
    }
    yaml_path = tmp_dir / "agent_auth.yaml"
    yaml_path.write_text(yaml.dump(cfg_dict, default_flow_style=False))
    return yaml_path


# ---------------------------------------------------------------------------
# Sample request
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_request() -> AuthRequest:
    """Return a simple AuthRequest for testing."""
    return AuthRequest(
        agent="assistant",
        user="alice",
        action="read",
        resource="/projects/acme",
    )
