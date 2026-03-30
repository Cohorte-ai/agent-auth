"""End-to-end integration tests — load YAML, authorize, sessions, delegation, A2A, audit."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from theaios.agent_auth.audit import AuditLog
from theaios.agent_auth.config import load_config
from theaios.agent_auth.engine import AuthEngine
from theaios.agent_auth.types import AuthRequest


@pytest.fixture()
def full_config_yaml(tmp_path: Path) -> Path:
    """Write a comprehensive agent_auth.yaml for E2E testing."""
    audit_path = str(tmp_path / ".agent_auth" / "audit.jsonl")
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
                "deny": ["delete"],
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
            "path": audit_path,
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
        assert decision.evaluation_time_ms > 0

    def test_deny_unknown_agent(self, full_config_yaml: Path) -> None:
        """Unknown agent profile is denied."""
        config = load_config(str(full_config_yaml))
        engine = AuthEngine(config)

        req = AuthRequest(agent="unknown-bot", user="alice", action="read")
        decision = engine.authorize(req)
        assert decision.allowed is False
        assert "not authorized" in decision.reason

    def test_deny_by_profile_deny_list(self, full_config_yaml: Path) -> None:
        """Action explicitly denied in profile deny list is rejected."""
        config = load_config(str(full_config_yaml))
        engine = AuthEngine(config)

        req = AuthRequest(agent="assistant", user="alice", action="delete")
        decision = engine.authorize(req)
        assert decision.allowed is False
        assert "denied by profile" in decision.reason

    def test_scope_enforcement(self, full_config_yaml: Path) -> None:
        """Request with a scope outside profile scopes is denied."""
        config = load_config(str(full_config_yaml))
        engine = AuthEngine(config)

        # Matching scope passes
        req_ok = AuthRequest(agent="assistant", user="alice", action="read", scope="project:alpha")
        assert engine.authorize(req_ok).allowed is True

        # Non-matching scope is denied
        req_bad = AuthRequest(agent="assistant", user="alice", action="read", scope="billing:123")
        decision = engine.authorize(req_bad)
        assert decision.allowed is False
        assert "Scope" in decision.reason

    def test_session_lifecycle(self, full_config_yaml: Path) -> None:
        """Create session, authorize with it, revoke, verify denied after revoke."""
        config = load_config(str(full_config_yaml))
        engine = AuthEngine(config)

        # Create session
        sess = engine.create_session("assistant", "alice", "project:*")
        assert sess.session_id is not None
        assert sess.status == "active"

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

        # Authorization with revoked session must be denied
        decision_after = engine.authorize(req)
        assert decision_after.allowed is False
        assert "Invalid or expired session" in decision_after.reason

    def test_session_agent_mismatch(self, full_config_yaml: Path) -> None:
        """Using a session with the wrong agent is denied."""
        config = load_config(str(full_config_yaml))
        engine = AuthEngine(config)

        sess = engine.create_session("assistant", "alice")
        req = AuthRequest(
            agent="deployer",
            user="alice",
            action="read",
            session_id=sess.session_id,
        )
        decision = engine.authorize(req)
        assert decision.allowed is False
        assert "mismatch" in decision.reason

    def test_delegation_lifecycle(self, full_config_yaml: Path) -> None:
        """Create delegation, authorize with it, revoke, verify denied after revoke."""
        config = load_config(str(full_config_yaml))
        engine = AuthEngine(config)

        # reviewer profile only has "read" — it cannot "write" without delegation
        req = AuthRequest(agent="reviewer", user="alice", action="write")
        assert engine.authorize(req).allowed is False

        # Delegate "write" to reviewer
        grant = engine.create_delegation("alice", "reviewer", ["write"], 3600, "temp write access")
        assert grant.delegation_id is not None
        assert grant.status == "active"

        # Now reviewer can write via delegation
        decision = engine.authorize(req)
        assert decision.allowed is True
        assert "Delegated" in decision.reason

        # Revoke delegation
        assert engine.revoke_delegation(grant.delegation_id) is True

        # Reviewer can no longer write
        decision_after = engine.authorize(req)
        assert decision_after.allowed is False

    def test_a2a_authorization(self, full_config_yaml: Path) -> None:
        """Inter-agent authorization: allowed and denied paths."""
        config = load_config(str(full_config_yaml))
        engine = AuthEngine(config)

        # Allowed: assistant -> reviewer (read)
        req_allow = AuthRequest(
            agent="assistant", user="system", action="read", target_agent="reviewer"
        )
        assert engine.authorize(req_allow).allowed is True

        # Denied: assistant -> deployer (deploy) — no matching rule, default=deny
        req_deny = AuthRequest(
            agent="assistant", user="system", action="deploy", target_agent="deployer"
        )
        decision = engine.authorize(req_deny)
        assert decision.allowed is False

        # Allowed: deployer -> * (deploy) via wildcard rule
        req_wildcard = AuthRequest(
            agent="deployer", user="system", action="deploy", target_agent="assistant"
        )
        decision_wc = engine.authorize(req_wildcard)
        assert decision_wc.allowed is True

    def test_approval_policy_triggered(self, full_config_yaml: Path) -> None:
        """Destructive action triggers approval requirement."""
        config = load_config(str(full_config_yaml))
        engine = AuthEngine(config)

        req = AuthRequest(agent="deployer", user="alice", action="deploy")
        decision = engine.authorize(req)
        assert decision.allowed is True
        assert decision.requires_approval is True
        assert decision.tier == "strong"
        assert decision.approval_policy == "destructive"

    def test_non_destructive_action_is_autonomous(self, full_config_yaml: Path) -> None:
        """Non-destructive action is allowed without approval."""
        config = load_config(str(full_config_yaml))
        engine = AuthEngine(config)

        req = AuthRequest(agent="assistant", user="alice", action="read")
        decision = engine.authorize(req)
        assert decision.allowed is True
        assert decision.requires_approval is False
        assert decision.tier == "autonomous"

    def test_role_inheritance_through_engine(self, full_config_yaml: Path) -> None:
        """Editor inherits viewer's 'read', admin inherits editor's 'write' + viewer's 'read'."""
        config = load_config(str(full_config_yaml))
        engine = AuthEngine(config)

        # assistant (editor) should have inherited 'read' from viewer
        assert engine.authorize(AuthRequest(agent="assistant", user="a", action="read")).allowed
        assert engine.authorize(AuthRequest(agent="assistant", user="a", action="write")).allowed

        # deployer (admin) should have read + write + delete + deploy
        assert engine.authorize(AuthRequest(agent="deployer", user="a", action="read")).allowed
        assert engine.authorize(AuthRequest(agent="deployer", user="a", action="write")).allowed

    def test_audit_log_written(self, full_config_yaml: Path, tmp_path: Path) -> None:
        """Authorization decisions are written to the audit log and can be read back."""
        config = load_config(str(full_config_yaml))
        engine = AuthEngine(config)

        # Make some authorization requests
        engine.authorize(AuthRequest(agent="assistant", user="alice", action="read"))
        engine.authorize(AuthRequest(agent="assistant", user="alice", action="delete"))
        engine.authorize(AuthRequest(agent="deployer", user="bob", action="deploy"))

        # Read audit log back
        audit_path = str(tmp_path / ".agent_auth" / "audit.jsonl")
        log = AuditLog(path=audit_path)
        entries = log.read()

        assert len(entries) == 3

        # First entry: allowed read
        assert entries[0]["agent"] == "assistant"
        assert entries[0]["action"] == "read"
        assert entries[0]["allowed"] is True

        # Second entry: denied delete
        assert entries[1]["agent"] == "assistant"
        assert entries[1]["action"] == "delete"
        assert entries[1]["allowed"] is False

        # Third entry: allowed deploy (with approval)
        assert entries[2]["agent"] == "deployer"
        assert entries[2]["action"] == "deploy"
        assert entries[2]["allowed"] is True
        assert entries[2]["requires_approval"] is True

    def test_audit_log_filter_by_agent(self, full_config_yaml: Path, tmp_path: Path) -> None:
        """Audit log can be filtered by agent name."""
        config = load_config(str(full_config_yaml))
        engine = AuthEngine(config)

        engine.authorize(AuthRequest(agent="assistant", user="alice", action="read"))
        engine.authorize(AuthRequest(agent="deployer", user="bob", action="deploy"))
        engine.authorize(AuthRequest(agent="assistant", user="alice", action="write"))

        audit_path = str(tmp_path / ".agent_auth" / "audit.jsonl")
        log = AuditLog(path=audit_path)
        assistant_entries = log.read(agent="assistant")
        assert len(assistant_entries) == 2
        assert all(e["agent"] == "assistant" for e in assistant_entries)

    def test_user_permissions_provider(self, full_config_yaml: Path) -> None:
        """External user permissions provider grants actions to unknown agents."""
        config = load_config(str(full_config_yaml))

        def user_perms(user: str) -> set[str]:
            if user == "superadmin":
                return {"read", "write", "delete", "deploy"}
            return set()

        engine = AuthEngine(config, user_permissions_provider=user_perms)

        # Unknown agent + superadmin user → allowed via user permissions
        req = AuthRequest(agent="unknown-bot", user="superadmin", action="read")
        decision = engine.authorize(req)
        assert decision.allowed is True
        assert "user permissions" in decision.reason

        # Unknown agent + normal user → denied
        req2 = AuthRequest(agent="unknown-bot", user="alice", action="read")
        assert engine.authorize(req2).allowed is False

    def test_full_pipeline_combined(self, full_config_yaml: Path, tmp_path: Path) -> None:
        """Combined test: session + delegation + a2a + approval + audit in one flow."""
        config = load_config(str(full_config_yaml))
        engine = AuthEngine(config)

        # 1. Create session for assistant
        sess = engine.create_session("assistant", "alice", "project:*")

        # 2. Authorize read with session — should succeed
        req = AuthRequest(
            agent="assistant",
            user="alice",
            action="read",
            session_id=sess.session_id,
            scope="project:alpha",
        )
        d1 = engine.authorize(req)
        assert d1.allowed is True

        # 3. Delegate "deploy" to reviewer
        engine.create_delegation("alice", "reviewer", ["deploy"], 3600, "deploy assist")

        # 4. Reviewer deploys via delegation — allowed but requires approval
        d2 = engine.authorize(AuthRequest(agent="reviewer", user="alice", action="deploy"))
        assert d2.allowed is True
        assert d2.requires_approval is True
        assert "Delegated" in d2.reason

        # 5. A2A: deployer -> assistant (deploy) via wildcard — allowed
        d3 = engine.authorize(
            AuthRequest(agent="deployer", user="system", action="deploy", target_agent="assistant")
        )
        assert d3.allowed is True

        # 6. Verify all events are in the audit log
        audit_path = str(tmp_path / ".agent_auth" / "audit.jsonl")
        log = AuditLog(path=audit_path)
        entries = log.read()
        assert len(entries) == 3
        assert entries[0]["session_id"] == sess.session_id
        assert entries[1]["requires_approval"] is True
