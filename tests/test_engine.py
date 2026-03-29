"""Tests for AuthEngine — full authorization pipeline."""

from __future__ import annotations

from pathlib import Path

import pytest

from theaios.agent_auth.config import load_config
from theaios.agent_auth.engine import AuthEngine
from theaios.agent_auth.types import AuthDecision, AuthRequest


class TestAuthEngineBasic:
    """AuthEngine(config) with basic_yaml fixture."""

    @pytest.fixture(autouse=True)
    def _setup(self, basic_yaml: Path, tmp_dir: Path) -> None:
        config = load_config(str(basic_yaml))
        # Override audit path to use tmp_dir to avoid polluting the filesystem
        config.audit.path = str(tmp_dir / ".agent_auth" / "audit.jsonl")
        self.engine = AuthEngine(config)

    def test_allow_permitted_action(self) -> None:
        req = AuthRequest(agent="assistant", user="alice", action="read")
        decision = self.engine.authorize(req)
        assert decision.allowed is True

    def test_deny_action_not_in_profile(self) -> None:
        req = AuthRequest(agent="assistant", user="alice", action="admin")
        decision = self.engine.authorize(req)
        assert decision.allowed is False
        assert decision.is_denied is True

    def test_deny_by_profile_deny_list(self) -> None:
        # assistant has deny=["delete"]
        req = AuthRequest(agent="assistant", user="alice", action="delete")
        decision = self.engine.authorize(req)
        assert decision.allowed is False

    def test_evaluation_time_set(self) -> None:
        req = AuthRequest(agent="assistant", user="alice", action="read")
        decision = self.engine.authorize(req)
        assert decision.evaluation_time_ms >= 0.0

    def test_reason_on_deny(self) -> None:
        req = AuthRequest(agent="assistant", user="alice", action="admin")
        decision = self.engine.authorize(req)
        assert decision.reason != ""

    def test_unknown_agent_denied(self) -> None:
        req = AuthRequest(agent="ghost", user="alice", action="read")
        decision = self.engine.authorize(req)
        assert decision.allowed is False

    def test_scope_check(self) -> None:
        req = AuthRequest(agent="assistant", user="alice", action="read", scope="admin:panel")
        decision = self.engine.authorize(req)
        # assistant scopes are project:*, so admin:panel is denied
        assert decision.allowed is False


class TestAuthEngineA2A:
    """A2A authorization through the engine."""

    @pytest.fixture(autouse=True)
    def _setup(self, basic_yaml: Path, tmp_dir: Path) -> None:
        config = load_config(str(basic_yaml))
        config.audit.path = str(tmp_dir / ".agent_auth" / "audit.jsonl")
        self.engine = AuthEngine(config)

    def test_a2a_allowed(self) -> None:
        req = AuthRequest(agent="assistant", user="system", action="read", target_agent="reviewer")
        decision = self.engine.authorize(req)
        assert decision.allowed is True

    def test_a2a_denied_by_default(self) -> None:
        req = AuthRequest(agent="assistant", user="system", action="write", target_agent="unknown")
        decision = self.engine.authorize(req)
        assert decision.allowed is False


class TestAuthEngineSessions:
    """Session-gated authorization."""

    @pytest.fixture(autouse=True)
    def _setup(self, basic_yaml: Path, tmp_dir: Path) -> None:
        config = load_config(str(basic_yaml))
        config.audit.path = str(tmp_dir / ".agent_auth" / "audit.jsonl")
        self.engine = AuthEngine(config)

    def test_create_session(self) -> None:
        sess = self.engine.create_session("assistant", "alice", "project:*")
        assert sess.session_id is not None
        assert sess.agent == "assistant"

    def test_authorize_with_valid_session(self) -> None:
        sess = self.engine.create_session("assistant", "alice", "project:*")
        req = AuthRequest(
            agent="assistant",
            user="alice",
            action="read",
            session_id=sess.session_id,
        )
        decision = self.engine.authorize(req)
        assert decision.allowed is True

    def test_invalid_session_denied(self) -> None:
        req = AuthRequest(
            agent="assistant",
            user="alice",
            action="read",
            session_id="nonexistent-session",
        )
        decision = self.engine.authorize(req)
        assert decision.allowed is False

    def test_revoke_session(self) -> None:
        sess = self.engine.create_session("assistant", "alice", "project:*")
        result = self.engine.revoke_session(sess.session_id)
        assert result is True

    def test_session_agent_mismatch_denied(self) -> None:
        sess = self.engine.create_session("assistant", "alice", "project:*")
        req = AuthRequest(
            agent="other_agent",
            user="alice",
            action="read",
            session_id=sess.session_id,
        )
        decision = self.engine.authorize(req)
        assert decision.allowed is False


class TestAuthEngineDelegation:
    """Delegation through the engine."""

    @pytest.fixture(autouse=True)
    def _setup(self, basic_yaml: Path, tmp_dir: Path) -> None:
        config = load_config(str(basic_yaml))
        config.audit.path = str(tmp_dir / ".agent_auth" / "audit.jsonl")
        self.engine = AuthEngine(config)

    def test_create_delegation(self) -> None:
        grant = self.engine.create_delegation("alice", "assistant", ["deploy"], 3600, "test")
        assert grant.delegation_id is not None
        assert grant.from_user == "alice"

    def test_delegated_action_allowed(self) -> None:
        # "deploy" is not in assistant's normal profile, but delegation grants it
        self.engine.create_delegation("alice", "assistant", ["deploy"], 3600, "test")
        req = AuthRequest(agent="assistant", user="alice", action="deploy")
        decision = self.engine.authorize(req)
        assert isinstance(decision, AuthDecision)
        assert decision.allowed is True

    def test_revoke_delegation(self) -> None:
        grant = self.engine.create_delegation("alice", "assistant", ["read"], 3600, "temp")
        result = self.engine.revoke_delegation(grant.delegation_id)
        assert result is True


class TestAuthEngineUserPermissions:
    """Engine with user_permissions_provider callback."""

    def test_user_permissions_provider_called(self, basic_yaml: Path, tmp_dir: Path) -> None:
        config = load_config(str(basic_yaml))
        config.audit.path = str(tmp_dir / ".agent_auth" / "audit.jsonl")

        def provider(user: str) -> set[str]:
            if user == "alice":
                return {"read", "write", "deploy"}
            return set()

        engine = AuthEngine(config, user_permissions_provider=provider)
        req = AuthRequest(agent="assistant", user="alice", action="read")
        decision = engine.authorize(req)
        assert isinstance(decision, AuthDecision)
        assert decision.allowed is True
