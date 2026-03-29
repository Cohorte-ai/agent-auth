"""Tests for delegation grants — create, check, revoke, expire, rules."""

from __future__ import annotations

from pathlib import Path

import pytest

from theaios.agent_auth.delegation import DelegationManager
from theaios.agent_auth.types import DelegationConfig


class TestDelegationManager:
    """DelegationManager handles temporary permission grants."""

    def _manager(self, tmp_dir: Path, **overrides: object) -> DelegationManager:
        config = DelegationConfig(
            enabled=True,
            default_duration=3600,
            max_duration=86400,
            rules=[],
        )
        for k, v in overrides.items():
            setattr(config, k, v)
        return DelegationManager(
            config=config,
            path=str(tmp_dir / ".agent_auth" / "delegations.jsonl"),
        )

    def test_create_delegation(self, tmp_dir: Path) -> None:
        mgr = self._manager(tmp_dir)
        grant = mgr.create("alice", "bot", ["read"], duration=3600, reason="temp access")
        assert grant.from_user == "alice"
        assert grant.to_agent == "bot"
        assert grant.actions == ["read"]
        assert grant.status == "active"
        assert grant.reason == "temp access"
        assert grant.delegation_id  # non-empty

    def test_check_active_delegation(self, tmp_dir: Path) -> None:
        mgr = self._manager(tmp_dir)
        mgr.create("alice", "bot", ["read"], duration=3600)
        result = mgr.check("bot", "read")
        assert result is not None

    def test_check_wrong_action(self, tmp_dir: Path) -> None:
        mgr = self._manager(tmp_dir)
        mgr.create("alice", "bot", ["read"], duration=3600)
        assert mgr.check("bot", "write") is None

    def test_check_wrong_agent(self, tmp_dir: Path) -> None:
        mgr = self._manager(tmp_dir)
        mgr.create("alice", "bot", ["read"], duration=3600)
        assert mgr.check("other_bot", "read") is None

    def test_revoke_delegation(self, tmp_dir: Path) -> None:
        mgr = self._manager(tmp_dir)
        grant = mgr.create("alice", "bot", ["read"], duration=3600)
        result = mgr.revoke(grant.delegation_id)
        assert result is True
        assert mgr.check("bot", "read") is None

    def test_revoke_nonexistent_returns_false(self, tmp_dir: Path) -> None:
        mgr = self._manager(tmp_dir)
        assert mgr.revoke("ghost-id") is False

    def test_expired_delegation_not_valid(self, tmp_dir: Path) -> None:
        mgr = self._manager(tmp_dir)
        mgr.create("alice", "bot", ["read"], duration=0)
        assert mgr.check("bot", "read") is None

    def test_exceeds_max_duration_raises(self, tmp_dir: Path) -> None:
        mgr = self._manager(tmp_dir, max_duration=3600)
        with pytest.raises(ValueError, match="[Dd]uration"):
            mgr.create("alice", "bot", ["read"], duration=86400)

    def test_disabled_delegation_raises(self, tmp_dir: Path) -> None:
        mgr = self._manager(tmp_dir, enabled=False)
        with pytest.raises(ValueError, match="[Dd]isabled"):
            mgr.create("alice", "bot", ["read"], duration=3600)

    def test_list_active(self, tmp_dir: Path) -> None:
        mgr = self._manager(tmp_dir)
        mgr.create("alice", "bot1", ["read"], duration=3600)
        mgr.create("bob", "bot2", ["write"], duration=3600)
        grants = mgr.list_active()
        assert len(grants) >= 2
