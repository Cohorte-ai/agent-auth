"""Tests for session creation, validation, revocation, and expiry."""

from __future__ import annotations

import uuid
from pathlib import Path


from theaios.agent_auth.sessions import SessionManager


class TestSessionManager:
    """SessionManager manages create / validate / revoke lifecycle."""

    def _manager(self, tmp_dir: Path) -> SessionManager:
        return SessionManager(path=str(tmp_dir / ".agent_auth" / "sessions.jsonl"))

    def test_create_session(self, tmp_dir: Path) -> None:
        mgr = self._manager(tmp_dir)
        sess = mgr.create("assistant", "alice", "project:*", duration=3600)
        assert sess.agent == "assistant"
        assert sess.user == "alice"
        assert sess.scope == "project:*"
        assert sess.status == "active"
        assert sess.session_id  # non-empty

    def test_session_id_is_uuid4(self, tmp_dir: Path) -> None:
        mgr = self._manager(tmp_dir)
        sess = mgr.create("a", "u", "x")
        parsed = uuid.UUID(sess.session_id, version=4)
        assert str(parsed) == sess.session_id

    def test_validate_active_session(self, tmp_dir: Path) -> None:
        mgr = self._manager(tmp_dir)
        sess = mgr.create("a", "u", "x")
        result = mgr.validate(sess.session_id)
        assert result is not None
        assert result.session_id == sess.session_id

    def test_validate_unknown_session(self, tmp_dir: Path) -> None:
        mgr = self._manager(tmp_dir)
        assert mgr.validate("nonexistent-id") is None

    def test_revoke_session(self, tmp_dir: Path) -> None:
        mgr = self._manager(tmp_dir)
        sess = mgr.create("a", "u", "x")
        result = mgr.revoke(sess.session_id)
        assert result is True
        assert mgr.validate(sess.session_id) is None

    def test_revoke_nonexistent_returns_false(self, tmp_dir: Path) -> None:
        mgr = self._manager(tmp_dir)
        assert mgr.revoke("ghost-id") is False

    def test_expired_session_invalid(self, tmp_dir: Path) -> None:
        mgr = self._manager(tmp_dir)
        sess = mgr.create("a", "u", "x", duration=0)
        # With 0s duration the session expires immediately
        assert mgr.validate(sess.session_id) is None

    def test_list_active(self, tmp_dir: Path) -> None:
        mgr = self._manager(tmp_dir)
        mgr.create("a", "u1", "x")
        mgr.create("a", "u2", "y")
        sessions = mgr.list_active()
        assert len(sessions) >= 2

    def test_list_active_filter_by_agent(self, tmp_dir: Path) -> None:
        mgr = self._manager(tmp_dir)
        mgr.create("bot1", "u", "x")
        mgr.create("bot2", "u", "y")
        sessions = mgr.list_active(agent="bot1")
        assert all(s.agent == "bot1" for s in sessions)

    def test_persistence(self, tmp_dir: Path) -> None:
        path = str(tmp_dir / ".agent_auth" / "sessions.jsonl")
        mgr1 = SessionManager(path=path)
        sess = mgr1.create("a", "u", "x")
        # Create a new manager pointing to the same file
        mgr2 = SessionManager(path=path)
        result = mgr2.validate(sess.session_id)
        assert result is not None
