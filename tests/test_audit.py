"""Tests for audit log — write, read, filter, clear."""

from __future__ import annotations

from pathlib import Path


from theaios.agent_auth.audit import AuditLog
from theaios.agent_auth.types import AuthDecision, AuthRequest


class TestAuditLog:
    """AuditLog writes decisions to JSONL in .agent_auth/ directory."""

    def _log(self, tmp_dir: Path) -> AuditLog:
        return AuditLog(path=str(tmp_dir / ".agent_auth" / "audit.jsonl"))

    def _decision(self, allowed: bool = True) -> AuthDecision:
        return AuthDecision(
            allowed=allowed,
            tier="autonomous" if allowed else "autonomous",
            reason="" if allowed else "denied by policy",
        )

    def test_write_creates_file(self, tmp_dir: Path) -> None:
        log = self._log(tmp_dir)
        req = AuthRequest(agent="assistant", user="alice", action="read")
        log.write(req, self._decision())
        entries = log.read()
        assert len(entries) >= 1

    def test_read_returns_logged_entry(self, tmp_dir: Path) -> None:
        log = self._log(tmp_dir)
        req = AuthRequest(agent="assistant", user="alice", action="read")
        log.write(req, self._decision())
        entries = log.read()
        assert entries[0]["agent"] == "assistant"
        assert entries[0]["action"] == "read"
        assert entries[0]["allowed"] is True

    def test_filter_by_agent(self, tmp_dir: Path) -> None:
        log = self._log(tmp_dir)
        req1 = AuthRequest(agent="bot1", user="alice", action="read")
        req2 = AuthRequest(agent="bot2", user="bob", action="write")
        log.write(req1, self._decision())
        log.write(req2, self._decision())
        entries = log.read(agent="bot1")
        assert all(e["agent"] == "bot1" for e in entries)

    def test_filter_by_action(self, tmp_dir: Path) -> None:
        log = self._log(tmp_dir)
        req1 = AuthRequest(agent="a", user="u", action="read")
        req2 = AuthRequest(agent="a", user="u", action="write")
        log.write(req1, self._decision())
        log.write(req2, self._decision())
        entries = log.read(action="write")
        assert all(e["action"] == "write" for e in entries)

    def test_clear(self, tmp_dir: Path) -> None:
        log = self._log(tmp_dir)
        req = AuthRequest(agent="a", user="u", action="read")
        log.write(req, self._decision())
        log.clear()
        entries = log.read()
        assert len(entries) == 0

    def test_read_nonexistent_file(self, tmp_dir: Path) -> None:
        log = AuditLog(path=str(tmp_dir / "does_not_exist" / "audit.jsonl"))
        # Should not crash, just return empty
        entries = log.read()
        assert entries == []
