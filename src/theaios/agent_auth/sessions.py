"""Session management with JSONL persistence."""

from __future__ import annotations

import json
import logging
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from theaios.agent_auth.types import Session

_logger = logging.getLogger(__name__)


class SessionManager:
    """Manages agent sessions with create, validate, revoke, and expiry.

    Sessions are persisted to a JSONL file for durability across restarts.
    """

    def __init__(self, path: str = ".agent_auth/sessions.jsonl") -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._sessions: dict[str, Session] = {}
        self._load()

    def _load(self) -> None:
        """Load sessions from JSONL file."""
        if not self._path.exists():
            return

        with open(self._path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    _logger.warning("Skipping malformed JSON line in sessions file")
                    continue
                if not isinstance(entry, dict):
                    _logger.warning("Skipping non-dict entry in sessions file")
                    continue
                session = Session(
                    session_id=str(entry.get("session_id", "")),
                    agent=str(entry.get("agent", "")),
                    user=str(entry.get("user", "")),
                    scope=str(entry.get("scope", "")),
                    created_at=str(entry.get("created_at", "")),
                    expires_at=str(entry.get("expires_at", "")),
                    status=str(entry.get("status", "active")),
                )
                self._sessions[session.session_id] = session

    def _save(self) -> None:
        """Persist all sessions to JSONL file (atomic write)."""
        # Atomic write: write to temp file then rename to prevent corruption
        with tempfile.NamedTemporaryFile(
            dir=self._path.parent, mode="w", encoding="utf-8", suffix=".tmp", delete=False
        ) as f:
            for session in self._sessions.values():
                entry = {
                    "session_id": session.session_id,
                    "agent": session.agent,
                    "user": session.user,
                    "scope": session.scope,
                    "created_at": session.created_at,
                    "expires_at": session.expires_at,
                    "status": session.status,
                }
                f.write(json.dumps(entry, default=str) + "\n")
            temp_path = Path(f.name)
        temp_path.replace(self._path)

    def create(
        self,
        agent: str,
        user: str,
        scope: str = "",
        duration: int = 3600,
    ) -> Session:
        """Create a new session.

        Parameters
        ----------
        agent : str
            Agent name.
        user : str
            User name.
        scope : str
            Session scope (e.g., "project:alpha").
        duration : int
            Session duration in seconds.

        Returns
        -------
        Session
            The newly created session.
        """
        now = datetime.now(timezone.utc)
        session = Session(
            session_id=str(uuid.uuid4()),
            agent=agent,
            user=user,
            scope=scope,
            created_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=duration)).isoformat(),
            status="active",
        )
        self._sessions[session.session_id] = session
        self._save()
        return session

    def validate(self, session_id: str) -> Session | None:
        """Validate a session. Returns the session if active, None otherwise.

        Automatically marks expired sessions.
        """
        session = self._sessions.get(session_id)
        if session is None:
            return None

        if session.status != "active":
            return None

        # Check expiry
        now = datetime.now(timezone.utc)
        try:
            expires = datetime.fromisoformat(session.expires_at)
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None

        if now >= expires:
            session.status = "expired"
            self._save()
            return None

        return session

    def revoke(self, session_id: str) -> bool:
        """Revoke a session. Returns True if revoked, False if not found."""
        session = self._sessions.get(session_id)
        if session is None:
            return False

        if session.status != "active":
            return False

        session.status = "revoked"
        self._save()
        return True

    def list_active(
        self,
        agent: str | None = None,
        user: str | None = None,
    ) -> list[Session]:
        """List active sessions, optionally filtered by agent and/or user."""
        results: list[Session] = []
        now = datetime.now(timezone.utc)

        for session in self._sessions.values():
            if session.status != "active":
                continue

            # Check expiry inline
            try:
                expires = datetime.fromisoformat(session.expires_at)
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                if now >= expires:
                    session.status = "expired"
                    continue
            except (ValueError, TypeError):
                continue

            if agent and session.agent != agent:
                continue
            if user and session.user != user:
                continue

            results.append(session)

        return results

    def expire_stale(self) -> int:
        """Expire all sessions that have passed their expiry time.

        Returns the number of sessions expired.
        """
        now = datetime.now(timezone.utc)
        count = 0

        for session in self._sessions.values():
            if session.status != "active":
                continue

            try:
                expires = datetime.fromisoformat(session.expires_at)
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                session.status = "expired"
                count += 1
                continue

            if now >= expires:
                session.status = "expired"
                count += 1

        if count > 0:
            self._save()

        return count
