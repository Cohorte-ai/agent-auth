"""JSONL audit log writer and reader."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from theaios.core.audit import JsonlLog

from theaios.agent_auth.types import AuthConfig, AuthDecision, AuthRequest


class AuditLog:
    """Append-only JSONL audit log.

    Writes one JSON object per line. Every authorization evaluation is logged,
    including allows — critical for compliance auditing.
    """

    def __init__(self, path: str = ".agent_auth/audit.jsonl") -> None:
        self._path = Path(path)
        self._log = JsonlLog(self._path)

    @property
    def path(self) -> Path:
        return self._path

    def write(
        self,
        request: AuthRequest,
        decision: AuthDecision,
        config: AuthConfig | None = None,
    ) -> None:
        """Write an audit log entry."""
        entry: dict[str, object] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_id": str(uuid.uuid4()),
            "agent": request.agent,
            "user": request.user,
            "action": request.action,
            "resource": request.resource,
            "allowed": decision.allowed,
            "tier": decision.tier,
            "reason": decision.reason,
            "requires_approval": decision.requires_approval,
            "approval_policy": decision.approval_policy,
            "session_id": request.session_id,
            "scope": request.scope,
            "target_agent": request.target_agent,
            "evaluation_time_ms": round(decision.evaluation_time_ms, 3),
        }

        if config:
            entry["config_name"] = config.metadata.name
            entry["config_version"] = config.version

        self._log.append(entry)

    def read(
        self,
        *,
        since: str | None = None,
        agent: str | None = None,
        user: str | None = None,
        action: str | None = None,
        allowed: bool | None = None,
        limit: int = 1000,
    ) -> list[dict[str, object]]:
        """Read audit log entries with optional filters."""

        def keep(entry: dict[str, object]) -> bool:
            if since and str(entry.get("timestamp", "")) < since:
                return False
            if agent and entry.get("agent") != agent:
                return False
            if user and entry.get("user") != user:
                return False
            if action and entry.get("action") != action:
                return False
            if allowed is not None and entry.get("allowed") != allowed:
                return False
            return True

        return self._log.read(keep, limit=limit)

    def clear(self) -> None:
        """Clear all audit log entries."""
        self._log.clear()
