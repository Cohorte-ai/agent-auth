"""JSONL audit log writer and reader."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from theaios.agent_auth.types import AuthConfig, AuthDecision, AuthRequest


class AuditLog:
    """Append-only JSONL audit log.

    Writes one JSON object per line. Every authorization evaluation is logged,
    including allows — critical for compliance auditing.
    """

    def __init__(self, path: str = ".agent_auth/audit.jsonl") -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

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

        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")

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
        if not self._path.exists():
            return []

        entries: list[dict[str, object]] = []
        with open(self._path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if since and entry.get("timestamp", "") < since:
                    continue
                if agent and entry.get("agent") != agent:
                    continue
                if user and entry.get("user") != user:
                    continue
                if action and entry.get("action") != action:
                    continue
                if allowed is not None and entry.get("allowed") != allowed:
                    continue

                entries.append(entry)
                if len(entries) >= limit:
                    break

        return entries

    def clear(self) -> None:
        """Clear all audit log entries."""
        if self._path.exists():
            self._path.unlink()
