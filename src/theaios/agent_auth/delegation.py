"""Delegation management with JSONL persistence."""

from __future__ import annotations

import fnmatch
import json
from collections.abc import Iterable
import logging
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from theaios.agent_auth.types import DelegationRuleConfig, DelegationConfig, DelegationGrant

_logger = logging.getLogger(__name__)


class DelegationManager:
    """Manages delegation grants from users to agents.

    Delegations allow users to grant specific action permissions to agents
    for a limited time, optionally with a reason for audit purposes.
    """

    def __init__(
        self,
        config: DelegationConfig | None = None,
        path: str = ".agent_auth/delegations.jsonl",
    ) -> None:
        self._config = config or DelegationConfig()
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._grants: dict[str, DelegationGrant] = {}
        self._stamp: tuple[int, int] | None = None
        self._load()

    def _file_stamp(self) -> tuple[int, int] | None:
        try:
            st = self._path.stat()
        except OSError:
            return None
        return (st.st_ino, st.st_mtime_ns)

    def _fresh(self) -> None:
        """Reload when another process (another engine, the CLI) replaced the file, so a
        revocation there takes effect here."""
        stamp = self._file_stamp()
        if stamp != self._stamp:
            self._grants.clear()
            self._load()

    def _load(self) -> None:
        """Load delegation grants from JSONL file."""
        self._stamp = self._file_stamp()
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
                    _logger.warning("Skipping malformed JSON line in delegations file")
                    continue
                if not isinstance(entry, dict):
                    _logger.warning("Skipping non-dict entry in delegations file")
                    continue
                actions_raw = entry.get("actions", [])
                actions = [str(a) for a in actions_raw] if isinstance(actions_raw, list) else []
                grant = DelegationGrant(
                    delegation_id=str(entry.get("delegation_id", "")),
                    from_user=str(entry.get("from_user", "")),
                    to_agent=str(entry.get("to_agent", "")),
                    actions=actions,
                    granted_at=str(entry.get("granted_at", "")),
                    expires_at=str(entry.get("expires_at", "")),
                    reason=str(entry.get("reason", "")),
                    status=str(entry.get("status", "active")),
                )
                self._grants[grant.delegation_id] = grant

    def _save(self) -> None:
        """Persist all delegation grants to JSONL file (atomic write)."""
        # Atomic write: write to temp file then rename to prevent corruption
        with tempfile.NamedTemporaryFile(
            dir=self._path.parent, mode="w", encoding="utf-8", suffix=".tmp", delete=False
        ) as f:
            for grant in self._grants.values():
                entry = {
                    "delegation_id": grant.delegation_id,
                    "from_user": grant.from_user,
                    "to_agent": grant.to_agent,
                    "actions": grant.actions,
                    "granted_at": grant.granted_at,
                    "expires_at": grant.expires_at,
                    "reason": grant.reason,
                    "status": grant.status,
                }
                f.write(json.dumps(entry, default=str) + "\n")
            temp_path = Path(f.name)
        temp_path.replace(self._path)
        self._stamp = self._file_stamp()

    def validate_rule(
        self,
        actions: list[str],
        duration: int,
        reason: str,
        roles: Iterable[str] | None = None,
    ) -> list[str]:
        """Validate a delegation against the configured rules (empty list = valid).

        Rules without ``roles`` apply to everyone, all of them (as in 0.1). Rules with
        ``roles`` say who may delegate: when there are any, the delegating user must hold a
        role of at least one of them that allows every action. ``roles`` is the delegating
        user's roles (``None``: unknown, so role rules cannot be satisfied). Action patterns are
        compared without reading wildcards as text: a rule allowing ``read:[!s]*`` does not
        accept a delegation of ``read:*``."""
        from theaios.agent_auth.resolution import covers

        errors: list[str] = []
        if not self._config.enabled:
            return ["Delegation is disabled"]
        if duration > self._config.max_duration:
            errors.append(
                f"Duration ({duration}s) exceeds max_duration ({self._config.max_duration}s)"
            )

        def check(rule: DelegationRuleConfig) -> list[str]:
            out: list[str] = []
            if rule.allowed_actions:
                for action in actions:
                    if not any(covers(allowed, action) for allowed in rule.allowed_actions):
                        out.append(
                            f"Action '{action}' not allowed by delegation rule '{rule.name}'"
                        )
            if duration > rule.max_duration:
                out.append(
                    f"Duration ({duration}s) exceeds rule '{rule.name}' "
                    f"max_duration ({rule.max_duration}s)"
                )
            if rule.require_reason and not reason:
                out.append(f"Delegation rule '{rule.name}' requires a reason")
            return out

        for rule in self._config.rules:
            if not rule.roles:
                errors += check(rule)
        role_rules = [r for r in self._config.rules if r.roles]
        if role_rules:
            held = set(roles or ())
            mine = [r for r in role_rules if held & set(r.roles)]
            if not mine:
                errors.append(
                    "No delegation rule lets "
                    + (f"roles {', '.join(sorted(held))}" if held else "a user without roles")
                    + " delegate"
                )
            elif all(check(r) for r in mine):
                errors += check(mine[0])
        return errors

    def create(
        self,
        from_user: str,
        to_agent: str,
        actions: list[str],
        duration: int | None = None,
        reason: str = "",
        roles: Iterable[str] | None = None,
    ) -> DelegationGrant:
        """Create a new delegation grant (``roles``: the delegating user's roles, for rules
        that say who may delegate).

        Parameters
        ----------
        from_user : str
            User granting the delegation.
        to_agent : str
            Agent receiving the delegation.
        actions : list[str]
            Actions being delegated.
        duration : int, optional
            Duration in seconds. Defaults to config default_duration.
        reason : str
            Reason for the delegation (may be required by rules).

        Returns
        -------
        DelegationGrant
            The newly created grant.

        Raises
        ------
        ValueError
            If the delegation violates configured rules.
        """
        self._fresh()
        effective_duration = duration if duration is not None else self._config.default_duration

        # Validate against rules
        errors = self.validate_rule(actions, effective_duration, reason, roles)
        if errors:
            raise ValueError("Delegation validation failed:\n  " + "\n  ".join(errors))

        now = datetime.now(timezone.utc)
        grant = DelegationGrant(
            delegation_id=str(uuid.uuid4()),
            from_user=from_user,
            to_agent=to_agent,
            actions=list(actions),
            granted_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=effective_duration)).isoformat(),
            reason=reason,
            status="active",
        )
        self._grants[grant.delegation_id] = grant
        self._save()
        return grant

    def check(self, agent: str, action: str, user: str | None = None) -> DelegationGrant | None:
        """Check if an agent has an active delegation for an action.

        With ``user``, only a delegation granted by that user counts: a user's delegation
        applies when the agent acts for that user, never for someone else. The engine always
        passes it. Returns the matching delegation grant or None.
        """
        self._fresh()
        now = datetime.now(timezone.utc)

        for grant in self._grants.values():
            if grant.status != "active":
                continue
            if grant.to_agent != agent:
                continue
            if user is not None and grant.from_user != user:
                continue

            # Check expiry
            try:
                expires = datetime.fromisoformat(grant.expires_at)
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                if now >= expires:
                    grant.status = "expired"
                    continue
            except (ValueError, TypeError):
                continue

            # Check if action matches
            for delegated_action in grant.actions:
                if fnmatch.fnmatch(action, delegated_action):
                    return grant

        return None

    def revoke(self, delegation_id: str) -> bool:
        """Revoke a delegation grant. Returns True if revoked, False if not found."""
        self._fresh()
        grant = self._grants.get(delegation_id)
        if grant is None:
            return False

        if grant.status != "active":
            return False

        grant.status = "revoked"
        self._save()
        return True

    def list_active(self, agent: str | None = None) -> list[DelegationGrant]:
        """List active delegation grants, optionally filtered by agent."""
        self._fresh()
        results: list[DelegationGrant] = []
        now = datetime.now(timezone.utc)

        for grant in self._grants.values():
            if grant.status != "active":
                continue

            # Check expiry inline
            try:
                expires = datetime.fromisoformat(grant.expires_at)
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                if now >= expires:
                    grant.status = "expired"
                    continue
            except (ValueError, TypeError):
                continue

            if agent and grant.to_agent != agent:
                continue

            results.append(grant)

        return results

    def expire_stale(self) -> int:
        """Expire all grants that have passed their expiry time.

        Returns the number of grants expired.
        """
        self._fresh()
        now = datetime.now(timezone.utc)
        count = 0

        for grant in self._grants.values():
            if grant.status != "active":
                continue

            try:
                expires = datetime.fromisoformat(grant.expires_at)
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                grant.status = "expired"
                count += 1
                continue

            if now >= expires:
                grant.status = "expired"
                count += 1

        if count > 0:
            self._save()

        return count
