"""Agent profile resolution with role-based permissions."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

from theaios.agent_auth.config import ConfigError
from theaios.agent_auth.roles import resolve_role
from theaios.agent_auth.types import AgentProfileConfig, RoleConfig


@dataclass
class ResolvedProfile:
    """A fully resolved agent profile with effective permissions."""

    name: str
    effective_actions: set[str] = field(default_factory=set)
    denied_actions: set[str] = field(default_factory=set)
    allowed_scopes: list[str] = field(default_factory=list)
    max_session_duration: int = 3600
    default_tier: str = "autonomous"
    role_chain: list[str] = field(default_factory=list)


def resolve_profile(
    name: str,
    profiles: dict[str, AgentProfileConfig],
    roles: dict[str, RoleConfig],
) -> ResolvedProfile:
    """Resolve a profile by applying role inheritance and permission overrides.

    1. Resolve the role (if any) to get base actions.
    2. Add profile-level allow actions.
    3. Remove profile-level deny actions.
    """
    if name not in profiles:
        raise ConfigError([f"Profile '{name}' does not exist"])

    profile = profiles[name]

    # Start with role actions
    role_actions: set[str] = set()
    role_chain: list[str] = []
    if profile.role:
        resolved = resolve_role(profile.role, roles)
        role_actions = resolved.actions
        role_chain = resolved.chain

    # Apply profile overrides
    effective = role_actions | set(profile.allow)
    denied = set(profile.deny)

    # Deny takes precedence
    effective -= denied

    return ResolvedProfile(
        name=name,
        effective_actions=effective,
        denied_actions=denied,
        allowed_scopes=list(profile.scopes),
        max_session_duration=profile.max_session_duration,
        default_tier=profile.default_tier,
        role_chain=role_chain,
    )


def check_action(
    profile: ResolvedProfile,
    action: str,
) -> str | None:
    """Check whether an action is allowed, denied, or unspecified by a profile.

    Returns "allow", "deny", or None (not explicitly listed).
    Uses fnmatch for wildcard support (e.g., "read:*" matches "read:documents").
    """
    # Check deny first (deny takes precedence)
    for pattern in profile.denied_actions:
        if fnmatch.fnmatch(action, pattern):
            return "deny"

    # Check allow
    for pattern in profile.effective_actions:
        if fnmatch.fnmatch(action, pattern):
            return "allow"

    return None


def check_scope(
    profile: ResolvedProfile,
    scope: str,
) -> bool:
    """Check whether a scope is allowed by a profile.

    Returns True if the scope matches any allowed scope pattern.
    An empty scopes list means all scopes are allowed.
    """
    if not profile.allowed_scopes:
        return True

    for pattern in profile.allowed_scopes:
        if fnmatch.fnmatch(scope, pattern):
            return True

    return False
