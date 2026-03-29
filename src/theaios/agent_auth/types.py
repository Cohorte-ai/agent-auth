"""Shared data models for the Agent Auth engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ApprovalTier(Enum):
    """Approval tier levels for authorization decisions."""

    AUTONOMOUS = "autonomous"
    SOFT = "soft"
    STRONG = "strong"


class A2ADefault(Enum):
    """Default policy for agent-to-agent communication."""

    ALLOW = "allow"
    DENY = "deny"


class SessionStatus(Enum):
    """Status of an agent session."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class DelegationStatus(Enum):
    """Status of a delegation grant."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


VALID_TIERS = {t.value for t in ApprovalTier}
VALID_A2A_DEFAULTS = {d.value for d in A2ADefault}
VALID_SESSION_STATUSES = {s.value for s in SessionStatus}
VALID_DELEGATION_STATUSES = {s.value for s in DelegationStatus}

TIER_ORDER: dict[str, int] = {
    "autonomous": 0,
    "soft": 1,
    "strong": 2,
}


# ---------------------------------------------------------------------------
# Runtime: request & decision
# ---------------------------------------------------------------------------


@dataclass
class AuthRequest:
    """An authorization request to evaluate.

    Represents an agent requesting to perform an action on a resource,
    optionally within a session or targeting another agent.
    """

    agent: str
    user: str
    action: str
    resource: str = ""
    session_id: str | None = None
    scope: str = ""
    target_agent: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass
class AuthDecision:
    """Result of an authorization evaluation."""

    allowed: bool
    tier: str = "autonomous"
    reason: str = ""
    requires_approval: bool = False
    approval_policy: str = ""
    evaluation_time_ms: float = 0.0

    @property
    def is_denied(self) -> bool:
        """True if the request was denied."""
        return not self.allowed

    @property
    def is_autonomous(self) -> bool:
        """True if the decision is autonomous (no approval required)."""
        return self.allowed and self.tier == "autonomous" and not self.requires_approval


# ---------------------------------------------------------------------------
# Runtime: sessions & delegation
# ---------------------------------------------------------------------------


@dataclass
class Session:
    """An active agent session with scope and expiry."""

    session_id: str
    agent: str
    user: str
    scope: str = ""
    created_at: str = ""
    expires_at: str = ""
    status: str = "active"


@dataclass
class DelegationGrant:
    """A delegation of specific actions from a user to an agent."""

    delegation_id: str
    from_user: str
    to_agent: str
    actions: list[str] = field(default_factory=list)
    granted_at: str = ""
    expires_at: str = ""
    reason: str = ""
    status: str = "active"


# ---------------------------------------------------------------------------
# Configuration (parsed from YAML)
# ---------------------------------------------------------------------------


@dataclass
class RoleConfig:
    """A named role with actions and inheritance."""

    name: str
    actions: list[str] = field(default_factory=list)
    extends: str = ""
    description: str = ""


@dataclass
class AgentProfileConfig:
    """An agent profile with role, scope, and permission overrides."""

    name: str
    role: str = ""
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    max_session_duration: int = 3600
    default_tier: str = "autonomous"
    description: str = ""


@dataclass
class ApprovalPolicyConfig:
    """A conditional approval policy that upgrades the approval tier."""

    name: str
    condition: str = ""
    tier: str = "soft"
    description: str = ""


@dataclass
class DelegationRuleConfig:
    """A rule constraining what can be delegated."""

    name: str
    allowed_actions: list[str] = field(default_factory=list)
    max_duration: int = 86400
    require_reason: bool = False
    description: str = ""


@dataclass
class DelegationConfig:
    """Top-level delegation configuration."""

    enabled: bool = True
    default_duration: int = 3600
    max_duration: int = 86400
    rules: list[DelegationRuleConfig] = field(default_factory=list)


@dataclass
class A2APolicyConfig:
    """A single agent-to-agent communication policy."""

    name: str
    from_agent: str = "*"
    to_agent: str = "*"
    action: str = "*"
    effect: str = "allow"
    condition: str = ""
    description: str = ""


@dataclass
class A2AConfig:
    """Top-level agent-to-agent configuration."""

    default: str = "deny"
    policies: list[A2APolicyConfig] = field(default_factory=list)


@dataclass
class SessionConfig:
    """Session management configuration."""

    default_duration: int = 3600
    max_duration: int = 86400
    cleanup_interval: int = 300


@dataclass
class AuditConfig:
    """Audit logging configuration."""

    enabled: bool = True
    path: str = ".agent_auth/audit.jsonl"
    retention_days: int = 90


@dataclass
class AuthMetadata:
    """Policy-level metadata."""

    name: str = ""
    description: str = ""
    author: str = ""


@dataclass
class AuthConfig:
    """Top-level auth configuration — maps 1:1 to agent_auth.yaml."""

    version: str = "1.0"
    metadata: AuthMetadata = field(default_factory=AuthMetadata)
    variables: dict[str, object] = field(default_factory=dict)
    roles: dict[str, RoleConfig] = field(default_factory=dict)
    profiles: dict[str, AgentProfileConfig] = field(default_factory=dict)
    approval_policies: list[ApprovalPolicyConfig] = field(default_factory=list)
    delegation: DelegationConfig = field(default_factory=DelegationConfig)
    a2a: A2AConfig = field(default_factory=A2AConfig)
    sessions: SessionConfig = field(default_factory=SessionConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
