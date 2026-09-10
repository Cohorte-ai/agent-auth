"""theaios-agent-auth — Agent-specific IAM for AI systems."""

__version__ = "0.1.1"

from theaios.agent_auth.config import ConfigError, load_config
from theaios.agent_auth.engine import AuthEngine
from theaios.agent_auth.types import (
    A2AConfig,
    A2ADefault,
    A2APolicyConfig,
    AgentProfileConfig,
    ApprovalPolicyConfig,
    ApprovalTier,
    AuditConfig,
    AuthConfig,
    AuthDecision,
    AuthMetadata,
    AuthRequest,
    DelegationConfig,
    DelegationGrant,
    DelegationRuleConfig,
    DelegationStatus,
    RoleConfig,
    Session,
    SessionConfig,
    SessionStatus,
)


def authorize(
    config: AuthConfig,
    request: AuthRequest,
) -> AuthDecision:
    """Authorize a request against a config. Convenience function."""
    engine = AuthEngine(config)
    return engine.authorize(request)


__all__ = [
    # Core
    "AuthEngine",
    "load_config",
    "authorize",
    "ConfigError",
    # Runtime types
    "AuthRequest",
    "AuthDecision",
    "Session",
    "DelegationGrant",
    # Config types
    "AuthConfig",
    "AuthMetadata",
    "RoleConfig",
    "AgentProfileConfig",
    "ApprovalPolicyConfig",
    "DelegationConfig",
    "DelegationRuleConfig",
    "A2AConfig",
    "A2APolicyConfig",
    "SessionConfig",
    "AuditConfig",
    # Enums
    "ApprovalTier",
    "A2ADefault",
    "SessionStatus",
    "DelegationStatus",
]
