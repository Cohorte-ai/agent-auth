"""theaios-agent-auth — Agent-specific IAM for AI systems."""

__version__ = "0.3.0"

from theaios.agent_auth.config import ConfigError, load_config
from theaios.agent_auth.engine import AuthEngine, VerifiedToken
from theaios.agent_auth.resolution import Principal, ResolvedAgent
from theaios.agent_auth.tokens import TokenClaims, TokenError
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
    ResolutionConfig,
    RoleConfig,
    SeparationOfDutiesConfig,
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
    # Resolution (0.2)
    "Principal",
    "ResolvedAgent",
    "VerifiedToken",
    "TokenClaims",
    "TokenError",
    "ResolutionConfig",
    "SeparationOfDutiesConfig",
]
