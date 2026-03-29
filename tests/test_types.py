"""Tests for theaios.agent_auth.types — enums, dataclasses, constants."""

from __future__ import annotations


from theaios.agent_auth.types import (
    A2ADefault,
    ApprovalTier,
    AuthDecision,
    AuthRequest,
    DelegationGrant,
    DelegationStatus,
    Session,
    SessionStatus,
    VALID_TIERS,
    VALID_A2A_DEFAULTS,
    VALID_SESSION_STATUSES,
    VALID_DELEGATION_STATUSES,
    TIER_ORDER,
)


# ===================================================================
# Enum value tests
# ===================================================================


class TestApprovalTier:
    def test_autonomous_value(self) -> None:
        assert ApprovalTier.AUTONOMOUS.value == "autonomous"

    def test_soft_value(self) -> None:
        assert ApprovalTier.SOFT.value == "soft"

    def test_strong_value(self) -> None:
        assert ApprovalTier.STRONG.value == "strong"

    def test_all_tiers_in_valid_set(self) -> None:
        for tier in ApprovalTier:
            assert tier.value in VALID_TIERS


class TestA2ADefault:
    def test_allow_value(self) -> None:
        assert A2ADefault.ALLOW.value == "allow"

    def test_deny_value(self) -> None:
        assert A2ADefault.DENY.value == "deny"

    def test_all_in_valid_set(self) -> None:
        for d in A2ADefault:
            assert d.value in VALID_A2A_DEFAULTS


class TestSessionStatus:
    def test_active_value(self) -> None:
        assert SessionStatus.ACTIVE.value == "active"

    def test_revoked_value(self) -> None:
        assert SessionStatus.REVOKED.value == "revoked"

    def test_expired_value(self) -> None:
        assert SessionStatus.EXPIRED.value == "expired"

    def test_all_in_valid_set(self) -> None:
        for s in SessionStatus:
            assert s.value in VALID_SESSION_STATUSES


class TestDelegationStatus:
    def test_active_value(self) -> None:
        assert DelegationStatus.ACTIVE.value == "active"

    def test_revoked_value(self) -> None:
        assert DelegationStatus.REVOKED.value == "revoked"

    def test_expired_value(self) -> None:
        assert DelegationStatus.EXPIRED.value == "expired"

    def test_all_in_valid_set(self) -> None:
        for d in DelegationStatus:
            assert d.value in VALID_DELEGATION_STATUSES


class TestTierOrder:
    def test_autonomous_lowest(self) -> None:
        assert TIER_ORDER["autonomous"] == 0

    def test_soft_middle(self) -> None:
        assert TIER_ORDER["soft"] == 1

    def test_strong_highest(self) -> None:
        assert TIER_ORDER["strong"] == 2


# ===================================================================
# AuthRequest defaults
# ===================================================================


class TestAuthRequest:
    def test_minimal_creation(self) -> None:
        req = AuthRequest(agent="a", user="u", action="read")
        assert req.agent == "a"
        assert req.user == "u"
        assert req.action == "read"

    def test_defaults(self) -> None:
        req = AuthRequest(agent="a", user="u", action="read")
        assert req.resource == ""
        assert req.session_id is None
        assert req.scope == ""
        assert req.target_agent is None
        assert req.metadata == {}

    def test_full_creation(self) -> None:
        req = AuthRequest(
            agent="bot",
            user="bob",
            action="write",
            resource="/files/report.pdf",
            session_id="sess-123",
            scope="/files",
            target_agent="reviewer",
            metadata={"priority": "high"},
        )
        assert req.resource == "/files/report.pdf"
        assert req.session_id == "sess-123"
        assert req.scope == "/files"
        assert req.target_agent == "reviewer"
        assert req.metadata == {"priority": "high"}


# ===================================================================
# AuthDecision properties
# ===================================================================


class TestAuthDecision:
    def test_allowed_decision(self) -> None:
        d = AuthDecision(allowed=True, tier="autonomous")
        assert d.allowed is True
        assert d.is_denied is False
        assert d.is_autonomous is True

    def test_denied_decision(self) -> None:
        d = AuthDecision(allowed=False, reason="no permission")
        assert d.allowed is False
        assert d.is_denied is True
        assert d.is_autonomous is False

    def test_requires_approval_not_autonomous(self) -> None:
        d = AuthDecision(
            allowed=True,
            requires_approval=True,
            approval_policy="destructive",
            tier="strong",
        )
        assert d.allowed is True
        assert d.requires_approval is True
        assert d.is_autonomous is False

    def test_defaults(self) -> None:
        d = AuthDecision(allowed=True)
        assert d.tier == "autonomous"
        assert d.reason == ""
        assert d.requires_approval is False
        assert d.approval_policy == ""
        assert d.evaluation_time_ms == 0.0

    def test_is_autonomous_requires_autonomous_tier(self) -> None:
        d = AuthDecision(allowed=True, tier="soft")
        assert d.is_autonomous is False

    def test_is_autonomous_requires_allowed(self) -> None:
        d = AuthDecision(allowed=False, tier="autonomous")
        assert d.is_autonomous is False


# ===================================================================
# Session & DelegationGrant
# ===================================================================


class TestSession:
    def test_defaults(self) -> None:
        s = Session(session_id="s1", agent="a", user="u")
        assert s.status == "active"
        assert s.session_id == "s1"
        assert s.scope == ""
        assert s.created_at == ""
        assert s.expires_at == ""

    def test_full_creation(self) -> None:
        s = Session(
            session_id="s2",
            agent="bot",
            user="alice",
            scope="project:x",
            created_at="2025-01-01T00:00:00+00:00",
            expires_at="2025-01-01T01:00:00+00:00",
            status="active",
        )
        assert s.agent == "bot"
        assert s.scope == "project:x"


class TestDelegationGrant:
    def test_defaults(self) -> None:
        g = DelegationGrant(
            delegation_id="d1",
            from_user="alice",
            to_agent="bot",
        )
        assert g.actions == []
        assert g.reason == ""
        assert g.status == "active"
        assert g.granted_at == ""
        assert g.expires_at == ""

    def test_full_creation(self) -> None:
        g = DelegationGrant(
            delegation_id="d2",
            from_user="bob",
            to_agent="helper",
            actions=["read", "write"],
            granted_at="2025-01-01T00:00:00+00:00",
            expires_at="2025-01-02T00:00:00+00:00",
            reason="temp access",
            status="active",
        )
        assert g.actions == ["read", "write"]
        assert g.reason == "temp access"
