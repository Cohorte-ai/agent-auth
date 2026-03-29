"""Tests for agent profile resolution — role expansion, deny overrides, scope matching."""

from __future__ import annotations

import pytest

from theaios.agent_auth.config import ConfigError
from theaios.agent_auth.profiles import (
    ResolvedProfile,
    check_action,
    check_scope,
    resolve_profile,
)
from theaios.agent_auth.types import AgentProfileConfig, RoleConfig


class TestResolveProfile:
    """resolve_profile(name, profiles, roles) -> ResolvedProfile."""

    def _roles(self) -> dict[str, RoleConfig]:
        return {
            "viewer": RoleConfig(name="viewer", actions=["read"]),
            "editor": RoleConfig(name="editor", actions=["write", "delete"], extends="viewer"),
        }

    def _profiles(self, **overrides: object) -> dict[str, AgentProfileConfig]:
        base = AgentProfileConfig(
            name="assistant",
            role="editor",
            allow=[],
            deny=[],
            scopes=["project:*"],
        )
        for k, v in overrides.items():
            setattr(base, k, v)
        return {"assistant": base}

    def test_resolve_basic_profile(self) -> None:
        profile = resolve_profile("assistant", self._profiles(), self._roles())
        assert "read" in profile.effective_actions
        assert "write" in profile.effective_actions

    def test_deny_overrides_role_action(self) -> None:
        profiles = self._profiles(deny=["delete"])
        profile = resolve_profile("assistant", profiles, self._roles())
        assert "delete" not in profile.effective_actions
        assert "read" in profile.effective_actions
        assert "write" in profile.effective_actions

    def test_scope_from_profile(self) -> None:
        profile = resolve_profile("assistant", self._profiles(), self._roles())
        assert profile.allowed_scopes == ["project:*"]

    def test_allow_adds_extra_actions(self) -> None:
        profiles = self._profiles(allow=["deploy"])
        profile = resolve_profile("assistant", profiles, self._roles())
        assert "deploy" in profile.effective_actions

    def test_deny_takes_precedence_over_allow(self) -> None:
        profiles = self._profiles(allow=["deploy"], deny=["deploy"])
        profile = resolve_profile("assistant", profiles, self._roles())
        assert "deploy" not in profile.effective_actions

    def test_unknown_profile_raises(self) -> None:
        with pytest.raises(ConfigError):
            resolve_profile("ghost", self._profiles(), self._roles())

    def test_unknown_role_in_profile_raises(self) -> None:
        profiles = {
            "bot": AgentProfileConfig(name="bot", role="nonexistent"),
        }
        with pytest.raises(ConfigError):
            resolve_profile("bot", profiles, self._roles())

    def test_empty_deny_list(self) -> None:
        profiles = self._profiles(deny=[])
        profile = resolve_profile("assistant", profiles, self._roles())
        assert profile.effective_actions == {"read", "write", "delete"}

    def test_role_chain_propagated(self) -> None:
        profile = resolve_profile("assistant", self._profiles(), self._roles())
        assert "viewer" in profile.role_chain
        assert "editor" in profile.role_chain


class TestCheckAction:
    """check_action(profile, action) -> 'allow' | 'deny' | None."""

    def test_allowed_action(self) -> None:
        profile = ResolvedProfile(name="p", effective_actions={"read"}, denied_actions=set())
        assert check_action(profile, "read") == "allow"

    def test_denied_action(self) -> None:
        profile = ResolvedProfile(name="p", effective_actions={"read"}, denied_actions={"write"})
        assert check_action(profile, "write") == "deny"

    def test_unknown_action(self) -> None:
        profile = ResolvedProfile(name="p", effective_actions={"read"}, denied_actions=set())
        assert check_action(profile, "deploy") is None

    def test_deny_overrides_allow_with_fnmatch(self) -> None:
        profile = ResolvedProfile(
            name="p", effective_actions={"read:*"}, denied_actions={"read:secret"}
        )
        assert check_action(profile, "read:secret") == "deny"
        assert check_action(profile, "read:public") == "allow"


class TestCheckScope:
    """check_scope(profile, scope) -> bool."""

    def test_matching_scope(self) -> None:
        profile = ResolvedProfile(name="p", allowed_scopes=["project:*"])
        assert check_scope(profile, "project:acme") is True

    def test_non_matching_scope(self) -> None:
        profile = ResolvedProfile(name="p", allowed_scopes=["project:*"])
        assert check_scope(profile, "admin:panel") is False

    def test_empty_scopes_allows_all(self) -> None:
        profile = ResolvedProfile(name="p", allowed_scopes=[])
        assert check_scope(profile, "anything") is True
