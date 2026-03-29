"""Tests for role resolution and inheritance."""

from __future__ import annotations

import pytest

from theaios.agent_auth.config import ConfigError
from theaios.agent_auth.roles import resolve_role
from theaios.agent_auth.types import RoleConfig


class TestResolveRole:
    """resolve_role(name, roles) -> ResolvedRole."""

    def test_simple_role(self) -> None:
        roles = {"viewer": RoleConfig(name="viewer", actions=["read"])}
        result = resolve_role("viewer", roles)
        assert result.actions == {"read"}
        assert result.chain == ["viewer"]

    def test_single_inheritance(self) -> None:
        roles = {
            "viewer": RoleConfig(name="viewer", actions=["read"]),
            "editor": RoleConfig(name="editor", actions=["write"], extends="viewer"),
        }
        result = resolve_role("editor", roles)
        assert result.actions == {"read", "write"}
        assert result.chain == ["viewer", "editor"]

    def test_deep_inheritance(self) -> None:
        roles = {
            "viewer": RoleConfig(name="viewer", actions=["read"]),
            "editor": RoleConfig(name="editor", actions=["write"], extends="viewer"),
            "admin": RoleConfig(name="admin", actions=["delete"], extends="editor"),
        }
        result = resolve_role("admin", roles)
        assert result.actions == {"read", "write", "delete"}
        assert result.chain == ["viewer", "editor", "admin"]

    def test_no_extends(self) -> None:
        roles = {"base": RoleConfig(name="base", actions=["read", "write"])}
        result = resolve_role("base", roles)
        assert result.actions == {"read", "write"}
        assert result.chain == ["base"]

    def test_empty_actions(self) -> None:
        roles = {
            "viewer": RoleConfig(name="viewer", actions=["read"]),
            "wrapper": RoleConfig(name="wrapper", actions=[], extends="viewer"),
        }
        result = resolve_role("wrapper", roles)
        assert result.actions == {"read"}

    def test_circular_inheritance_raises(self) -> None:
        roles = {
            "a": RoleConfig(name="a", actions=["x"], extends="b"),
            "b": RoleConfig(name="b", actions=["y"], extends="a"),
        }
        with pytest.raises(ConfigError, match="[Cc]ircular"):
            resolve_role("a", roles)

    def test_missing_role_raises(self) -> None:
        roles = {"viewer": RoleConfig(name="viewer", actions=["read"])}
        with pytest.raises(ConfigError):
            resolve_role("nonexistent", roles)

    def test_missing_parent_role_raises(self) -> None:
        roles = {
            "editor": RoleConfig(name="editor", actions=["write"], extends="ghost"),
        }
        with pytest.raises(ConfigError):
            resolve_role("editor", roles)
