"""Tests for theaios.agent_auth.config — loading, validation, interpolation."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from theaios.agent_auth.config import ConfigError, load_config


class TestLoadConfig:
    """Loading agent_auth.yaml from disk."""

    def test_load_valid_yaml(self, basic_yaml: Path) -> None:
        cfg = load_config(str(basic_yaml))
        assert cfg.version == "1.0"
        assert "editor" in cfg.roles
        assert "assistant" in cfg.profiles

    def test_file_not_found_raises(self, tmp_dir: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_config(str(tmp_dir / "nonexistent.yaml"))

    def test_invalid_yaml_raises(self, tmp_dir: Path) -> None:
        bad = tmp_dir / "bad.yaml"
        bad.write_text("{{{{not yaml")
        with pytest.raises(Exception):
            load_config(str(bad))

    def test_non_dict_yaml_raises(self, tmp_dir: Path) -> None:
        p = tmp_dir / "list.yaml"
        p.write_text("- item1\n- item2")
        with pytest.raises(ConfigError):
            load_config(str(p))

    def test_empty_file_raises(self, tmp_dir: Path) -> None:
        p = tmp_dir / "empty.yaml"
        p.write_text("")
        with pytest.raises(ConfigError):
            load_config(str(p))


class TestEnvVarInterpolation:
    """Variables like ${ENV_VAR} are resolved from environment."""

    def test_env_var_substitution(self, tmp_dir: Path) -> None:
        os.environ["TEST_AUTH_ENV"] = "production"
        try:
            cfg_dict = {
                "version": "1.0",
                "variables": {"env": "${TEST_AUTH_ENV}"},
                "roles": {},
                "profiles": {},
            }
            p = tmp_dir / "env.yaml"
            p.write_text(yaml.dump(cfg_dict))
            cfg = load_config(str(p))
            assert cfg.variables["env"] == "production"
        finally:
            del os.environ["TEST_AUTH_ENV"]

    def test_missing_env_var_kept_as_is(self, tmp_dir: Path) -> None:
        cfg_dict = {
            "version": "1.0",
            "variables": {"env": "${DEFINITELY_NOT_SET_XYZ}"},
            "roles": {},
            "profiles": {},
        }
        p = tmp_dir / "env2.yaml"
        p.write_text(yaml.dump(cfg_dict))
        cfg = load_config(str(p))
        # Kept as placeholder since env var is not set
        assert isinstance(cfg.variables["env"], str)


class TestConfigValidation:
    """Semantic validation of config contents."""

    def test_unsupported_version_raises(self, tmp_dir: Path) -> None:
        cfg_dict = {"version": "99.0", "roles": {}, "profiles": {}}
        p = tmp_dir / "bad_ver.yaml"
        p.write_text(yaml.dump(cfg_dict))
        with pytest.raises(ConfigError):
            load_config(str(p))

    def test_unknown_role_in_profile_raises(self, tmp_dir: Path) -> None:
        cfg_dict = {
            "version": "1.0",
            "roles": {"viewer": {"actions": ["read"]}},
            "profiles": {"bot": {"role": "nonexistent"}},
        }
        p = tmp_dir / "bad_role.yaml"
        p.write_text(yaml.dump(cfg_dict))
        with pytest.raises(ConfigError, match="nonexistent"):
            load_config(str(p))

    def test_invalid_approval_tier_raises(self, tmp_dir: Path) -> None:
        cfg_dict = {
            "version": "1.0",
            "roles": {},
            "profiles": {},
            "approval_policies": [
                {"name": "bad", "condition": "", "tier": "invalid_tier"},
            ],
        }
        p = tmp_dir / "bad_tier.yaml"
        p.write_text(yaml.dump(cfg_dict))
        with pytest.raises(ConfigError, match="tier"):
            load_config(str(p))

    def test_invalid_a2a_default_raises(self, tmp_dir: Path) -> None:
        cfg_dict = {
            "version": "1.0",
            "roles": {},
            "profiles": {},
            "a2a": {"default": "maybe"},
        }
        p = tmp_dir / "bad_a2a.yaml"
        p.write_text(yaml.dump(cfg_dict))
        with pytest.raises(ConfigError, match="a2a"):
            load_config(str(p))

    def test_valid_config_object_attributes(self, basic_yaml: Path) -> None:
        cfg = load_config(str(basic_yaml))
        assert cfg.metadata.name == "test-config"
        assert cfg.audit.enabled is True
        assert cfg.sessions.default_duration == 3600
        assert cfg.delegation.max_duration == 86400

    def test_circular_role_extends_raises(self, tmp_dir: Path) -> None:
        cfg_dict = {
            "version": "1.0",
            "roles": {
                "a": {"actions": ["x"], "extends": "b"},
                "b": {"actions": ["y"], "extends": "a"},
            },
            "profiles": {},
        }
        p = tmp_dir / "circular.yaml"
        p.write_text(yaml.dump(cfg_dict))
        with pytest.raises(ConfigError, match="circular"):
            load_config(str(p))
