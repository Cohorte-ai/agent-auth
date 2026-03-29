"""YAML auth config loader and validation."""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

from theaios.agent_auth.types import (
    VALID_A2A_DEFAULTS,
    VALID_TIERS,
    A2AConfig,
    A2APolicyConfig,
    AgentProfileConfig,
    ApprovalPolicyConfig,
    AuditConfig,
    AuthConfig,
    AuthMetadata,
    DelegationConfig,
    DelegationRuleConfig,
    RoleConfig,
    SessionConfig,
)


class ConfigError(Exception):
    """Raised when an auth config file is invalid."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("Invalid auth config:\n  " + "\n  ".join(errors))


_ENV_PATTERN = re.compile(r"\$\{(\w+)\}")


def _interpolate_env(value: str) -> str:
    """Replace ${ENV_VAR} references with environment variable values."""

    def _replace(match: re.Match[str]) -> str:
        var_name = match.group(1)
        return os.environ.get(var_name, match.group(0))

    return _ENV_PATTERN.sub(_replace, value)


def _interpolate_recursive(obj: object) -> object:
    """Recursively interpolate environment variables in strings."""
    if isinstance(obj, str):
        return _interpolate_env(obj)
    if isinstance(obj, dict):
        return {k: _interpolate_recursive(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_interpolate_recursive(item) for item in obj]
    return obj


def load_config(path: str = "agent_auth.yaml") -> AuthConfig:
    """Load a YAML auth config file, validate, and return typed config."""
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Auth config file not found: {path}")

    with open(config_path) as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ConfigError(["Auth config file must be a YAML mapping"])

    # Security: parse and validate YAML structure BEFORE interpolating env vars.
    # This ensures that malformed configs are rejected before any env var values
    # are substituted, preventing env var contents from leaking in error messages.
    config = _parse_config(raw)

    # Now interpolate env vars on the raw dict and re-parse
    raw = _interpolate_recursive(raw)
    if not isinstance(raw, dict):
        raise ConfigError(["Config must be a YAML mapping after interpolation"])

    config = _parse_config(raw)

    errors = validate_config(config)
    if errors:
        raise ConfigError(errors)

    return config


def _parse_config(raw: dict[str, object]) -> AuthConfig:
    """Parse raw YAML dict into typed AuthConfig."""

    # Version
    version = str(raw.get("version", "1.0"))

    # Metadata
    meta_raw = raw.get("metadata", {})
    if not isinstance(meta_raw, dict):
        meta_raw = {}
    metadata = AuthMetadata(
        name=str(meta_raw.get("name", "")),
        description=str(meta_raw.get("description", "")),
        author=str(meta_raw.get("author", "")),
    )

    # Variables
    variables_raw = raw.get("variables", {})
    variables: dict[str, object] = dict(variables_raw) if isinstance(variables_raw, dict) else {}

    # Roles
    roles: dict[str, RoleConfig] = {}
    roles_raw = raw.get("roles", {})
    if isinstance(roles_raw, dict):
        for name, rraw in roles_raw.items():
            if not isinstance(rraw, dict):
                rraw = {}
            actions_raw = rraw.get("actions", [])
            actions = [str(a) for a in actions_raw] if isinstance(actions_raw, list) else []
            roles[str(name)] = RoleConfig(
                name=str(name),
                actions=actions,
                extends=str(rraw.get("extends", "")),
                description=str(rraw.get("description", "")),
            )

    # Profiles
    profiles: dict[str, AgentProfileConfig] = {}
    profiles_raw = raw.get("profiles", {})
    if isinstance(profiles_raw, dict):
        for name, praw in profiles_raw.items():
            if not isinstance(praw, dict):
                praw = {}
            allow_raw = praw.get("allow", [])
            allow = [str(a) for a in allow_raw] if isinstance(allow_raw, list) else []
            deny_raw = praw.get("deny", [])
            deny = [str(d) for d in deny_raw] if isinstance(deny_raw, list) else []
            scopes_raw = praw.get("scopes", [])
            scopes = [str(s) for s in scopes_raw] if isinstance(scopes_raw, list) else []
            profiles[str(name)] = AgentProfileConfig(
                name=str(name),
                role=str(praw.get("role", "")),
                allow=allow,
                deny=deny,
                scopes=scopes,
                max_session_duration=int(praw.get("max_session_duration", 3600)),
                default_tier=str(praw.get("default_tier", "autonomous")),
                description=str(praw.get("description", "")),
            )

    # Approval policies
    approval_policies: list[ApprovalPolicyConfig] = []
    ap_raw = raw.get("approval_policies", [])
    if isinstance(ap_raw, list):
        for araw in ap_raw:
            if not isinstance(araw, dict):
                continue
            approval_policies.append(
                ApprovalPolicyConfig(
                    name=str(araw.get("name", "")),
                    condition=str(araw.get("condition", "")),
                    tier=str(araw.get("tier", "soft")),
                    description=str(araw.get("description", "")),
                )
            )

    # Delegation
    deleg_raw = raw.get("delegation", {})
    if not isinstance(deleg_raw, dict):
        deleg_raw = {}
    deleg_rules: list[DelegationRuleConfig] = []
    dr_raw = deleg_raw.get("rules", [])
    if isinstance(dr_raw, list):
        for drule in dr_raw:
            if not isinstance(drule, dict):
                continue
            aa_raw = drule.get("allowed_actions", [])
            allowed_actions = [str(a) for a in aa_raw] if isinstance(aa_raw, list) else []
            deleg_rules.append(
                DelegationRuleConfig(
                    name=str(drule.get("name", "")),
                    allowed_actions=allowed_actions,
                    max_duration=int(drule.get("max_duration", 86400)),
                    require_reason=bool(drule.get("require_reason", False)),
                    description=str(drule.get("description", "")),
                )
            )
    delegation = DelegationConfig(
        enabled=bool(deleg_raw.get("enabled", True)),
        default_duration=int(deleg_raw.get("default_duration", 3600)),
        max_duration=int(deleg_raw.get("max_duration", 86400)),
        rules=deleg_rules,
    )

    # A2A
    a2a_raw = raw.get("a2a", {})
    if not isinstance(a2a_raw, dict):
        a2a_raw = {}
    a2a_policies: list[A2APolicyConfig] = []
    a2ap_raw = a2a_raw.get("policies", [])
    if isinstance(a2ap_raw, list):
        for apraw in a2ap_raw:
            if not isinstance(apraw, dict):
                continue
            a2a_policies.append(
                A2APolicyConfig(
                    name=str(apraw.get("name", "")),
                    from_agent=str(apraw.get("from_agent", "*")),
                    to_agent=str(apraw.get("to_agent", "*")),
                    action=str(apraw.get("action", "*")),
                    effect=str(apraw.get("effect", "allow")),
                    condition=str(apraw.get("condition", "")),
                    description=str(apraw.get("description", "")),
                )
            )
    a2a = A2AConfig(
        default=str(a2a_raw.get("default", "deny")),
        policies=a2a_policies,
    )

    # Sessions
    sess_raw = raw.get("sessions", {})
    if not isinstance(sess_raw, dict):
        sess_raw = {}
    sessions = SessionConfig(
        default_duration=int(sess_raw.get("default_duration", 3600)),
        max_duration=int(sess_raw.get("max_duration", 86400)),
        cleanup_interval=int(sess_raw.get("cleanup_interval", 300)),
    )

    # Audit
    audit_raw = raw.get("audit", {})
    if not isinstance(audit_raw, dict):
        audit_raw = {}
    audit = AuditConfig(
        enabled=bool(audit_raw.get("enabled", True)),
        path=str(audit_raw.get("path", ".agent_auth/audit.jsonl")),
        retention_days=int(audit_raw.get("retention_days", 90)),
    )

    return AuthConfig(
        version=version,
        metadata=metadata,
        variables=variables,
        roles=roles,
        profiles=profiles,
        approval_policies=approval_policies,
        delegation=delegation,
        a2a=a2a,
        sessions=sessions,
        audit=audit,
    )


def validate_config(config: AuthConfig) -> list[str]:
    """Return list of validation errors (empty = valid)."""
    errors: list[str] = []

    # Version
    if config.version not in ("1.0",):
        errors.append(f"Unsupported config version: '{config.version}' (expected '1.0')")

    # Roles — unique names, no circular extends, valid extends refs
    for name, role in config.roles.items():
        if role.extends and role.extends not in config.roles:
            errors.append(f"roles.{name}: extends '{role.extends}' does not exist")

    # Check for circular role inheritance
    for name in config.roles:
        visited: set[str] = set()
        current = name
        while current:
            if current in visited:
                errors.append(
                    f"roles.{name}: circular inheritance detected: "
                    f"{' -> '.join(visited)} -> {current}"
                )
                break
            visited.add(current)
            current = config.roles.get(current, RoleConfig(name="")).extends

    # Profiles — valid role refs, valid tiers
    seen_profiles: set[str] = set()
    for name, profile in config.profiles.items():
        if name in seen_profiles:
            errors.append(f"profiles.{name}: duplicate profile name")
        seen_profiles.add(name)

        if profile.role and profile.role not in config.roles:
            errors.append(f"profiles.{name}: role '{profile.role}' does not exist")

        if profile.default_tier not in VALID_TIERS:
            errors.append(
                f"profiles.{name}: invalid default_tier '{profile.default_tier}', "
                f"expected one of {sorted(VALID_TIERS)}"
            )

        if profile.max_session_duration < 1:
            errors.append(f"profiles.{name}: max_session_duration must be >= 1")

        if profile.max_session_duration > config.sessions.max_duration:
            errors.append(
                f"profiles.{name}: max_session_duration ({profile.max_session_duration}) "
                f"exceeds sessions.max_duration ({config.sessions.max_duration})"
            )

    # Approval policies — unique names, valid tiers
    seen_ap: set[str] = set()
    for i, ap in enumerate(config.approval_policies):
        prefix = f"approval_policies[{i}]"
        if not ap.name:
            errors.append(f"{prefix}: 'name' is required")
        elif ap.name in seen_ap:
            errors.append(f"{prefix}: duplicate approval policy name '{ap.name}'")
        else:
            seen_ap.add(ap.name)

        if ap.tier not in VALID_TIERS:
            errors.append(
                f"{prefix} ({ap.name}): invalid tier '{ap.tier}', "
                f"expected one of {sorted(VALID_TIERS)}"
            )

    # Delegation rules — unique names, valid duration bounds
    seen_dr: set[str] = set()
    for i, rule in enumerate(config.delegation.rules):
        prefix = f"delegation.rules[{i}]"
        if not rule.name:
            errors.append(f"{prefix}: 'name' is required")
        elif rule.name in seen_dr:
            errors.append(f"{prefix}: duplicate delegation rule name '{rule.name}'")
        else:
            seen_dr.add(rule.name)

        if rule.max_duration < 1:
            errors.append(f"{prefix} ({rule.name}): max_duration must be >= 1")

        if rule.max_duration > config.delegation.max_duration:
            errors.append(
                f"{prefix} ({rule.name}): max_duration ({rule.max_duration}) "
                f"exceeds delegation.max_duration ({config.delegation.max_duration})"
            )

    # A2A — valid default, unique policy names, valid effects
    if config.a2a.default not in VALID_A2A_DEFAULTS:
        errors.append(
            f"a2a.default: invalid default '{config.a2a.default}', "
            f"expected one of {sorted(VALID_A2A_DEFAULTS)}"
        )

    seen_a2a: set[str] = set()
    valid_effects = {"allow", "deny"}
    for i, policy in enumerate(config.a2a.policies):
        prefix = f"a2a.policies[{i}]"
        if not policy.name:
            errors.append(f"{prefix}: 'name' is required")
        elif policy.name in seen_a2a:
            errors.append(f"{prefix}: duplicate A2A policy name '{policy.name}'")
        else:
            seen_a2a.add(policy.name)

        if policy.effect not in valid_effects:
            errors.append(
                f"{prefix} ({policy.name}): invalid effect '{policy.effect}', "
                f"expected one of {sorted(valid_effects)}"
            )

    # Session config — valid duration bounds
    if config.sessions.default_duration < 1:
        errors.append("sessions.default_duration must be >= 1")
    if config.sessions.max_duration < 1:
        errors.append("sessions.max_duration must be >= 1")
    if config.sessions.default_duration > config.sessions.max_duration:
        errors.append(
            f"sessions.default_duration ({config.sessions.default_duration}) "
            f"exceeds sessions.max_duration ({config.sessions.max_duration})"
        )

    return errors
