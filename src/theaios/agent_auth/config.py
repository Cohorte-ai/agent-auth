"""YAML auth config loader and validation."""

from __future__ import annotations

import difflib
from collections.abc import Iterable, Mapping
from pathlib import Path

import yaml
from theaios.core.expressions import ExpressionError, compile_expression, references
from theaios.core.env import interpolate_env, interpolate_recursive

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


def _interpolate_env(value: str) -> str:
    """Replace ${VAR} placeholders (see theaios.core.env)."""
    return interpolate_env(value)


def _interpolate_recursive(obj: object) -> object:
    """Interpolate env vars in every string of a parsed config."""
    return interpolate_recursive(obj)


def load_config(path: str = "agent_auth.yaml") -> AuthConfig:
    """Load a YAML auth config file, validate, and return typed config."""
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Auth config file not found: {path}")

    if not config_path.is_file():
        raise ConfigError([f"{path} is not a file"])
    try:
        with open(config_path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f"{path}:{mark.line + 1}" if mark is not None else path
        problem = getattr(exc, "problem", None) or str(exc)
        raise ConfigError([f"{where}: YAML syntax error: {problem}"]) from None
    except UnicodeDecodeError:
        raise ConfigError([f"{path} is not UTF-8 text"]) from None

    if not isinstance(raw, dict):
        raise ConfigError(["Auth config file must be a YAML mapping"])

    errors = shape_errors(raw)
    if errors:
        raise ConfigError(errors)

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


# Every key the parser reads, per place in the file. Anything else is a typo or a key from
# another tool (guardrails' `from:`/`to:`), and used to be dropped without a word.
_STR, _INT, _BOOL, _STRLIST = (
    "a string",
    "an integer",
    "true or false (unquoted)",
    "a list of strings",
)
_TOP_KEYS = {
    "version",
    "metadata",
    "variables",
    "roles",
    "profiles",
    "approval_policies",
    "delegation",
    "a2a",
    "sessions",
    "audit",
}
_MAPPINGS = ("metadata", "variables", "roles", "profiles", "delegation", "a2a", "sessions", "audit")
_ROLE = {"actions": _STRLIST, "extends": _STR, "description": _STR}
_PROFILE = {
    "role": _STR,
    "allow": _STRLIST,
    "deny": _STRLIST,
    "scopes": _STRLIST,
    "max_session_duration": _INT,
    "default_tier": _STR,
    "description": _STR,
}
_APPROVAL = {"name": _STR, "condition": _STR, "tier": _STR, "description": _STR}
_DELEGATION = {"enabled": _BOOL, "default_duration": _INT, "max_duration": _INT, "rules": None}
_DELEGATION_RULE = {
    "name": _STR,
    "allowed_actions": _STRLIST,
    "max_duration": _INT,
    "require_reason": _BOOL,
    "description": _STR,
}
_A2A = {"default": _STR, "policies": None}
_A2A_POLICY = {
    "name": _STR,
    "from_agent": _STR,
    "to_agent": _STR,
    "action": _STR,
    "effect": _STR,
    "condition": _STR,
    "description": _STR,
}
_SESSIONS = {"default_duration": _INT, "max_duration": _INT, "cleanup_interval": _INT}
_AUDIT = {"enabled": _BOOL, "path": _STR, "retention_days": _INT}


def _type_ok(value: object, kind: str) -> bool:
    if kind == _STR:
        return isinstance(value, str)
    if kind == _INT:
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == _BOOL:
        return isinstance(value, bool)
    return isinstance(value, list) and all(isinstance(x, str) for x in value)


def _check_mapping(where: str, raw: object, spec: Mapping[str, str | None]) -> list[str]:
    if not isinstance(raw, dict):
        return [f"{where}: must be a mapping, got {type(raw).__name__}"]
    errors = []
    for key, value in raw.items():
        if key not in spec:
            errors.append(f"{where}: unknown key '{key}'{_did_you_mean(str(key), spec)}")
            continue
        kind = spec[key]
        if kind is not None and value is not None and not _type_ok(value, kind):
            errors.append(f"{where}: '{key}' must be {kind}, got {type(value).__name__}")
    return errors


def _check_list(where: str, raw: object, spec: Mapping[str, str | None]) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        return [f"{where}: must be a list (each entry starting with '-'), got {type(raw).__name__}"]
    errors = []
    for i, entry in enumerate(raw):
        label = f"{where}[{i}]"
        if isinstance(entry, dict) and "name" in entry:
            label += f" ({entry['name']})"
        errors += _check_mapping(label, entry, spec)
    return errors


def shape_errors(raw: dict[object, object]) -> list[str]:
    """Structural problems that parsing would otherwise hide: unknown keys, sections of the
    wrong type (``approval_policies`` written as a mapping loaded zero policies), values of the
    wrong type (``condition: 42``). Each used to load silently and change what the config does."""
    errors = [
        f"config: unknown key '{key}'{_did_you_mean(str(key), _TOP_KEYS)}"
        for key in raw
        if key not in _TOP_KEYS
    ]
    for key in _MAPPINGS:
        if raw.get(key) is not None and not isinstance(raw[key], dict):
            errors.append(f"'{key}' must be a mapping, got {type(raw[key]).__name__}")
    for name, role in _items(raw.get("roles")):
        errors += _check_mapping(f"roles.{name}", role, _ROLE)
    for name, profile in _items(raw.get("profiles")):
        errors += _check_mapping(f"profiles.{name}", profile, _PROFILE)
    errors += _check_list("approval_policies", raw.get("approval_policies"), _APPROVAL)
    delegation = raw.get("delegation")
    if isinstance(delegation, dict):
        errors += _check_mapping("delegation", delegation, _DELEGATION)
        errors += _check_list("delegation.rules", delegation.get("rules"), _DELEGATION_RULE)
    a2a = raw.get("a2a")
    if isinstance(a2a, dict):
        errors += _check_mapping("a2a", a2a, _A2A)
        errors += _check_list("a2a.policies", a2a.get("policies"), _A2A_POLICY)
    if isinstance(raw.get("sessions"), dict):
        errors += _check_mapping("sessions", raw["sessions"], _SESSIONS)
    if isinstance(raw.get("audit"), dict):
        errors += _check_mapping("audit", raw["audit"], _AUDIT)
    return errors


def _items(section: object) -> list[tuple[object, object]]:
    return list(section.items()) if isinstance(section, dict) else []


# Keys from a neighbouring library or a common guess, mapped to the right key here. Checked
# before fuzzy matching, which can suggest something harmful (`condition` -> `description`
# would leave a rule with no condition, matching everything).
_ALIASES = {
    "when": "condition",
    "if": "condition",
    "from": "from_agent",
    "to": "to_agent",
    "source": "from_agent",
    "target": "to_agent",
}


def _did_you_mean(name: str, known: Iterable[str]) -> str:
    options = list(known)
    if _ALIASES.get(name) in options:
        return f" (did you mean '{_ALIASES[name]}'?)"
    close = difflib.get_close_matches(name, options, n=1)
    if not close and name:  # `from` for `from_agent`
        close = [k for k in options if k.startswith(name + "_")][:1]
    return f" (did you mean '{close[0]}'?)" if close else ""


def condition_errors(condition: str, variables: Iterable[str]) -> list[str]:
    """Problems in a policy condition: a syntax error, an undefined ``$variable``, or
    ``matches`` (agent-auth has no matchers). Each would make the condition fail on every
    evaluation."""
    if not isinstance(condition, str):
        return [f"condition must be a string, got {type(condition).__name__}"]
    try:
        refs = references(compile_expression(condition))
    except ExpressionError as exc:
        return [f"invalid condition: {exc}"]
    known = set(variables)
    errors = [
        f"condition uses undefined variable '${name}'{_did_you_mean(name, known)}"
        for name in sorted(refs.variables - known)
    ]
    errors += [
        f"condition uses 'matches {name}', but agent-auth has no matchers"
        for name in sorted(refs.matchers)
    ]
    return errors


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

        errors.extend(
            f"{prefix} ({ap.name}): {e}" for e in condition_errors(ap.condition, config.variables)
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

        errors.extend(
            f"{prefix} ({policy.name}): {e}"
            for e in condition_errors(policy.condition, config.variables)
        )

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
