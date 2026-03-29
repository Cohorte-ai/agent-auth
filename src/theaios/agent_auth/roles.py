"""Role resolution with inheritance."""

from __future__ import annotations

from dataclasses import dataclass, field

from theaios.agent_auth.config import ConfigError
from theaios.agent_auth.types import RoleConfig


@dataclass
class ResolvedRole:
    """A fully resolved role with inherited actions."""

    name: str
    actions: set[str] = field(default_factory=set)
    chain: list[str] = field(default_factory=list)


def resolve_role(
    name: str,
    roles: dict[str, RoleConfig],
    _seen: set[str] | None = None,
) -> ResolvedRole:
    """Resolve a role by following the inheritance chain.

    Child roles inherit actions from parents. Child actions are merged
    with parent actions (union).
    """
    if _seen is None:
        _seen = set()

    if name in _seen:
        raise ConfigError([f"Circular role inheritance detected: {' -> '.join(_seen)} -> {name}"])

    if name not in roles:
        raise ConfigError([f"Role '{name}' does not exist"])

    _seen.add(name)
    role = roles[name]

    # Base case: no parent
    if not role.extends:
        return ResolvedRole(
            name=name,
            actions=set(role.actions),
            chain=[name],
        )

    # Recursive: resolve parent first
    parent = resolve_role(role.extends, roles, _seen)

    # Merge: child actions union with parent actions
    merged_actions = parent.actions | set(role.actions)

    return ResolvedRole(
        name=name,
        actions=merged_actions,
        chain=parent.chain + [name],
    )
