"""Resolution: what an agent may do for a given principal, and why.

    access(agent, principal)?  no -> nothing
    baseline(agent) ∪ grants[agent][role] for each principal role ∪ delegations from the user
    minus deny(agent) and limits (code-declared, config cannot widen them)
    = ResolvedAgent: every capability and every denial with its provenance.

A principal is either a user the agent acts for (``on_behalf_of``) or nobody (``service``):
a service request gets the agent's baseline only, never grants or delegations. See
docs/design/resolution.md.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field

_GLOB = "*?["


def literal_prefix(pattern: str) -> str:
    """The part of a glob before its first wildcard."""
    for i, ch in enumerate(pattern):
        if ch in _GLOB:
            return pattern[:i]
    return pattern


def covers(outer: str, inner: str) -> bool:
    """True only when every action matching ``inner`` provably matches ``outer``.

    Conservative: a wildcard in ``inner`` is never read as a literal character (``read:*`` is
    not covered by ``read:[!s]*``). Covered cases: equal patterns; a literal ``inner`` that
    ``outer`` matches; ``outer`` a literal prefix followed by a single trailing ``*`` and
    ``inner``'s literal prefix starting with it."""
    if outer == inner:
        return True
    if not any(ch in _GLOB for ch in inner):
        return fnmatch.fnmatchcase(inner, outer)
    if outer.endswith("*") and not any(ch in _GLOB for ch in outer[:-1]):
        return literal_prefix(inner).startswith(outer[:-1])
    return False


def denial_matches(action: str, pattern: str) -> bool:
    """Denials and limits match regardless of case: ``DELETE_users`` is still a ``delete_*``.

    As written or folded: folding alone would let ``db:drop_ß`` (folded to two characters)
    escape ``db:drop_?`` and ``cfg:ADMIN`` escape ``cfg:[!a-z]*``."""
    return fnmatch.fnmatchcase(action, pattern) or fnmatch.fnmatchcase(
        action.casefold(), pattern.casefold()
    )


ON_BEHALF_OF = "on_behalf_of"
SERVICE = "service"
IDENTITIES = (ON_BEHALF_OF, SERVICE)


@dataclass(frozen=True)
class Principal:
    """Who an agent acts for."""

    identity: str
    user: str = ""
    roles: frozenset[str] = frozenset()

    @staticmethod
    def for_user(user: str, roles: Iterable[str] = ()) -> Principal:
        if not user:
            raise ValueError("a user principal needs a user name")
        return Principal(ON_BEHALF_OF, user, frozenset(roles))

    @staticmethod
    def service() -> Principal:
        return Principal(SERVICE)

    @property
    def is_service(self) -> bool:
        return self.identity == SERVICE

    def describe(self) -> str:
        if self.is_service:
            return "service"
        roles = f" ({', '.join(sorted(self.roles))})" if self.roles else ""
        return f"user '{self.user}'{roles}"


@dataclass
class ResolvedAgent:
    """Everything an agent may do for a principal, each item with where it came from.

    ``capabilities`` maps an action pattern to its sources: ``baseline``,
    ``grant:<role>``, ``delegation:<id>``. ``denials`` maps a pattern to ``deny`` (the
    profile) or ``limit`` (code). Denials win over capabilities.
    """

    agent: str
    principal: Principal
    access: bool
    access_reason: str
    capabilities: dict[str, list[str]] = field(default_factory=dict)
    denials: dict[str, list[str]] = field(default_factory=dict)
    scopes: list[str] = field(default_factory=list)
    default_tier: str = "autonomous"
    # Agents this resolution was delegated through, outermost first (empty: not delegated).
    chain: list[str] = field(default_factory=list)

    def check(self, action: str) -> tuple[bool, list[str]]:
        """``(allowed, provenance)`` for an action: the denial or capabilities that decide."""
        if not self.access:
            return False, ["access"]
        for pattern, sources in self.denials.items():
            if denial_matches(action, pattern):
                return False, [f"{s}:{pattern}" for s in sources]
        matched = [
            f"{s}:{pattern}"
            for pattern, sources in self.capabilities.items()
            if fnmatch.fnmatchcase(action, pattern)
            for s in sources
        ]
        return bool(matched), matched

    @property
    def fingerprint(self) -> str:
        """A digest of the whole resolution: it changes whenever what the agent may do for
        this principal changes."""
        body = {
            "agent": self.agent,
            "identity": self.principal.identity,
            "user": self.principal.user,
            "roles": sorted(self.principal.roles),
            "access": self.access,
            "capabilities": {k: sorted(v) for k, v in sorted(self.capabilities.items())},
            "denials": {k: sorted(v) for k, v in sorted(self.denials.items())},
            "scopes": sorted(self.scopes),
            "chain": list(self.chain),
        }
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16]

    def attenuate(self, child: ResolvedAgent) -> ResolvedAgent:
        """What ``child`` may do when this agent delegates to it: the intersection of both
        resolutions, for the same principal. A sub-agent never gets more than its parent.

        A pattern is kept when one side's pattern covers the other's: child ``read:docs``
        under parent ``read:*`` keeps ``read:docs``; child ``read:*`` under parent
        ``read:docs`` keeps ``read:docs``. Both sides' denials apply."""
        if child.principal != self.principal:
            raise ValueError("a sub-agent must act for the same principal as its parent")
        kept: dict[str, list[str]] = {}
        if self.access and child.access:
            for c, c_sources in child.capabilities.items():
                for p, p_sources in self.capabilities.items():
                    if covers(p, c):  # the parent's pattern covers the child's
                        narrower = c
                    elif covers(c, p):  # the child's pattern covers the parent's
                        narrower = p
                    else:
                        continue  # no provable overlap: dropped (conservative)
                    sources = kept.setdefault(narrower, [])
                    for src in [*c_sources, *(f"{x}@{self.agent}" for x in p_sources)]:
                        if src not in sources:
                            sources.append(src)
        denials: dict[str, list[str]] = {k: list(v) for k, v in child.denials.items()}
        for pattern, sources in self.denials.items():
            denials.setdefault(pattern, []).extend(f"{x}@{self.agent}" for x in sources)
        if not self.access:
            reason = f"the parent '{self.agent}' has no access: {self.access_reason}"
        else:
            reason = child.access_reason
        access = self.access and child.access
        if self.scopes and child.scopes:
            scopes = [x for x in child.scopes if x in self.scopes]
            if not scopes:  # an empty list would mean "every scope": no overlap is no access
                access = False
                reason = f"'{child.agent}' and '{self.agent}' have no scope in common"
        else:
            scopes = list(child.scopes or self.scopes)
        return ResolvedAgent(
            agent=child.agent,
            principal=child.principal,
            access=access,
            access_reason=reason,
            capabilities=kept,
            denials=denials,
            scopes=scopes,
            default_tier=_stricter(self.default_tier, child.default_tier),
            chain=[*self.chain, self.agent],
        )


_TIERS = {"autonomous": 0, "soft": 1, "strong": 2}


def _stricter(a: str, b: str) -> str:
    return a if _TIERS.get(a, 0) >= _TIERS.get(b, 0) else b


UserRoles = Callable[[str], Iterable[str]]


def resolve(
    agent: str,
    principal: Principal,
    *,
    baseline: Iterable[str],
    deny: Iterable[str],
    access: Iterable[str],
    grants: Mapping[str, Iterable[str]],
    delegations: Iterable[tuple[str, Iterable[str]]] = (),
    limits: Iterable[str] = (),
    scopes: Iterable[str] = (),
    default_tier: str = "autonomous",
    user_permissions: Iterable[str] = (),
    known: bool = True,
) -> ResolvedAgent:
    """Build the ResolvedAgent. ``delegations`` are ``(delegation_id, actions)`` pairs already
    filtered to this agent and this user."""
    allowed_by = list(access)
    user_permissions = list(user_permissions)
    if not known and not (user_permissions and not principal.is_service):
        ok, why = False, f"no profile '{agent}' in the config"
    elif not known:  # 0.1 compatibility: the deprecated union can serve unprofiled agents
        ok, why = True, f"no profile '{agent}': only the deprecated user-permissions union"
    elif not allowed_by:
        ok, why = True, "open to everyone"
    elif principal.is_service:
        ok = SERVICE in allowed_by
        why = "service access" if ok else "the agent is not available as a service"
    else:
        # Roles by name; users only as "user:<name>"; "service" is a keyword. A user named
        # "finance" or "service" never matches a role or the keyword.
        roles = {r for r in principal.roles if r != SERVICE and not r.startswith("user:")}
        hit = sorted(({f"user:{principal.user}"} | roles) & set(allowed_by))
        ok = bool(hit)
        why = (
            f"access via {', '.join(hit)}"
            if ok
            else (f"{principal.describe()} may not use '{agent}'")
        )

    capabilities: dict[str, list[str]] = {}

    def add(pattern: str, source: str) -> None:
        sources = capabilities.setdefault(pattern, [])
        if source not in sources:
            sources.append(source)

    if ok:
        for action in baseline:
            add(action, "baseline")
        if not principal.is_service:
            for role in sorted(principal.roles):
                for action in grants.get(role, ()):
                    add(action, f"grant:{role}")
            for delegation_id, actions in delegations if known else ():
                for action in actions:
                    add(action, f"delegation:{delegation_id}")
            for action in user_permissions:  # deprecated 0.1 union
                add(action, "user_permissions")

    denials: dict[str, list[str]] = {}
    for pattern in deny:
        denials.setdefault(pattern, []).append("deny")
    for pattern in limits:
        denials.setdefault(pattern, []).append("limit")

    return ResolvedAgent(
        agent=agent,
        principal=principal,
        access=ok,
        access_reason=why,
        capabilities=capabilities,
        denials=denials,
        scopes=list(scopes),
        default_tier=default_tier,
    )
