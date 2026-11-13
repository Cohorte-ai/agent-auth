"""Authorization engine.

Evaluates auth requests against config: profiles, roles, sessions,
delegations, approval policies, and A2A rules.
Returns an AuthDecision for every request.
"""

from __future__ import annotations

import asyncio
import threading
import unicodedata
import dataclasses
from datetime import datetime
from dataclasses import dataclass
import fnmatch
import time
import warnings
from collections.abc import Iterable, Mapping, Sequence
from typing import Callable, Protocol

from theaios.agent_auth.a2a import A2AEvaluator
from theaios.agent_auth.approval import ApprovalEvaluator
from theaios.agent_auth.audit import AuditLog
from theaios.agent_auth.config import ConfigError, validate_config
from theaios.agent_auth.delegation import DelegationManager
from theaios.agent_auth.profiles import ResolvedProfile, check_scope, resolve_profile
from theaios.agent_auth.roles import resolve_role
from theaios.agent_auth.resolution import (
    IDENTITIES,
    ON_BEHALF_OF,
    SERVICE,
    Principal,
    ResolvedAgent,
    denial_matches,
    resolve,
)
from theaios.agent_auth import tokens
from theaios.agent_auth.sessions import SessionManager
from theaios.agent_auth.types import (
    AuthConfig,
    AuthDecision,
    AuthRequest,
    DelegationGrant,
    Session,
)


class UserPermissionsProvider(Protocol):
    """Protocol for external user permission lookups.

    Implement this to integrate with your existing IAM / user database.
    """

    def get_user_actions(self, user: str) -> set[str]:
        """Return the set of actions a user is allowed to perform."""
        ...


class AuthEngine:
    """Authorization engine for agent-specific IAM.

    8-step authorization pipeline:
    1. Validate session (if session_id provided)
    2. Resolve agent profile
    3. Check profile deny list
    4. Check profile allow list
    5. Check delegations
    6. Check user permissions (if provider configured)
    7. Evaluate A2A policies (if target_agent provided)
    8. Evaluate approval policies

    Parameters
    ----------
    config : AuthConfig
        A parsed config from ``load_config()``.
    user_permissions_provider : UserPermissionsProvider, optional
        External provider for user permission lookups.
    """

    def __init__(
        self,
        config: AuthConfig,
        user_permissions_provider: UserPermissionsProvider
        | Callable[[str], set[str]]
        | None = None,
        *,
        user_roles: Callable[[str], Iterable[str]] | None = None,
        limits: Mapping[str, Iterable[str]] | None = None,
        token_key: bytes | Sequence[bytes] | None = None,
    ) -> None:
        # Same checks as load_config, so a config built in code cannot skip them.
        errors = validate_config(config)
        if errors:
            raise ConfigError(errors)
        self._config = config

        # Wrap callable into protocol-compatible interface
        if user_permissions_provider is None:
            self._user_provider: UserPermissionsProvider | None = None
        elif hasattr(user_permissions_provider, "get_user_actions"):
            self._user_provider = user_permissions_provider  # noqa: E501
        elif callable(user_permissions_provider):
            self._user_provider = _CallableProvider(user_permissions_provider)
        else:
            self._user_provider = None

        # Resolve roles
        self._resolved_roles = {name: resolve_role(name, config.roles) for name in config.roles}

        # Resolve profiles
        self._profiles: dict[str, ResolvedProfile] = {}
        for name in config.profiles:
            self._profiles[name] = resolve_profile(name, config.profiles, config.roles)

        # Approval evaluator
        self._approval = ApprovalEvaluator(config.approval_policies, config.variables)

        # A2A evaluator
        self._a2a = A2AEvaluator(config.a2a, config.variables)

        # Session manager
        self._sessions = SessionManager(path=_sibling(config.audit.path, "sessions"))

        # Delegation manager
        self._delegations = DelegationManager(
            config=config.delegation, path=_sibling(config.audit.path, "delegations")
        )

        # Audit log
        self._audit = AuditLog(path=config.audit.path) if config.audit.enabled else None

        # Resolution (0.2): principal roles from the application, code-declared limits that no
        # config can widen, separation of duties, signed tokens.
        self._user_roles = user_roles
        self._limits = _check_limits(limits, config)
        if token_key is not None:
            tokens.check_keys(token_key)
        self._token_key = token_key
        self._sod_done: dict[tuple[str, str, str], set[str]] = {}
        self._sod_lock = threading.Lock()
        self._warned_union: set[tuple[str, str]] = set()

    @property
    def config(self) -> AuthConfig:
        """The loaded auth configuration."""
        return self._config

    def authorize(
        self, request: AuthRequest, *, resolved: ResolvedAgent | None = None
    ) -> AuthDecision:
        """Authorize a request: decide, log it, and record it for separation of duties.

        Pass ``resolved`` to decide against a given resolution instead of resolving afresh:
        the attenuated resolution of a sub-agent (``delegate``), or the one a verified token
        carries (``verify_token``). Approval tiers, scopes and separation of duties still
        apply."""
        if self._config.separation_of_duties:
            with self._sod_lock:  # the check and the record must not interleave
                return self._authorize(request, record=True, given=resolved)
        return self._authorize(request, record=True, given=resolved)

    def explain(
        self, request: AuthRequest, *, resolved: ResolvedAgent | None = None
    ) -> AuthDecision:
        """The decision ``authorize`` would make, with its provenance, without logging or
        recording anything."""
        return self._authorize(request, record=False, given=resolved)

    def _authorize(
        self, request: AuthRequest, *, record: bool, given: ResolvedAgent | None = None
    ) -> AuthDecision:
        """Authorize a request through the 8-step pipeline.

        Parameters
        ----------
        request : AuthRequest
            The authorization request to evaluate.

        Returns
        -------
        AuthDecision
            The authorization decision.
        """
        start = time.perf_counter()

        # Step 1: Validate session
        if request.session_id:
            session = self._sessions.validate(request.session_id)
            if session is None:
                decision = AuthDecision(
                    allowed=False,
                    reason="Invalid or expired session",
                    evaluation_time_ms=(time.perf_counter() - start) * 1000,
                )
                return self._done(request, decision, record)

            # Verify session matches request
            if session.agent != request.agent:
                decision = AuthDecision(
                    allowed=False,
                    reason=f"Session agent mismatch: expected '{session.agent}', "
                    f"got '{request.agent}'",
                    evaluation_time_ms=(time.perf_counter() - start) * 1000,
                )
                return self._done(request, decision, record)

            if session.user and session.user != request.user:
                decision = AuthDecision(
                    allowed=False,
                    reason=f"Session user mismatch: expected '{session.user}', "
                    f"got '{request.user}'",
                    evaluation_time_ms=(time.perf_counter() - start) * 1000,
                )
                return self._done(request, decision, record)
            # A session bound to a scope binds its requests: a request without a scope takes
            # the session's; a request for another scope is refused.
            if session.scope:
                # Inherit only a literal scope: a pattern ("project:*") is not a value, and a
                # request without a scope keeps 0.1 behaviour (no scope check).
                if not request.scope and not any(ch in "*?[" for ch in session.scope):
                    request = dataclasses.replace(request, scope=session.scope)
                if request.scope and not fnmatch.fnmatchcase(request.scope, session.scope):
                    return self._done(
                        request,
                        AuthDecision(
                            allowed=False,
                            reason=f"Scope '{request.scope}' is outside the session's scope "
                            f"'{session.scope}'",
                            evaluation_time_ms=(time.perf_counter() - start) * 1000,
                            provenance=["scope"],
                        ),
                        record,
                    )

        # Names a pattern is matched against must mean one thing: refuse what a tool could
        # trim, normalise or re-case into something a pattern did not see.
        bad = [
            (what, name)
            for what, name in (("action", request.action), ("target agent", request.target_agent))
            if (what == "action" or name) and not _plain_name(name or "")  # no target: fine
        ]
        if bad:
            what, name = bad[0]
            return self._done(
                request,
                AuthDecision(
                    allowed=False,
                    reason=f"Invalid {what} {name!r}: empty, surrounded by spaces, or "
                    "with control, invisible, look-alike or case-unstable characters",
                    evaluation_time_ms=(time.perf_counter() - start) * 1000,
                    provenance=["action" if what == "action" else "target_agent"],
                ),
                record,
            )

        # Scopes are literal values: a request scope with wildcards would match profile patterns
        # as text ("project:*" against "project:[!s]*").
        if any(ch in "*?[" for ch in request.scope):
            return self._done(
                request,
                AuthDecision(
                    allowed=False,
                    reason=f"Invalid scope {request.scope!r}: a request scope is a value, not a "
                    "pattern",
                    evaluation_time_ms=(time.perf_counter() - start) * 1000,
                    provenance=["scope"],
                ),
                record,
            )

        # Step 2: Who is the agent acting for? One identity, never mixed.
        if request.identity not in IDENTITIES:
            return self._done(
                request,
                AuthDecision(
                    allowed=False,
                    reason=f"Unknown identity '{request.identity}' (expected "
                    "'on_behalf_of' or 'service')",
                    evaluation_time_ms=(time.perf_counter() - start) * 1000,
                ),
                record,
            )
        if request.identity == SERVICE and request.user:
            return self._done(
                request,
                AuthDecision(
                    allowed=False,
                    reason="A service request acts for no one: it must not carry a user",
                    evaluation_time_ms=(time.perf_counter() - start) * 1000,
                ),
                record,
            )
        profile = self._profiles.get(request.agent)
        try:
            principal = self._principal(request)
        except Exception as exc:  # noqa: BLE001 - the identity provider failed: fail closed
            return self._done(
                request,
                AuthDecision(
                    allowed=False,
                    reason=f"Could not get the roles of '{request.user}' (user_roles failed: "
                    f"{type(exc).__name__}: {exc})",
                    evaluation_time_ms=(time.perf_counter() - start) * 1000,
                    provenance=["access"],
                ),
                record,
            )
        if given is not None and (
            given.agent != request.agent
            or given.principal.identity != principal.identity
            or given.principal.user != principal.user
        ):
            return self._done(
                request,
                AuthDecision(
                    allowed=False,
                    reason=f"The resolution passed is for '{given.agent}' acting for "
                    f"{given.principal.describe()}, not for this request",
                    evaluation_time_ms=(time.perf_counter() - start) * 1000,
                    provenance=["access"],
                ),
                record,
            )
        if given is not None:
            # A resolution is a snapshot: re-derive it now (revocations, role changes, policy
            # edits) and refuse it if it no longer matches, as verify_token does for tokens.
            fresh = self._rederive([*given.chain, request.agent], principal)
            if fresh.fingerprint != given.fingerprint:
                return self._done(
                    request,
                    AuthDecision(
                        allowed=False,
                        reason="The resolution passed is stale: what the agent may do changed "
                        "since it was derived (revocation, roles, policy); derive it again",
                        evaluation_time_ms=(time.perf_counter() - start) * 1000,
                        provenance=["access"],
                    ),
                    record,
                )
            resolved = fresh
        else:
            resolved = self.resolve(request.agent, principal)

        # Step 3: Access, denials (profile deny, code limits) and scope
        allowed, provenance = resolved.check(request.action)
        if not resolved.access:
            return self._done(
                request,
                AuthDecision(
                    allowed=False,
                    reason=f"Action '{request.action}' not authorized for agent "
                    f"'{request.agent}': {resolved.access_reason}"
                    if request.agent not in self._config.profiles
                    else f"Access denied: {resolved.access_reason}",
                    evaluation_time_ms=(time.perf_counter() - start) * 1000,
                    provenance=["access"],
                ),
                record,
            )
        if provenance and not allowed:
            head = provenance[0].split(":", 1)[0]
            source, _, owner = head.partition("@")
            if source == "limit":
                reason = f"Action '{request.action}' is blocked by a limit set in code"
            elif owner:
                reason = (
                    f"Action '{request.action}' denied by profile '{owner}', which delegated "
                    f"to '{request.agent}'"
                )
            else:
                name = profile.name if profile else request.agent
                reason = f"Action '{request.action}' denied by profile '{name}'"
            return self._done(
                request,
                AuthDecision(
                    allowed=False,
                    reason=reason,
                    evaluation_time_ms=(time.perf_counter() - start) * 1000,
                    provenance=provenance,
                ),
                record,
            )
        scope_denied = bool(
            request.scope
            and (
                (profile is not None and not check_scope(profile, request.scope))
                or (
                    resolved.scopes
                    and not any(fnmatch.fnmatchcase(request.scope, x) for x in resolved.scopes)
                )
            )
        )
        if scope_denied:
            return self._done(
                request,
                AuthDecision(
                    allowed=False,
                    reason=f"Scope '{request.scope}' not allowed for '{request.agent}'",
                    evaluation_time_ms=(time.perf_counter() - start) * 1000,
                    provenance=["scope"],
                ),
                record,
            )

        # Steps 4-6: baseline, grants, the user's delegations and the deprecated
        # user-permissions union are all in the resolution.
        action_allowed = allowed
        if action_allowed and {x.split(":", 1)[0].split("@")[0] for x in provenance} == {
            "user_permissions"
        }:
            self._warn_union(request)
        delegation_id = next(
            (x.split(":")[1] for x in provenance if x.startswith("delegation:")), None
        )
        delegation_grant: DelegationGrant | None = next(
            (
                g
                for g in self._delegations.list_active(agent=request.agent)
                if delegation_id and g.delegation_id == delegation_id
            ),
            None,
        )

        # Separation of duties: the same principal may not do two conflicting actions on the
        # same resource.
        if action_allowed:
            conflict = self._sod_conflict(request)
            if conflict is not None:
                return self._done(
                    request,
                    AuthDecision(
                        allowed=False,
                        reason=conflict,
                        evaluation_time_ms=(time.perf_counter() - start) * 1000,
                        provenance=["separation_of_duties"],
                    ),
                    record,
                )

        # Step 7: Check A2A policies. A sub-agent's resolution (``delegate``) carries the agent
        # that handed it the work: that hand-off must be allowed too, for this action.
        if given is not None and given.chain:
            hops = [*given.chain, request.agent]
            for src, dst in zip(hops, hops[1:]):
                ok, why = self._a2a.evaluate(
                    from_agent=src,
                    to_agent=dst,
                    action=request.action,
                    context=self._condition_context(request),
                )
                if not ok:
                    return self._done(
                        request,
                        AuthDecision(
                            allowed=False,
                            reason=f"{why} ('{src}' delegated to '{dst}')",
                            evaluation_time_ms=(time.perf_counter() - start) * 1000,
                            provenance=["a2a"],
                        ),
                        record,
                    )
        if request.target_agent:
            a2a_allowed, a2a_reason = self._a2a.evaluate(
                from_agent=request.agent,
                to_agent=request.target_agent,
                action=request.action,
                context=self._condition_context(request),
            )
            if not a2a_allowed:
                decision = AuthDecision(
                    allowed=False,
                    reason=a2a_reason,
                    evaluation_time_ms=(time.perf_counter() - start) * 1000,
                )
                return self._done(request, decision, record)

        # If action is not allowed by any source, deny
        if not action_allowed:
            decision = AuthDecision(
                allowed=False,
                reason=f"Action '{request.action}' not authorized for agent "
                f"'{request.agent}'"
                + (
                    f" within what '{resolved.chain[-1]}' delegated to it"
                    if resolved.chain
                    else self._grant_hint(request, principal)
                ),
                evaluation_time_ms=(time.perf_counter() - start) * 1000,
            )
            return self._done(request, decision, record)

        # Step 8: Evaluate approval policies
        default_tier = resolved.default_tier
        # Metadata keys are reachable both as `metadata.key` (as documented) and, for
        # compatibility, at the top level; the request's own fields always win, so metadata
        # cannot overwrite the resource or user a policy checks.
        # Request fields (identity included) win over metadata.
        eval_context: dict[str, object] = self._condition_context(request)

        tier, approval_policy, eval_error = self._approval.explain(
            request.action, eval_context, default_tier
        )
        # Conditions ignore case (ApprovalEvaluator). A sub-agent inherits every approval its
        # chain would need: the policies are evaluated as each agent of the chain too, and the
        # strictest tier wins.
        for ancestor in resolved.chain:
            t2, p2, e2 = self._approval.explain(
                request.action, {**eval_context, "agent": ancestor}, default_tier
            )
            if _TIER_ORDER.get(t2, 0) > _TIER_ORDER.get(tier, 0):
                tier, approval_policy, eval_error = t2, f"{p2}@{ancestor}" if p2 else "", e2

        requires_approval = tier in ("soft", "strong")
        if not requires_approval:
            approval_policy = ""

        reason = ""
        sources = [x.split(":", 1)[0] for x in provenance]
        if "baseline" in sources and profile:
            reason = f"Allowed by profile '{profile.name}'"
        elif any(x.startswith("grant:") for x in provenance):
            role = next(x for x in provenance if x.startswith("grant:")).split(":")[1]
            role, _, owner = role.partition("@")
            reason = f"Allowed by the '{role}' grant on '{owner or request.agent}'" + (
                f", delegated to '{request.agent}'" if owner else ""
            )
        elif delegation_grant is not None:
            reason = f"Delegated by user '{delegation_grant.from_user}'"
        elif profile and "user_permissions" not in sources:
            reason = f"Allowed by profile '{profile.name}'"
        else:
            reason = "Allowed by user permissions"

        if requires_approval:
            reason += f" (requires {tier} approval"
            if approval_policy:
                reason += f": {approval_policy}"
            if eval_error:
                reason += f"; condition could not be evaluated ({eval_error}), treated as matched"
            reason += ")"

        decision = AuthDecision(
            allowed=True,
            tier=tier,
            reason=reason,
            requires_approval=requires_approval,
            approval_policy=approval_policy,
            evaluation_time_ms=(time.perf_counter() - start) * 1000,
            provenance=provenance,
        )
        if record:
            self._sod_record(request)
        return self._done(request, decision, record)

    # Resolution ------------------------------------------------------------------------

    def _principal(self, request: AuthRequest) -> Principal:
        if request.identity == SERVICE:
            return Principal.service()
        roles: list[str] = []
        if self._user_roles and request.user:
            got = self._user_roles(request.user)
            if got is None or isinstance(got, (str, bytes)):
                raise TypeError(f"user_roles must return a collection of role names, got {got!r}")
            roles = [str(r) for r in got]
        return Principal(ON_BEHALF_OF, request.user, frozenset(roles))

    def principal(self, user: str = "", *, service: bool = False) -> Principal:
        """The principal for a user (roles from ``user_roles``) or for service requests."""
        if service:
            if user:
                raise ValueError("a service principal acts for no one: do not pass a user")
            return Principal.service()
        return self._principal(AuthRequest(agent="", user=user, action=""))

    def resolve(self, agent: str, principal: Principal) -> ResolvedAgent:
        """What ``agent`` may do for ``principal`` right now, with provenance."""
        cfg = self._config.profiles.get(agent)
        profile = self._profiles.get(agent)
        delegations: list[tuple[str, list[str]]] = []
        user_permissions: list[str] = []
        if not principal.is_service and principal.user:
            delegations = [
                (g.delegation_id, list(g.actions))
                for g in self._delegations.list_active(agent=agent)
                if g.from_user == principal.user
                and self._delegation_still_valid(g, principal.roles)
            ]
            if self._user_provider is not None and (
                self._config.resolution.user_permissions == "union"
            ):
                user_permissions = sorted(self._user_provider.get_user_actions(principal.user))
        limits = [*self._limits.get("*", []), *self._limits.get(agent, [])]
        return resolve(
            agent,
            principal,
            baseline=sorted(profile.effective_actions) if profile else [],
            deny=sorted(profile.denied_actions) if profile else [],
            access=cfg.access if cfg else [],
            grants=cfg.grants if cfg else {},
            delegations=delegations,
            limits=limits,
            scopes=profile.allowed_scopes if profile else [],
            default_tier=profile.default_tier if profile else "autonomous",
            user_permissions=user_permissions,
            known=agent in self._config.profiles,
        )

    def _delegation_still_valid(
        self, grant: DelegationGrant, roles: frozenset[str] | None = None
    ) -> bool:
        """A delegation applies only while delegation is enabled and the *current* rules would
        still accept it: disabling delegation or tightening a rule takes effect at once."""
        try:
            granted = datetime.fromisoformat(grant.granted_at)
            expires = datetime.fromisoformat(grant.expires_at)
            duration = int((expires - granted).total_seconds())
        except (TypeError, ValueError):
            return False
        if roles is None:
            try:
                roles = self._principal(
                    AuthRequest(agent=grant.to_agent, user=grant.from_user, action="")
                ).roles
            except Exception:  # noqa: BLE001 - unknown roles: rules that need roles cannot pass
                roles = frozenset()
        return not self._delegations.validate_rule(
            list(grant.actions), duration, grant.reason, sorted(roles)
        )

    def _warn_union(self, request: AuthRequest) -> None:
        key = (request.agent, request.action)
        if key in self._warned_union:
            return
        self._warned_union.add(key)
        warnings.warn(
            f"agent-auth: '{request.agent}' was allowed '{request.action}' for "
            f"'{request.user}' only because the user may do it (user_permissions_provider "
            "union, deprecated). Add it to the agent's grants for that user's role, or set "
            "resolution.user_permissions: ignore. The union is removed in 1.0.",
            FutureWarning,
            stacklevel=4,
        )

    def _grant_hint(self, request: AuthRequest, principal: Principal) -> str:
        """Why a grant did not apply, when that is the likely mistake."""
        cfg = self._config.profiles.get(request.agent)
        if principal.is_service or cfg is None:
            return ""
        roles = [
            r
            for r, actions in cfg.grants.items()
            if any(fnmatch.fnmatchcase(request.action, a) for a in actions)
        ]
        if not roles:
            return ""
        if not principal.roles:
            source = (
                "no user_roles was given to the engine"
                if self._user_roles is None
                else ("user_roles returned none")
            )
            return f" (granted to roles {', '.join(sorted(roles))}; '{request.user}' has no roles: {source})"
        return (
            f" (granted to roles {', '.join(sorted(roles))}; '{request.user}' has "
            f"{', '.join(sorted(principal.roles))})"
        )

    def preview(self, agent: str, principal: Principal) -> ResolvedAgent:
        """Same as :meth:`resolve`: what an administrator sees before granting access."""
        return self.resolve(agent, principal)

    def _rederive(self, agents: list[str], principal: Principal) -> ResolvedAgent:
        """Resolve a delegation chain from scratch: the first agent, attenuated by each next,
        with the A2A reach of each hop."""
        if len(agents) > MAX_CHAIN:
            raise tokens.TokenError(f"delegation chains are limited to {MAX_CHAIN} agents")
        current = self.resolve(agents[0], principal)
        for agent in agents[1:]:
            current = self._delegate(current, agent)
        return current

    def delegate(self, parent: ResolvedAgent, child_agent: str) -> ResolvedAgent:
        if len(parent.chain) + 1 >= MAX_CHAIN:
            raise ValueError(f"delegation chains are limited to {MAX_CHAIN} agents")
        return self._delegate(parent, child_agent)

    def _delegate(self, parent: ResolvedAgent, child_agent: str) -> ResolvedAgent:
        """What ``child_agent`` may do when ``parent`` hands it work: the intersection of the
        child's own resolution and the parent's, for the same principal."""
        child = parent.attenuate(self.resolve(child_agent, parent.principal))
        if not self._a2a.may_reach(parent.agent, child_agent):
            child.access = False
            child.access_reason = (
                f"A2A rules do not let '{parent.agent}' hand work to '{child_agent}'"
            )
            child.capabilities = {}
        return child

    def issue_token(self, resolved: ResolvedAgent, audience: str, ttl: int = 300) -> str:
        """A short-lived token for ``audience`` (the service that will verify it)."""
        return tokens.issue(resolved, audience, ttl, tokens.check_key(self._token_key))

    def verify_token(self, token: str, audience: str, *, leeway: int = 0) -> VerifiedToken:
        """Check a token and return its claims with the agent's *current* resolution. Refuses
        a token whose resolution changed since it was issued (policy edit, roles, revoked
        delegation)."""
        claims = tokens.decode(token, audience, tokens.check_keys(self._token_key), leeway=leeway)
        if claims.identity == SERVICE:
            principal = Principal.service()
        else:
            principal = self._principal(
                AuthRequest(agent=claims.agent, user=claims.user, action="")
            )
        current = self._rederive([*claims.chain, claims.agent], principal)
        if current.fingerprint != claims.fingerprint:
            raise tokens.TokenError(
                "the agent's permissions differ from when the token was issued: they changed "
                "(policy, roles, delegations), or this verifier's config, limits or user_roles "
                "differ from the issuer's; issue a new one"
            )
        return VerifiedToken(claims, current)

    @staticmethod
    def _sod_key(request: AuthRequest, rule: str) -> tuple[str, str, str]:
        # Case and surrounding spaces do not make a different resource; a missing resource is
        # one shared resource (over-restrictive rather than skipped).
        return (rule, request.user.strip().casefold(), request.resource.strip().casefold())

    def _sod_conflict(self, request: AuthRequest) -> str | None:
        action = request.action.casefold()
        for rule in self._config.separation_of_duties:
            if not any(denial_matches(request.action, a) for a in rule.actions):
                continue
            done = self._sod_done.get(self._sod_key(request, rule.name), set())
            others = sorted(a for a in done if a != action)
            if others:
                return (
                    f"Separation of duties ('{rule.name}'): '{request.user or 'service'}' "
                    f"already did {', '.join(others)} on '{request.resource}'"
                )
        return None

    def _sod_record(self, request: AuthRequest) -> None:
        action = request.action.casefold()
        for rule in self._config.separation_of_duties:
            if any(denial_matches(request.action, a) for a in rule.actions):
                self._sod_done.setdefault(self._sod_key(request, rule.name), set()).add(action)

    def _condition_context(self, request: AuthRequest) -> dict[str, object]:
        """What A2A and approval conditions see: metadata keys at the top level and under
        ``metadata``, with the request's own fields always winning."""
        context: dict[str, object] = dict(request.metadata)
        context.update(
            {
                "agent": request.agent,
                "user": request.user,
                "action": request.action,
                "resource": request.resource,
                "scope": request.scope,
                "identity": request.identity,
                "metadata": dict(request.metadata),
            }
        )
        return context

    def _done(self, request: AuthRequest, decision: AuthDecision, record: bool) -> AuthDecision:
        if record:
            self._log(request, decision)
        return decision

    async def authorize_async(
        self, request: AuthRequest, *, resolved: ResolvedAgent | None = None
    ) -> AuthDecision:
        """Async version of authorize. Same logic, awaitable for framework adapters."""
        return await asyncio.to_thread(self.authorize, request, resolved=resolved)

    def create_session(
        self,
        agent: str,
        user: str,
        scope: str = "",
        duration: int | None = None,
    ) -> Session:
        """Create a new session for an agent.

        Uses profile max_session_duration if no duration specified.
        """
        if duration is None:
            profile = self._profiles.get(agent)
            if profile:
                duration = profile.max_session_duration
            else:
                duration = self._config.sessions.default_duration

        # Clamp to max
        duration = min(duration, self._config.sessions.max_duration)

        return self._sessions.create(agent, user, scope, duration)

    def revoke_session(self, session_id: str) -> bool:
        """Revoke an active session."""
        return self._sessions.revoke(session_id)

    def create_delegation(
        self,
        from_user: str,
        to_agent: str,
        actions: list[str],
        duration: int | None = None,
        reason: str = "",
    ) -> DelegationGrant:
        """Create a delegation from a user to an agent. Refused for an agent with no profile,
        and checked against the delegation rules with the user's roles."""
        if to_agent not in self._config.profiles:
            raise ValueError(f"no profile '{to_agent}' in the config: cannot delegate to it")
        roles = self._principal(AuthRequest(agent=to_agent, user=from_user, action="")).roles
        return self._delegations.create(
            from_user, to_agent, actions, duration, reason, roles=sorted(roles)
        )

    def revoke_delegation(self, delegation_id: str) -> bool:
        """Revoke an active delegation."""
        return self._delegations.revoke(delegation_id)

    def _log(self, request: AuthRequest, decision: AuthDecision) -> None:
        """Write an audit log entry if auditing is enabled."""
        if self._audit is not None:
            self._audit.write(request, decision, self._config)


def _sibling(audit_path: str, kind: str) -> str:
    """Where sessions or delegations live next to the audit log. Never the audit file itself:
    a path without "audit.jsonl" used to make all three share one file."""
    if "audit.jsonl" in audit_path:
        return audit_path.replace("audit.jsonl", f"{kind}.jsonl")
    return f"{audit_path}.{kind}.jsonl"


def _plain_name(name: str) -> bool:
    """A name patterns can be matched against: not empty, no surrounding spaces, NFKC-stable,
    no control or format characters, and the same length and fold under every case mapping
    (refuses dotless ı, ß, İ and the like: "drop_ındex" upper-cases to DROP_INDEX, and a
    "?" in a pattern counts characters that case mapping splits or merges)."""
    return (
        bool(name)
        and name == name.strip()
        and unicodedata.normalize("NFKC", name) == name
        and not any(unicodedata.category(ch) in ("Cc", "Cf") for ch in name)
        and name.upper().casefold() == name.casefold()
        and len(name.casefold()) == len(name.upper()) == len(name.lower()) == len(name)
    )


_TIER_ORDER = {"autonomous": 0, "soft": 1, "strong": 2}
MAX_CHAIN = 16


def _check_limits(
    limits: Mapping[str, Iterable[str]] | None, config: AuthConfig
) -> dict[str, list[str]]:
    """Limits are the last line of defence: a typo must fail loudly, never disable them."""
    if limits is None:
        return {}
    if not isinstance(limits, Mapping):
        raise TypeError("limits must be a mapping of agent name (or '*') to deny patterns")
    out: dict[str, list[str]] = {}
    for agent, patterns in limits.items():
        if agent != "*" and agent not in config.profiles:
            raise ValueError(
                f"limits name agent '{agent}', which has no profile in the config "
                f"(agents: {', '.join(sorted(config.profiles)) or 'none'}; '*' means all)"
            )
        if isinstance(patterns, (str, bytes)):
            raise TypeError(f"limits['{agent}'] must be a list of patterns, not {patterns!r}")
        patterns = list(patterns)  # once: a generator must not be consumed by the check
        if not all(isinstance(p, str) for p in patterns):
            raise TypeError(f"limits['{agent}'] must be a list of patterns, not {patterns!r}")
        out[str(agent)] = list(patterns)
    return out


@dataclass(frozen=True)
class VerifiedToken:
    """A verified token: its claims, and what the agent may do now (``resolved.check``)."""

    claims: tokens.TokenClaims
    resolved: ResolvedAgent


class _CallableProvider:
    """Wraps a plain callable as a UserPermissionsProvider."""

    def __init__(self, fn: Callable[[str], set[str]]) -> None:
        self._fn = fn

    def get_user_actions(self, user: str) -> set[str]:
        return self._fn(user)
