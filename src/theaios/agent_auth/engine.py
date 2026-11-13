"""Authorization engine.

Evaluates auth requests against config: profiles, roles, sessions,
delegations, approval policies, and A2A rules.
Returns an AuthDecision for every request.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import fnmatch
import time
import warnings
from collections.abc import Iterable, Mapping
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
        token_key: bytes | None = None,
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
        self._sessions = SessionManager(
            path=str(config.audit.path).replace("audit.jsonl", "sessions.jsonl")
            if config.audit.path != ".agent_auth/audit.jsonl"
            else ".agent_auth/sessions.jsonl"
        )

        # Delegation manager
        self._delegations = DelegationManager(
            config=config.delegation,
            path=str(config.audit.path).replace("audit.jsonl", "delegations.jsonl")
            if config.audit.path != ".agent_auth/audit.jsonl"
            else ".agent_auth/delegations.jsonl",
        )

        # Audit log
        self._audit = AuditLog(path=config.audit.path) if config.audit.enabled else None

        # Resolution (0.2): principal roles from the application, code-declared limits that no
        # config can widen, separation of duties, signed tokens.
        self._user_roles = user_roles
        self._limits: dict[str, list[str]] = {
            str(agent): [str(p) for p in patterns] for agent, patterns in (limits or {}).items()
        }
        self._token_key = token_key
        self._sod_done: dict[tuple[str, str, str], set[str]] = {}
        self._warned_union = False

    @property
    def config(self) -> AuthConfig:
        """The loaded auth configuration."""
        return self._config

    def authorize(self, request: AuthRequest) -> AuthDecision:
        """Authorize a request: decide, log it, and record it for separation of duties."""
        return self._authorize(request, record=True)

    def explain(self, request: AuthRequest) -> AuthDecision:
        """The decision ``authorize`` would make, with its provenance, without logging or
        recording anything."""
        return self._authorize(request, record=False)

    def _authorize(self, request: AuthRequest, *, record: bool) -> AuthDecision:
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
        resolved = self.resolve(request.agent, self._principal(request))

        # Step 3: Access, denials (profile deny, code limits) and scope
        allowed, provenance = resolved.check(request.action)
        if not resolved.access:
            return self._done(
                request,
                AuthDecision(
                    allowed=False,
                    reason=f"Access denied: {resolved.access_reason}",
                    evaluation_time_ms=(time.perf_counter() - start) * 1000,
                    provenance=["access"],
                ),
                record,
            )
        if provenance and not allowed:
            source = provenance[0].split(":", 1)[0]
            if source == "limit":
                reason = f"Action '{request.action}' is blocked by a limit set in code"
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
        if profile and request.scope and not check_scope(profile, request.scope):
            return self._done(
                request,
                AuthDecision(
                    allowed=False,
                    reason=f"Scope '{request.scope}' not allowed by profile '{profile.name}'",
                    evaluation_time_ms=(time.perf_counter() - start) * 1000,
                    provenance=["scope"],
                ),
                record,
            )

        # Steps 4-6: baseline, grants and the user's delegations (in the resolution); then the
        # deprecated user-permissions union.
        action_allowed = allowed
        if (
            not action_allowed
            and self._user_provider is not None
            and self._config.resolution.user_permissions == "union"
            and request.identity == ON_BEHALF_OF
        ):
            user_actions = self._user_provider.get_user_actions(request.user)
            if request.action in user_actions:
                action_allowed = True
                provenance = ["user_permissions"]
                if not self._warned_union:
                    self._warned_union = True
                    warnings.warn(
                        "agent-auth: an action was allowed only because the user may do it "
                        "(user_permissions_provider union). Declare it in the agent's grants "
                        "instead; set resolution.user_permissions: ignore to stop the union. "
                        "The union is removed in 1.0.",
                        DeprecationWarning,
                        stacklevel=3,
                    )
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
        if action_allowed and request.resource:
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

        # Step 7: Check A2A policies
        if request.target_agent:
            a2a_allowed, a2a_reason = self._a2a.evaluate(
                from_agent=request.agent,
                to_agent=request.target_agent,
                action=request.action,
                context={**request.metadata, "metadata": dict(request.metadata)},
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
                reason=f"Action '{request.action}' not authorized for agent '{request.agent}'",
                evaluation_time_ms=(time.perf_counter() - start) * 1000,
            )
            return self._done(request, decision, record)

        # Step 8: Evaluate approval policies
        default_tier = profile.default_tier if profile else "autonomous"
        # Metadata keys are reachable both as `metadata.key` (as documented) and, for
        # compatibility, at the top level; the request's own fields always win, so metadata
        # cannot overwrite the resource or user a policy checks.
        eval_context: dict[str, object] = dict(request.metadata)
        eval_context.update(
            {
                "agent": request.agent,
                "user": request.user,
                "action": request.action,
                "resource": request.resource,
                "scope": request.scope,
                "metadata": dict(request.metadata),
            }
        )

        tier, approval_policy, eval_error = self._approval.explain(
            request.action, eval_context, default_tier
        )

        requires_approval = tier in ("soft", "strong")
        if not requires_approval:
            approval_policy = ""

        reason = ""
        sources = [x.split(":", 1)[0] for x in provenance]
        if "baseline" in sources and profile:
            reason = f"Allowed by profile '{profile.name}'"
        elif any(x.startswith("grant:") for x in provenance):
            role = next(x for x in provenance if x.startswith("grant:")).split(":")[1]
            reason = f"Allowed by the '{role}' grant on '{request.agent}'"
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
        if record and request.resource:
            self._sod_record(request)
        return self._done(request, decision, record)

    # Resolution ------------------------------------------------------------------------

    def _principal(self, request: AuthRequest) -> Principal:
        if request.identity == SERVICE:
            return Principal.service()
        roles = list(self._user_roles(request.user)) if self._user_roles and request.user else []
        return Principal(ON_BEHALF_OF, request.user, frozenset(str(r) for r in roles))

    def principal(self, user: str = "", *, service: bool = False) -> Principal:
        """The principal for a user (roles from ``user_roles``) or for service requests."""
        if service:
            return Principal.service()
        return self._principal(AuthRequest(agent="", user=user, action=""))

    def resolve(self, agent: str, principal: Principal) -> ResolvedAgent:
        """What ``agent`` may do for ``principal`` right now, with provenance."""
        cfg = self._config.profiles.get(agent)
        profile = self._profiles.get(agent)
        delegations: list[tuple[str, list[str]]] = []
        if not principal.is_service and principal.user:
            delegations = [
                (g.delegation_id, list(g.actions))
                for g in self._delegations.list_active(agent=agent)
                if g.from_user == principal.user
            ]
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
        )

    def preview(self, agent: str, principal: Principal) -> ResolvedAgent:
        """Same as :meth:`resolve`: what an administrator sees before granting access."""
        return self.resolve(agent, principal)

    def delegate(self, parent: ResolvedAgent, child_agent: str) -> ResolvedAgent:
        """What ``child_agent`` may do when ``parent`` hands it work: the intersection of the
        child's own resolution and the parent's, for the same principal."""
        return parent.attenuate(self.resolve(child_agent, parent.principal))

    def issue_token(self, resolved: ResolvedAgent, audience: str, ttl: int = 300) -> str:
        """A short-lived token for ``audience`` (the service that will verify it)."""
        return tokens.issue(resolved, audience, ttl, tokens.check_key(self._token_key))

    def verify_token(self, token: str, audience: str, *, leeway: int = 0) -> VerifiedToken:
        """Check a token and return its claims with the agent's *current* resolution. Refuses
        a token whose resolution changed since it was issued (policy edit, roles, revoked
        delegation)."""
        claims = tokens.decode(token, audience, tokens.check_key(self._token_key), leeway=leeway)
        if claims.identity == SERVICE:
            principal = Principal.service()
        else:
            principal = self._principal(
                AuthRequest(agent=claims.agent, user=claims.user, action="")
            )
        agents = [*claims.chain, claims.agent]
        current = self.resolve(agents[0], principal)
        for agent in agents[1:]:
            current = current.attenuate(self.resolve(agent, principal))
        if current.fingerprint != claims.fingerprint:
            raise tokens.TokenError(
                "the agent's permissions changed since the token was issued; issue a new one"
            )
        return VerifiedToken(claims, current)

    def _sod_conflict(self, request: AuthRequest) -> str | None:
        for rule in self._config.separation_of_duties:
            if not any(fnmatch.fnmatchcase(request.action, a) for a in rule.actions):
                continue
            done = self._sod_done.get((rule.name, request.user, request.resource), set())
            others = sorted(a for a in done if a != request.action)
            if others:
                return (
                    f"Separation of duties ('{rule.name}'): '{request.user or 'service'}' "
                    f"already did {', '.join(others)} on '{request.resource}'"
                )
        return None

    def _sod_record(self, request: AuthRequest) -> None:
        for rule in self._config.separation_of_duties:
            if any(fnmatch.fnmatchcase(request.action, a) for a in rule.actions):
                key = (rule.name, request.user, request.resource)
                self._sod_done.setdefault(key, set()).add(request.action)

    def _done(self, request: AuthRequest, decision: AuthDecision, record: bool) -> AuthDecision:
        if record:
            self._log(request, decision)
        return decision

    async def authorize_async(self, request: AuthRequest) -> AuthDecision:
        """Async version of authorize. Same logic, awaitable for framework adapters."""
        return await asyncio.to_thread(self.authorize, request)

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
        """Create a delegation from a user to an agent."""
        return self._delegations.create(from_user, to_agent, actions, duration, reason)

    def revoke_delegation(self, delegation_id: str) -> bool:
        """Revoke an active delegation."""
        return self._delegations.revoke(delegation_id)

    def _log(self, request: AuthRequest, decision: AuthDecision) -> None:
        """Write an audit log entry if auditing is enabled."""
        if self._audit is not None:
            self._audit.write(request, decision, self._config)


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
