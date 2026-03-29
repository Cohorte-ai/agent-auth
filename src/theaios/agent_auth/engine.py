"""Authorization engine.

Evaluates auth requests against config: profiles, roles, sessions,
delegations, approval policies, and A2A rules.
Returns an AuthDecision for every request.
"""

from __future__ import annotations

import asyncio
import time
from typing import Callable, Protocol

from theaios.agent_auth.a2a import A2AEvaluator
from theaios.agent_auth.approval import ApprovalEvaluator
from theaios.agent_auth.audit import AuditLog
from theaios.agent_auth.delegation import DelegationManager
from theaios.agent_auth.profiles import ResolvedProfile, check_action, check_scope, resolve_profile
from theaios.agent_auth.roles import resolve_role
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
    ) -> None:
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

    @property
    def config(self) -> AuthConfig:
        """The loaded auth configuration."""
        return self._config

    def authorize(self, request: AuthRequest) -> AuthDecision:
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
                self._log(request, decision)
                return decision

            # Verify session matches request
            if session.agent != request.agent:
                decision = AuthDecision(
                    allowed=False,
                    reason=f"Session agent mismatch: expected '{session.agent}', "
                    f"got '{request.agent}'",
                    evaluation_time_ms=(time.perf_counter() - start) * 1000,
                )
                self._log(request, decision)
                return decision

            if session.user and session.user != request.user:
                decision = AuthDecision(
                    allowed=False,
                    reason=f"Session user mismatch: expected '{session.user}', "
                    f"got '{request.user}'",
                    evaluation_time_ms=(time.perf_counter() - start) * 1000,
                )
                self._log(request, decision)
                return decision

        # Step 2: Resolve agent profile
        profile = self._profiles.get(request.agent)

        # Step 3: Check profile deny list
        if profile:
            perm = check_action(profile, request.action)
            if perm == "deny":
                decision = AuthDecision(
                    allowed=False,
                    reason=f"Action '{request.action}' denied by profile '{profile.name}'",
                    evaluation_time_ms=(time.perf_counter() - start) * 1000,
                )
                self._log(request, decision)
                return decision

            # Check scope
            if request.scope and not check_scope(profile, request.scope):
                decision = AuthDecision(
                    allowed=False,
                    reason=f"Scope '{request.scope}' not allowed by profile '{profile.name}'",
                    evaluation_time_ms=(time.perf_counter() - start) * 1000,
                )
                self._log(request, decision)
                return decision

        # Step 4: Check profile allow list
        action_allowed = False
        if profile:
            perm = check_action(profile, request.action)
            if perm == "allow":
                action_allowed = True

        # Step 5: Check delegations
        delegation_grant: DelegationGrant | None = None
        if not action_allowed:
            delegation_grant = self._delegations.check(request.agent, request.action)
            if delegation_grant is not None:
                action_allowed = True

        # Step 6: Check user permissions
        if not action_allowed and self._user_provider is not None:
            user_actions = self._user_provider.get_user_actions(request.user)
            if request.action in user_actions:
                action_allowed = True

        # Step 7: Check A2A policies
        if request.target_agent:
            a2a_allowed, a2a_reason = self._a2a.evaluate(
                from_agent=request.agent,
                to_agent=request.target_agent,
                action=request.action,
                context=dict(request.metadata),
            )
            if not a2a_allowed:
                decision = AuthDecision(
                    allowed=False,
                    reason=a2a_reason,
                    evaluation_time_ms=(time.perf_counter() - start) * 1000,
                )
                self._log(request, decision)
                return decision

        # If action is not allowed by any source, deny
        if not action_allowed:
            decision = AuthDecision(
                allowed=False,
                reason=f"Action '{request.action}' not authorized for agent '{request.agent}'",
                evaluation_time_ms=(time.perf_counter() - start) * 1000,
            )
            self._log(request, decision)
            return decision

        # Step 8: Evaluate approval policies
        default_tier = profile.default_tier if profile else "autonomous"
        eval_context: dict[str, object] = {
            "agent": request.agent,
            "user": request.user,
            "action": request.action,
            "resource": request.resource,
            "scope": request.scope,
        }
        eval_context.update(request.metadata)

        tier = self._approval.evaluate(request.action, eval_context, default_tier)

        requires_approval = tier in ("soft", "strong")
        approval_policy = ""
        if requires_approval:
            # Find the matching policy name for reporting
            for policy_cfg in self._config.approval_policies:
                if policy_cfg.tier == tier:
                    approval_policy = policy_cfg.name
                    break

        reason = ""
        if delegation_grant is not None:
            reason = f"Delegated by user '{delegation_grant.from_user}'"
        elif profile:
            reason = f"Allowed by profile '{profile.name}'"
        else:
            reason = "Allowed by user permissions"

        if requires_approval:
            reason += f" (requires {tier} approval)"

        decision = AuthDecision(
            allowed=True,
            tier=tier,
            reason=reason,
            requires_approval=requires_approval,
            approval_policy=approval_policy,
            evaluation_time_ms=(time.perf_counter() - start) * 1000,
        )
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


class _CallableProvider:
    """Wraps a plain callable as a UserPermissionsProvider."""

    def __init__(self, fn: Callable[[str], set[str]]) -> None:
        self._fn = fn

    def get_user_actions(self, user: str) -> set[str]:
        return self._fn(user)
