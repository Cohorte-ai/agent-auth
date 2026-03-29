"""Click-based CLI: agent-auth validate, check, inspect, sessions, delegate, audit, version."""

from __future__ import annotations

import json
import sys

import click

from theaios import agent_auth
from theaios.agent_auth.audit import AuditLog
from theaios.agent_auth.config import ConfigError, load_config
from theaios.agent_auth.engine import AuthEngine
from theaios.agent_auth.reporting import (
    export_audit_json,
    print_audit_summary,
    print_auth_result,
    print_config_summary,
    print_delegations_list,
    print_sessions_list,
)
from theaios.agent_auth.types import AuthRequest


@click.group()
@click.option("--config", "-c", "config_path", default="agent_auth.yaml", help="Config file path")
@click.pass_context
def main(ctx: click.Context, config_path: str) -> None:
    """theaios-agent-auth — Agent-specific IAM for AI systems."""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config_path


# ---------------------------------------------------------------------------
# agent-auth version
# ---------------------------------------------------------------------------


@main.command()
def version() -> None:
    """Show version."""
    click.echo(f"agent-auth {agent_auth.__version__}")


# ---------------------------------------------------------------------------
# agent-auth validate
# ---------------------------------------------------------------------------


@main.command()
@click.pass_context
def validate(ctx: click.Context) -> None:
    """Validate an auth config file for errors."""
    config_path = ctx.obj["config_path"]
    try:
        config = load_config(config_path)
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except ConfigError as e:
        click.echo("Validation failed:", err=True)
        for error in e.errors:
            click.echo(f"  - {error}", err=True)
        sys.exit(1)

    n_roles = len(config.roles)
    n_profiles = len(config.profiles)
    n_policies = len(config.approval_policies)
    n_a2a = len(config.a2a.policies)
    click.echo(
        f"Config is valid: {n_roles} roles, {n_profiles} profiles, "
        f"{n_policies} approval policies, {n_a2a} A2A policies"
    )


# ---------------------------------------------------------------------------
# agent-auth inspect
# ---------------------------------------------------------------------------


@main.command()
@click.pass_context
def inspect(ctx: click.Context) -> None:
    """Display config: roles, profiles, policies."""
    config_path = ctx.obj["config_path"]
    try:
        config = load_config(config_path)
    except (FileNotFoundError, ConfigError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    print_config_summary(config)


# ---------------------------------------------------------------------------
# agent-auth check
# ---------------------------------------------------------------------------


@main.command()
@click.option("--agent", "-a", required=True, help="Agent name")
@click.option("--user", "-u", required=True, help="User name")
@click.option("--action", required=True, help="Action to check")
@click.option("--resource", "-r", default="", help="Resource")
@click.option("--scope", "-s", default="", help="Scope")
@click.option("--target-agent", default=None, help="Target agent for A2A check")
@click.option("--output", "-o", type=click.Choice(["console", "json"]), default="console")
@click.pass_context
def check(
    ctx: click.Context,
    agent: str,
    user: str,
    action: str,
    resource: str,
    scope: str,
    target_agent: str | None,
    output: str,
) -> None:
    """Check authorization for an agent action."""
    config_path = ctx.obj["config_path"]
    try:
        config = load_config(config_path)
    except (FileNotFoundError, ConfigError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    engine = AuthEngine(config)
    request = AuthRequest(
        agent=agent,
        user=user,
        action=action,
        resource=resource,
        scope=scope,
        target_agent=target_agent,
    )
    decision = engine.authorize(request)

    if output == "json":
        result: dict[str, object] = {
            "allowed": decision.allowed,
            "tier": decision.tier,
            "reason": decision.reason,
            "requires_approval": decision.requires_approval,
            "approval_policy": decision.approval_policy,
            "evaluation_time_ms": round(decision.evaluation_time_ms, 3),
        }
        click.echo(json.dumps(result, indent=2))
    else:
        print_auth_result(decision)

    if decision.is_denied:
        sys.exit(1)


# ---------------------------------------------------------------------------
# agent-auth sessions
# ---------------------------------------------------------------------------


@main.command()
@click.option("--list", "list_sessions", is_flag=True, help="List active sessions")
@click.option("--create", "create_session", is_flag=True, help="Create a new session")
@click.option("--revoke", "revoke_session", default=None, help="Revoke a session by ID")
@click.option("--agent", "-a", default=None, help="Agent name")
@click.option("--user", "-u", default=None, help="User name")
@click.option("--scope", "-s", default="", help="Scope for new session")
@click.option("--duration", "-d", type=int, default=None, help="Duration in seconds")
@click.pass_context
def sessions(
    ctx: click.Context,
    list_sessions: bool,
    create_session: bool,
    revoke_session: str | None,
    agent: str | None,
    user: str | None,
    scope: str,
    duration: int | None,
) -> None:
    """Manage agent sessions."""
    config_path = ctx.obj["config_path"]
    try:
        config = load_config(config_path)
    except (FileNotFoundError, ConfigError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    engine = AuthEngine(config)

    if revoke_session:
        if engine.revoke_session(revoke_session):
            click.echo(f"Session {revoke_session} revoked")
        else:
            click.echo(f"Session {revoke_session} not found or already inactive", err=True)
            sys.exit(1)
    elif create_session:
        if not agent or not user:
            click.echo("Error: --agent and --user are required for --create", err=True)
            sys.exit(1)
        session = engine.create_session(agent, user, scope, duration)
        click.echo(f"Session created: {session.session_id}")
        click.echo(f"  Agent: {session.agent}")
        click.echo(f"  User: {session.user}")
        click.echo(f"  Scope: {session.scope or '(all)'}")
        click.echo(f"  Expires: {session.expires_at}")
    elif list_sessions:
        active = engine._sessions.list_active(agent=agent, user=user)
        print_sessions_list(active)
    else:
        click.echo("Use --list, --create, or --revoke. See --help.", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# agent-auth delegate
# ---------------------------------------------------------------------------


@main.command()
@click.option("--from-user", required=True, help="User granting delegation")
@click.option("--to-agent", required=True, help="Agent receiving delegation")
@click.option("--actions", required=True, help="Comma-separated actions to delegate")
@click.option("--duration", "-d", type=int, default=None, help="Duration in seconds")
@click.option("--reason", default="", help="Reason for delegation")
@click.pass_context
def delegate(
    ctx: click.Context,
    from_user: str,
    to_agent: str,
    actions: str,
    duration: int | None,
    reason: str,
) -> None:
    """Create a delegation from a user to an agent."""
    config_path = ctx.obj["config_path"]
    try:
        config = load_config(config_path)
    except (FileNotFoundError, ConfigError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    engine = AuthEngine(config)
    action_list = [a.strip() for a in actions.split(",")]

    try:
        grant = engine.create_delegation(from_user, to_agent, action_list, duration, reason)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    click.echo(f"Delegation created: {grant.delegation_id}")
    click.echo(f"  From: {grant.from_user}")
    click.echo(f"  To: {grant.to_agent}")
    click.echo(f"  Actions: {', '.join(grant.actions)}")
    click.echo(f"  Expires: {grant.expires_at}")
    if grant.reason:
        click.echo(f"  Reason: {grant.reason}")


# ---------------------------------------------------------------------------
# agent-auth delegations
# ---------------------------------------------------------------------------


@main.command()
@click.option("--list", "list_delegations", is_flag=True, help="List active delegations")
@click.option("--revoke", "revoke_delegation", default=None, help="Revoke a delegation by ID")
@click.option("--agent", "-a", default=None, help="Filter by agent")
@click.pass_context
def delegations(
    ctx: click.Context,
    list_delegations: bool,
    revoke_delegation: str | None,
    agent: str | None,
) -> None:
    """Manage delegations."""
    config_path = ctx.obj["config_path"]
    try:
        config = load_config(config_path)
    except (FileNotFoundError, ConfigError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    engine = AuthEngine(config)

    if revoke_delegation:
        if engine.revoke_delegation(revoke_delegation):
            click.echo(f"Delegation {revoke_delegation} revoked")
        else:
            click.echo(
                f"Delegation {revoke_delegation} not found or already inactive",
                err=True,
            )
            sys.exit(1)
    elif list_delegations:
        active = engine._delegations.list_active(agent=agent)
        print_delegations_list(active)
    else:
        click.echo("Use --list or --revoke. See --help.", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# agent-auth audit
# ---------------------------------------------------------------------------


@main.command()
@click.option("--since", help="Show entries since this ISO timestamp")
@click.option("--agent", help="Filter by agent name")
@click.option("--user", help="Filter by user name")
@click.option("--action", help="Filter by action")
@click.option("--limit", type=int, default=1000, help="Maximum entries to show")
@click.option("--output", "-o", type=click.Choice(["console", "json"]), default="console")
@click.option("--output-file", help="Write JSON output to file")
@click.pass_context
def audit(
    ctx: click.Context,
    since: str | None,
    agent: str | None,
    user: str | None,
    action: str | None,
    limit: int,
    output: str,
    output_file: str | None,
) -> None:
    """View the audit log."""
    config_path = ctx.obj["config_path"]
    try:
        config = load_config(config_path)
    except (FileNotFoundError, ConfigError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    log = AuditLog(path=config.audit.path)
    entries = log.read(since=since, agent=agent, user=user, action=action, limit=limit)

    if output == "json" or output_file:
        if output_file:
            export_audit_json(entries, output_file)
            click.echo(f"Exported {len(entries)} entries to {output_file}")
        else:
            click.echo(json.dumps(entries, indent=2, default=str))
    else:
        print_audit_summary(entries)
