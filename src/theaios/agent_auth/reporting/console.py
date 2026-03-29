"""Rich terminal output for auth inspection, check results, sessions, and audit."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from theaios.agent_auth.types import AuthConfig, AuthDecision, DelegationGrant, Session

console = Console()


def print_config_summary(config: AuthConfig) -> None:
    """Print a formatted summary of an auth config."""
    if config.metadata.name:
        console.print(f"\n[bold]{config.metadata.name}[/bold]")
    if config.metadata.description:
        console.print(f"  {config.metadata.description}")
    console.print(f"  Version: {config.version}")
    if config.metadata.author:
        console.print(f"  Author: {config.metadata.author}")

    # Roles
    if config.roles:
        console.print(f"\n[bold]Roles[/bold] ({len(config.roles)})")
        table = Table(show_header=True, header_style="bold")
        table.add_column("Name")
        table.add_column("Extends")
        table.add_column("Actions")
        table.add_column("Description")
        for name, role in config.roles.items():
            table.add_row(
                name,
                role.extends or "-",
                ", ".join(role.actions) or "-",
                role.description or "-",
            )
        console.print(table)

    # Profiles
    if config.profiles:
        console.print(f"\n[bold]Profiles[/bold] ({len(config.profiles)})")
        table = Table(show_header=True, header_style="bold")
        table.add_column("Name")
        table.add_column("Role")
        table.add_column("Default Tier")
        table.add_column("Allow")
        table.add_column("Deny")
        table.add_column("Scopes")
        for name, profile in config.profiles.items():
            tier_color = {
                "autonomous": "green",
                "soft": "yellow",
                "strong": "red",
            }.get(profile.default_tier, "white")
            table.add_row(
                name,
                profile.role or "-",
                f"[{tier_color}]{profile.default_tier}[/{tier_color}]",
                ", ".join(profile.allow) or "-",
                ", ".join(profile.deny) or "-",
                ", ".join(profile.scopes) or "*",
            )
        console.print(table)

    # Approval Policies
    if config.approval_policies:
        console.print(f"\n[bold]Approval Policies[/bold] ({len(config.approval_policies)})")
        table = Table(show_header=True, header_style="bold")
        table.add_column("Name")
        table.add_column("Tier")
        table.add_column("Condition")
        table.add_column("Description")
        for policy in config.approval_policies:
            tier_color = {"soft": "yellow", "strong": "red"}.get(policy.tier, "white")
            table.add_row(
                policy.name,
                f"[{tier_color}]{policy.tier}[/{tier_color}]",
                policy.condition or "(always)",
                policy.description or "-",
            )
        console.print(table)

    # A2A Policies
    if config.a2a.policies:
        console.print(f"\n[bold]A2A Policies[/bold] ({len(config.a2a.policies)})")
        console.print(f"  Default: {config.a2a.default}")
        table = Table(show_header=True, header_style="bold")
        table.add_column("Name")
        table.add_column("From")
        table.add_column("To")
        table.add_column("Action")
        table.add_column("Effect")
        for a2a_policy in config.a2a.policies:
            effect_color = "green" if a2a_policy.effect == "allow" else "red"
            table.add_row(
                a2a_policy.name,
                a2a_policy.from_agent,
                a2a_policy.to_agent,
                a2a_policy.action,
                f"[{effect_color}]{a2a_policy.effect}[/{effect_color}]",
            )
        console.print(table)

    # Delegation
    if config.delegation.rules:
        console.print(f"\n[bold]Delegation Rules[/bold] ({len(config.delegation.rules)})")
        console.print(f"  Enabled: {config.delegation.enabled}")
        console.print(f"  Default duration: {config.delegation.default_duration}s")
        table = Table(show_header=True, header_style="bold")
        table.add_column("Name")
        table.add_column("Allowed Actions")
        table.add_column("Max Duration")
        table.add_column("Require Reason")
        for rule in config.delegation.rules:
            table.add_row(
                rule.name,
                ", ".join(rule.allowed_actions) or "*",
                f"{rule.max_duration}s",
                "[green]yes[/green]" if rule.require_reason else "[dim]no[/dim]",
            )
        console.print(table)

    console.print()


def print_auth_result(decision: AuthDecision) -> None:
    """Print a formatted authorization result."""
    if decision.allowed:
        status_color = "green"
        status_text = "ALLOWED"
    else:
        status_color = "red"
        status_text = "DENIED"

    console.print(f"\n[bold {status_color}]{status_text}[/bold {status_color}]", end="")

    if decision.requires_approval:
        console.print(f"  [yellow](requires {decision.tier} approval)[/yellow]", end="")
    elif decision.tier != "autonomous":
        console.print(f"  (tier: {decision.tier})", end="")
    console.print()

    if decision.reason:
        console.print(f"  Reason: {decision.reason}")
    if decision.approval_policy:
        console.print(f"  Approval policy: {decision.approval_policy}")
    if decision.evaluation_time_ms > 0:
        console.print(f"  Evaluated in: {decision.evaluation_time_ms:.2f}ms")
    console.print()


def print_sessions_list(sessions: list[Session]) -> None:
    """Print a formatted list of sessions."""
    if not sessions:
        console.print("[dim]No active sessions found.[/dim]")
        return

    console.print(f"\n[bold]Active Sessions[/bold] ({len(sessions)})\n")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Session ID")
    table.add_column("Agent")
    table.add_column("User")
    table.add_column("Scope")
    table.add_column("Created")
    table.add_column("Expires")

    for session in sessions:
        created = session.created_at
        if "." in created:
            created = created.split(".")[0]
        expires = session.expires_at
        if "." in expires:
            expires = expires.split(".")[0]

        table.add_row(
            session.session_id[:12] + "...",
            session.agent,
            session.user,
            session.scope or "*",
            created,
            expires,
        )
    console.print(table)
    console.print()


def print_delegations_list(delegations: list[DelegationGrant]) -> None:
    """Print a formatted list of delegation grants."""
    if not delegations:
        console.print("[dim]No active delegations found.[/dim]")
        return

    console.print(f"\n[bold]Active Delegations[/bold] ({len(delegations)})\n")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Delegation ID")
    table.add_column("From User")
    table.add_column("To Agent")
    table.add_column("Actions")
    table.add_column("Granted")
    table.add_column("Expires")
    table.add_column("Reason")

    for grant in delegations:
        granted = grant.granted_at
        if "." in granted:
            granted = granted.split(".")[0]
        expires = grant.expires_at
        if "." in expires:
            expires = expires.split(".")[0]

        table.add_row(
            grant.delegation_id[:12] + "...",
            grant.from_user,
            grant.to_agent,
            ", ".join(grant.actions),
            granted,
            expires,
            grant.reason or "-",
        )
    console.print(table)
    console.print()


def print_audit_summary(entries: list[dict[str, object]]) -> None:
    """Print a summary of audit log entries."""
    if not entries:
        console.print("[dim]No audit entries found.[/dim]")
        return

    console.print(f"\n[bold]Audit Log[/bold] ({len(entries)} entries)\n")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Timestamp")
    table.add_column("Agent")
    table.add_column("User")
    table.add_column("Action")
    table.add_column("Allowed")
    table.add_column("Tier")
    table.add_column("Reason")

    for entry in entries[-50:]:  # Show last 50
        allowed = entry.get("allowed", False)
        allowed_color = "green" if allowed else "red"
        allowed_text = "yes" if allowed else "no"

        ts = str(entry.get("timestamp", ""))
        # Truncate to seconds
        if "." in ts:
            ts = ts.split(".")[0]

        reason = str(entry.get("reason", ""))
        if len(reason) > 40:
            reason = reason[:37] + "..."

        table.add_row(
            ts,
            str(entry.get("agent", "")),
            str(entry.get("user", "")),
            str(entry.get("action", "")),
            f"[{allowed_color}]{allowed_text}[/{allowed_color}]",
            str(entry.get("tier", "-")),
            reason,
        )
    console.print(table)
    console.print()
