"""
SCOPEX scope management CLI.

Provides commands for managing authorized domains, IP addresses,
and CIDR networks.

All authorized scope is persisted in SQLite.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from scopex.core.scope import (
    ScopeManager,
    ScopeViolation,
    InvalidTarget,
    ScopeType,
    normalize_domain,
    normalize_ip,
    normalize_cidr,
)
from scopex.database.database import session_scope
from scopex.database.scope_repository import ScopeRepository


scope_app = typer.Typer(
    name="scope",
    help="Manage authorized SCOPEX targets.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()

scope_manager = ScopeManager()


# ============================================================
# Add Domain
# ============================================================

@scope_app.command("add-domain")
def add_domain(
    domain: str = typer.Argument(
        ...,
        help="Domain to authorize.",
    ),
) -> None:
    """Add an authorized domain."""

    try:
        normalized = normalize_domain(domain)

        with session_scope() as session:
            repository = ScopeRepository(session)

            existing = repository.get_by_type_and_value(
                ScopeType.DOMAIN.value,
                normalized,
            )

            if existing is not None:
                if not existing.enabled:
                    repository.set_enabled(
                        existing.id,
                        True,
                    )

                scope_manager.add_domain(normalized)

                console.print(
                    "[yellow]ALREADY AUTHORIZED[/yellow] "
                    f"domain: [bold]{normalized}[/bold]"
                )
                return

            repository.create(
                target_type=ScopeType.DOMAIN.value,
                value=normalized,
            )

        scope_manager.add_domain(normalized)

        console.print(
            "[green]AUTHORIZED[/green] "
            f"domain: [bold]{normalized}[/bold]"
        )

    except InvalidTarget as exc:
        console.print(
            f"[red]INVALID TARGET[/red]: {exc}"
        )

    except ScopeViolation as exc:
        console.print(
            f"[red]SCOPE ERROR[/red]: {exc}"
        )


# ============================================================
# Add IP
# ============================================================

@scope_app.command("add-ip")
def add_ip(
    ip_address: str = typer.Argument(
        ...,
        help="IPv4 address to authorize.",
    ),
) -> None:
    """Add an authorized IPv4 address."""

    try:
        normalized = normalize_ip(ip_address)

        with session_scope() as session:
            repository = ScopeRepository(session)

            existing = repository.get_by_type_and_value(
                ScopeType.IP.value,
                normalized,
            )

            if existing is not None:
                if not existing.enabled:
                    repository.set_enabled(
                        existing.id,
                        True,
                    )

                scope_manager.add_ip(normalized)

                console.print(
                    "[yellow]ALREADY AUTHORIZED[/yellow] "
                    f"IP: [bold]{normalized}[/bold]"
                )
                return

            repository.create(
                target_type=ScopeType.IP.value,
                value=normalized,
            )

        scope_manager.add_ip(normalized)

        console.print(
            "[green]AUTHORIZED[/green] "
            f"IP: [bold]{normalized}[/bold]"
        )

    except InvalidTarget as exc:
        console.print(
            f"[red]INVALID TARGET[/red]: {exc}"
        )

    except ScopeViolation as exc:
        console.print(
            f"[red]SCOPE ERROR[/red]: {exc}"
        )


# ============================================================
# Add CIDR
# ============================================================

@scope_app.command("add-cidr")
def add_cidr(
    network: str = typer.Argument(
        ...,
        help="IPv4 CIDR network to authorize.",
    ),
) -> None:
    """Add an authorized IPv4 CIDR network."""

    try:
        normalized = normalize_cidr(network)

        with session_scope() as session:
            repository = ScopeRepository(session)

            existing = repository.get_by_type_and_value(
                ScopeType.CIDR.value,
                normalized,
            )

            if existing is not None:
                if not existing.enabled:
                    repository.set_enabled(
                        existing.id,
                        True,
                    )

                scope_manager.add_cidr(normalized)

                console.print(
                    "[yellow]ALREADY AUTHORIZED[/yellow] "
                    f"CIDR: [bold]{normalized}[/bold]"
                )
                return

            repository.create(
                target_type=ScopeType.CIDR.value,
                value=normalized,
            )

        scope_manager.add_cidr(normalized)

        console.print(
            "[green]AUTHORIZED[/green] "
            f"CIDR: [bold]{normalized}[/bold]"
        )

    except InvalidTarget as exc:
        console.print(
            f"[red]INVALID TARGET[/red]: {exc}"
        )

    except ScopeViolation as exc:
        console.print(
            f"[red]SCOPE ERROR[/red]: {exc}"
        )


# ============================================================
# List
# ============================================================

@scope_app.command("list")
def list_scope() -> None:
    """Display all enabled authorized targets."""

    with session_scope() as session:
        repository = ScopeRepository(session)

        targets = repository.get_all(
            enabled_only=True,
        )

    if not targets:
        console.print(
            "[yellow]No authorized targets configured.[/yellow]"
        )
        return

    table = Table(
        title="SCOPEX AUTHORIZED SCOPE",
        show_header=True,
        header_style="bold",
    )

    table.add_column("ID")
    table.add_column("Type")
    table.add_column("Target")
    table.add_column("Status")

    for target in targets:
        table.add_row(
            str(target.id),
            target.target_type,
            target.value,
            "enabled" if target.enabled else "disabled",
        )

    console.print(table)


# ============================================================
# Check
# ============================================================

@scope_app.command("check")
def check_target(
    target: str = typer.Argument(
        ...,
        help="Target to validate against the authorized scope.",
    ),
) -> None:
    """Validate a target against authorized scope."""

    try:
        normalized = scope_manager.validate(target)

        console.print(
            "[green]AUTHORIZED[/green]: "
            f"[bold]{normalized}[/bold]"
        )

    except ScopeViolation as exc:
        console.print(
            f"[red]BLOCKED[/red]: {exc}"
        )

    except InvalidTarget as exc:
        console.print(
            f"[red]INVALID TARGET[/red]: {exc}"
        )


# ============================================================
# Disable
# ============================================================

@scope_app.command("disable")
def disable_scope(
    target_id: int = typer.Argument(
        ...,
        help="ID of the authorized scope target.",
    ),
) -> None:
    """Disable an authorized scope target."""

    with session_scope() as session:
        repository = ScopeRepository(session)

        target = repository.set_enabled(
            target_id,
            False,
        )

        if target is None:
            console.print(
                f"[red]NOT FOUND[/red]: "
                f"Scope target ID {target_id}"
            )
            return

        console.print(
            "[yellow]DISABLED[/yellow] "
            f"{target.target_type}: "
            f"[bold]{target.value}[/bold]"
        )


# ============================================================
# Enable
# ============================================================

@scope_app.command("enable")
def enable_scope(
    target_id: int = typer.Argument(
        ...,
        help="ID of the authorized scope target.",
    ),
) -> None:
    """Enable an authorized scope target."""

    with session_scope() as session:
        repository = ScopeRepository(session)

        target = repository.set_enabled(
            target_id,
            True,
        )

        if target is None:
            console.print(
                f"[red]NOT FOUND[/red]: "
                f"Scope target ID {target_id}"
            )
            return

        console.print(
            "[green]ENABLED[/green] "
            f"{target.target_type}: "
            f"[bold]{target.value}[/bold]"
        )


# ============================================================
# Remove
# ============================================================

@scope_app.command("remove")
def remove_scope(
    target_id: int = typer.Argument(
        ...,
        help="ID of the authorized scope target.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Permanently delete without confirmation.",
    ),
) -> None:
    """Permanently remove an authorized scope target."""

    with session_scope() as session:
        repository = ScopeRepository(session)

        target = repository.get_by_id(
            target_id
        )

        if target is None:
            console.print(
                f"[red]NOT FOUND[/red]: "
                f"Scope target ID {target_id}"
            )
            return

        if not force:
            confirmed = typer.confirm(
                f"Remove {target.target_type} "
                f"'{target.value}' permanently?"
            )

            if not confirmed:
                console.print(
                    "[yellow]CANCELLED[/yellow]"
                )
                return

        repository.delete(target_id)

        console.print(
            "[red]REMOVED[/red] "
            f"{target.target_type}: "
            f"[bold]{target.value}[/bold]"
        )


# ============================================================
# Summary
# ============================================================

@scope_app.command("summary")
def scope_summary() -> None:
    """Display a summary of authorized scope."""

    with session_scope() as session:
        repository = ScopeRepository(session)

        targets = repository.get_all(
            enabled_only=True,
        )

    console.print()
    console.print(
        "[bold cyan]SCOPEX SCOPE SUMMARY[/bold cyan]"
    )
    console.print()

    console.print(
        f"Authorized targets: "
        f"[bold]{len(targets)}[/bold]"
    )

    counts = {
        ScopeType.DOMAIN.value: 0,
        ScopeType.IP.value: 0,
        ScopeType.CIDR.value: 0,
    }

    for target in targets:
        if target.target_type in counts:
            counts[target.target_type] += 1

    for target_type, count in counts.items():
        console.print(
            f"{target_type}: [bold]{count}[/bold]"
        )

    console.print()


if __name__ == "__main__":
    scope_app()