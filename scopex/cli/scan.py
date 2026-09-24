"""
SCOPEX scan command.

Provides the user-facing command for authorized DNS reconnaissance.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from scopex.core.scope import ScopeViolation
from scopex.scan.orchestrator import ScanOrchestrator


console = Console()


def scan(
    target: str = typer.Argument(
        ...,
        help="Authorized root domain to scan.",
    ),
    wordlist: Optional[Path] = typer.Option(
        None,
        "--wordlist",
        "-w",
        help="Optional subdomain wordlist.",
    ),
) -> None:
    """
    Run an authorized DNS reconnaissance scan.
    """

    console.print()
    console.print("[bold cyan]SCOPEX SCAN[/bold cyan]")
    console.print()

    # Validate the wordlist before starting the scan.
    if wordlist is not None and not wordlist.exists():
        console.print(
            f"[bold red]WORDLIST ERROR:[/bold red] "
            f"Wordlist does not exist: {wordlist}"
        )
        raise typer.Exit(code=2)

    try:
        orchestrator = ScanOrchestrator()

        summary = orchestrator.run(
            target=target,
            wordlist=wordlist,
        )

    except ScopeViolation as exc:
        console.print(
            f"[bold red]SCOPE ERROR:[/bold red] {exc}"
        )
        raise typer.Exit(code=2)

    except ValueError as exc:
        console.print(
            f"[bold red]TARGET ERROR:[/bold red] {exc}"
        )
        raise typer.Exit(code=2)

    except FileNotFoundError as exc:
        console.print(
            f"[bold red]WORDLIST ERROR:[/bold red] {exc}"
        )
        raise typer.Exit(code=2)

    except Exception as exc:
        console.print(
            f"[bold red]SCAN ERROR:[/bold red] {exc}"
        )
        raise typer.Exit(code=1)

    table = Table(
        title="Scan Summary",
        show_header=True,
    )

    table.add_column("Metric")
    table.add_column("Value")

    table.add_row("Scan ID", str(summary.scan_id))
    table.add_row("Target", summary.target)
    table.add_row("Status", summary.status)
    table.add_row("Candidates", str(summary.candidates))
    table.add_row("Resolved", str(summary.resolved))
    table.add_row("Partial", str(summary.partial))
    table.add_row("Unresolved", str(summary.unresolved))
    table.add_row("Errors", str(summary.errors))
    table.add_row("Assets", str(summary.assets))
    table.add_row("Evidence", str(summary.evidence))

    console.print(table)
    console.print()
    console.print("[bold green]SCAN COMPLETED[/bold green]")