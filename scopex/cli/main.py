"""
SCOPEX command-line interface.

This module defines the main SCOPEX CLI application.
"""

from __future__ import annotations

import typer
from rich.console import Console

from scopex import __version__
from scopex.cli.doctor import doctor
from scopex.cli.scope import scope_app
from scopex.core.logging import configure_logging


# ============================================================
# CLI Application
# ============================================================

app = typer.Typer(
    name="scopex",
    help="External Attack Surface Intelligence Platform.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()


# ============================================================
# Global CLI Callback
# ============================================================

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        help="Show the SCOPEX version.",
    ),
) -> None:
    """
    SCOPEX - External Attack Surface Intelligence Platform.
    """

    configure_logging()

    if version:
        console.print(
            f"[bold cyan]SCOPEX[/bold cyan] "
            f"version [bold]{__version__}[/bold]"
        )
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


# ============================================================
# Info Command
# ============================================================

@app.command()
def info() -> None:
    """
    Display basic SCOPEX information.
    """

    console.print()

    console.print(
        "[bold cyan]SCOPEX[/bold cyan] "
        "- External Attack Surface Intelligence Platform"
    )

    console.print(
        f"Version: {__version__}"
    )

    console.print()

    console.print(
        "Authorized external attack-surface discovery, "
        "asset intelligence, evidence collection, "
        "and historical monitoring."
    )


# ============================================================
# Doctor Command
# ============================================================

app.command(name="doctor")(doctor)


# ============================================================
# Scope Command Group
# ============================================================

app.add_typer(
    scope_app,
    name="scope",
)


# ============================================================
# Application Entry Point
# ============================================================

if __name__ == "__main__":
    app()