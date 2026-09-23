"""
SCOPEX diagnostic command.

Checks the local SCOPEX environment and reports whether the
platform is ready to perform authorized reconnaissance.
"""

from __future__ import annotations

import shutil
import sys

from rich.console import Console
from rich.table import Table

from scopex.core.config import (
    DATA_DIR,
    DATABASE_PATH,
    LOG_DIR,
    ensure_directories,
)
from scopex.core.logging import get_logger
from scopex.database.database import (
    check_database_connection,
    init_database,
)


# ============================================================
# Console and Logger
# ============================================================

console = Console()

logger = get_logger("scopex.doctor")


# ============================================================
# Python Check
# ============================================================

def check_python() -> tuple[bool, str]:
    """
    Check whether the installed Python version is supported.
    """

    version = sys.version_info

    version_string = (
        f"{version.major}."
        f"{version.minor}."
        f"{version.micro}"
    )

    if version >= (3, 11):
        return True, version_string

    return False, (
        f"{version_string} "
        "(Python 3.11+ required)"
    )


# ============================================================
# Directory Check
# ============================================================

def check_directories() -> tuple[bool, str]:
    """
    Check whether required SCOPEX directories exist.
    """

    try:
        ensure_directories()

        required_directories = [
            DATA_DIR,
            LOG_DIR,
        ]

        missing = [
            str(path)
            for path in required_directories
            if not path.exists()
        ]

        if missing:
            return False, (
                "Missing: "
                + ", ".join(missing)
            )

        return True, "data/ and logs/ available"

    except Exception as exc:
        logger.exception(
            "Directory check failed."
        )

        return False, str(exc)


# ============================================================
# Database Check
# ============================================================

def check_database() -> tuple[bool, str]:
    """
    Check whether the SCOPEX database is operational.
    """

    try:
        init_database()

        if check_database_connection():
            return True, str(DATABASE_PATH)

        return False, "Database connection failed."

    except Exception as exc:
        logger.exception(
            "Database check failed."
        )

        return False, str(exc)


# ============================================================
# Python Dependency Check
# ============================================================

def check_dependency(
    module_name: str,
    display_name: str,
) -> tuple[bool, str]:
    """
    Check whether a Python dependency can be imported.
    """

    try:
        __import__(module_name)

        return True, (
            f"{display_name} available"
        )

    except ImportError:
        return False, (
            f"{display_name} not installed"
        )


# ============================================================
# Nmap Check
# ============================================================

def check_nmap() -> tuple[bool, str]:
    """
    Check whether Nmap is available in PATH.
    """

    nmap_path = shutil.which("nmap")

    if nmap_path:
        return True, nmap_path

    return False, "Nmap not found in PATH"


# ============================================================
# Doctor Command
# ============================================================

def doctor() -> None:
    """
    Run SCOPEX environment diagnostics.
    """

    console.print()

    console.print(
        "[bold cyan]SCOPEX SYSTEM DIAGNOSTICS[/bold cyan]"
    )

    console.print()

    table = Table(
        show_header=True,
        header_style="bold",
    )

    table.add_column("Component")
    table.add_column("Status")
    table.add_column("Details")

    checks: list[tuple[str, bool, str]] = []

    # --------------------------------------------------------
    # Python
    # --------------------------------------------------------

    success, details = check_python()

    checks.append(
        ("Python", success, details)
    )

    # --------------------------------------------------------
    # Directories
    # --------------------------------------------------------

    success, details = check_directories()

    checks.append(
        ("Directories", success, details)
    )

    # --------------------------------------------------------
    # Database
    # --------------------------------------------------------

    success, details = check_database()

    checks.append(
        ("SQLite Database", success, details)
    )

    # --------------------------------------------------------
    # Typer
    # --------------------------------------------------------

    success, details = check_dependency(
        "typer",
        "Typer",
    )

    checks.append(
        ("Typer", success, details)
    )

    # --------------------------------------------------------
    # Rich
    # --------------------------------------------------------

    success, details = check_dependency(
        "rich",
        "Rich",
    )

    checks.append(
        ("Rich", success, details)
    )

    # --------------------------------------------------------
    # SQLAlchemy
    # --------------------------------------------------------

    success, details = check_dependency(
        "sqlalchemy",
        "SQLAlchemy",
    )

    checks.append(
        ("SQLAlchemy", success, details)
    )

    # --------------------------------------------------------
    # Nmap
    # --------------------------------------------------------

    success, details = check_nmap()

    checks.append(
        ("Nmap", success, details)
    )

    # ========================================================
    # Render Results
    # ========================================================

    all_required_passed = True

    for component, success, details in checks:

        if success:
            status = "[green]PASS[/green]"

        else:
            status = "[red]FAIL[/red]"

            # Nmap is an external dependency.
            # It should not prevent the Python foundation
            # from being considered operational.
            if component != "Nmap":
                all_required_passed = False

        table.add_row(
            component,
            status,
            details,
        )

    console.print(table)

    console.print()

    if all_required_passed:
        console.print(
            "[bold green]SYSTEM READY[/bold green]"
        )
    else:
        console.print(
            "[bold red]SYSTEM NOT READY[/bold red]"
        )

    console.print()


# ============================================================
# Standalone Execution
# ============================================================

if __name__ == "__main__":
    doctor()