"""
SCOPEX configuration management.

This module provides a centralized configuration object for the
SCOPEX application.

Configuration is designed to work natively on Windows and uses
environment variables where appropriate.
"""

from pathlib import Path


# ============================================================
# Project Paths
# ============================================================

# scopex/core/config.py
# parents[0] = core/
# parents[1] = scopex/
# parents[2] = project root/
PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data"
LOG_DIR = PROJECT_ROOT / "logs"
DATABASE_PATH = DATA_DIR / "scopex.db"


# ============================================================
# Application Information
# ============================================================

APP_NAME = "SCOPEX"
APP_DESCRIPTION = "External Attack Surface Intelligence Platform"


# ============================================================
# Scanner Configuration
# ============================================================

DEFAULT_TIMEOUT = 10
MAX_CONCURRENCY = 10

# Nmap executable.
# If Nmap is available in PATH, simply using "nmap" is enough.
NMAP_PATH = "nmap"


# ============================================================
# Runtime Configuration
# ============================================================

DEBUG = False


# ============================================================
# Configuration Initialization
# ============================================================

def ensure_directories() -> None:
    """
    Create required SCOPEX directories if they do not exist.
    """

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def get_database_path() -> Path:
    """
    Return the absolute path to the SCOPEX SQLite database.
    """

    return DATABASE_PATH


def get_project_root() -> Path:
    """
    Return the SCOPEX project root directory.
    """

    return PROJECT_ROOT