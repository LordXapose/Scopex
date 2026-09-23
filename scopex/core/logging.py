"""
SCOPEX logging configuration.

Provides centralized application logging with:
- Console output
- Rotating log files
- Consistent formatting
- Module-level loggers
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from scopex.core.config import LOG_DIR, ensure_directories


# ============================================================
# Logging Configuration
# ============================================================

LOG_FILE = LOG_DIR / "scopex.log"

LOG_FORMAT = (
    "%(asctime)s | "
    "%(levelname)-8s | "
    "%(name)s | "
    "%(message)s"
)

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

DEFAULT_LOG_LEVEL = logging.INFO

MAX_LOG_SIZE = 5 * 1024 * 1024  # 5 MB
BACKUP_COUNT = 3


# ============================================================
# Logging Initialization
# ============================================================

def configure_logging(
    level: int = DEFAULT_LOG_LEVEL,
) -> None:
    """
    Configure SCOPEX application logging.

    Creates:
        - Console handler
        - Rotating file handler

    Args:
        level: Python logging level.
    """

    ensure_directories()

    root_logger = logging.getLogger()

    # Prevent duplicate handlers if configure_logging()
    # is called more than once.
    if getattr(root_logger, "_scopex_configured", False):
        return

    root_logger.setLevel(level)

    formatter = logging.Formatter(
        fmt=LOG_FORMAT,
        datefmt=DATE_FORMAT,
    )

    # --------------------------------------------------------
    # Console Handler
    # --------------------------------------------------------

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)

    # --------------------------------------------------------
    # Rotating File Handler
    # --------------------------------------------------------

    file_handler = RotatingFileHandler(
        filename=LOG_FILE,
        maxBytes=MAX_LOG_SIZE,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )

    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)

    # --------------------------------------------------------
    # Register Handlers
    # --------------------------------------------------------

    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    root_logger._scopex_configured = True


# ============================================================
# Logger Factory
# ============================================================

def get_logger(name: str) -> logging.Logger:
    """
    Return a named SCOPEX logger.

    Example:
        logger = get_logger("scopex.scanner")
    """

    return logging.getLogger(name)


# ============================================================
# Logging Shutdown
# ============================================================

def shutdown_logging() -> None:
    """
    Shut down the Python logging system cleanly.
    """

    logging.shutdown()