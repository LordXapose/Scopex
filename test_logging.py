"""
SCOPEX logging integration tests.
"""

from pathlib import Path

from scopex.core.logging import (
    LOG_FILE,
    configure_logging,
    get_logger,
    shutdown_logging,
)


def test_logging_configuration():
    """Test that SCOPEX logging can be configured."""

    configure_logging()

    logger = get_logger(
        "scopex.pytest"
    )

    assert logger is not None

    logger.info(
        "SCOPEX pytest logging test."
    )

    shutdown_logging()

    assert Path(LOG_FILE).exists()


def test_logger_creation():
    """Test creation of named loggers."""

    configure_logging()

    logger = get_logger(
        "scopex.test.logger"
    )

    assert logger.name == (
        "scopex.test.logger"
    )

    shutdown_logging()