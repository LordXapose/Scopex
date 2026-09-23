"""
SCOPEX exception integration tests.
"""

import pytest

from scopex.core.exceptions import (
    CollectorError,
    ConfigurationError,
    DatabaseError,
    RepositoryError,
    ScopeError,
    ScopeXError,
    ScannerError,
    TargetValidationError,
)


@pytest.mark.parametrize(
    "exception_class",
    [
        ConfigurationError,
        DatabaseError,
        ScopeError,
        ScannerError,
        TargetValidationError,
        CollectorError,
        RepositoryError,
    ],
)
def test_exception_hierarchy(
    exception_class,
):
    """Test that all SCOPEX exceptions inherit from ScopeXError."""

    error = exception_class(
        "Test error"
    )

    assert isinstance(
        error,
        ScopeXError,
    )


def test_exception_message():
    """Test that exception messages are preserved."""

    message = (
        "Target is outside authorized scope."
    )

    error = ScopeError(message)

    assert str(error) == message
    assert error.message == message


def test_exception_handling():
    """Test catching a specialized SCOPEX exception."""

    with pytest.raises(
        ScopeXError,
        match="Invalid scan target.",
    ):
        raise TargetValidationError(
            "Invalid scan target."
        )