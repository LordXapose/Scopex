"""
SCOPEX application exceptions.

Defines structured exception types used throughout SCOPEX.
"""


class ScopeXError(Exception):
    """
    Base exception for all SCOPEX-specific errors.
    """

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class ConfigurationError(ScopeXError):
    """
    Raised when SCOPEX configuration is invalid.
    """


class DatabaseError(ScopeXError):
    """
    Raised when a database operation fails.
    """


class ScopeError(ScopeXError):
    """
    Raised when a target violates the authorized scan scope.
    """


class ScannerError(ScopeXError):
    """
    Raised when a scanner or collector encounters an error.
    """


class TargetValidationError(ScopeXError):
    """
    Raised when a scan target is invalid.
    """


class CollectorError(ScopeXError):
    """
    Raised when a reconnaissance collector fails.
    """


class RepositoryError(ScopeXError):
    """
    Raised when a repository operation fails.
    """
    