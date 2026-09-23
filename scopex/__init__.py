"""
SCOPEX - External Attack Surface Intelligence Platform.

SCOPEX is a Windows-native platform for authorized external
attack-surface discovery, asset intelligence, evidence collection,
and historical monitoring.
"""

__version__ = "0.1.0"
__author__ = "kenil4sec"
__description__ = "External Attack Surface Intelligence Platform"


def get_version() -> str:
    """Return the current SCOPEX version."""
    return __version__