"""
SCOPEX scan orchestration package.

Provides controlled orchestration of authorized
attack-surface discovery workflows.
"""

from scopex.scan.orchestrator import (
    ScanOrchestrator,
    ScanSummary,
)

__all__ = [
    "ScanOrchestrator",
    "ScanSummary",
]