"""
SCOPEX end-to-end DNS scan orchestration.

Coordinates:

    Authorized Scope
        ↓
    Subdomain Discovery
        ↓
    DNS Resolution
        ↓
    Asset Intelligence
        ↓
    SQLite persistence

The orchestrator is intentionally limited to authorized
domain targets. IP scanning will be introduced later.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from scopex.assets.intelligence import AssetIntelligence
from scopex.core.scope import ScopeManager
from scopex.database.database import session_scope
from scopex.database.models import Evidence, Scan
from scopex.dns.discovery import SubdomainCandidate, SubdomainDiscovery
from scopex.dns.resolution import (
    DNSResolutionEngine,
    ResolutionResult,
    ResolutionStatus,
)
from scopex.dns.resolver import DNSResolver


@dataclass(frozen=True)
class ScanSummary:
    """Summary returned after a scan completes."""

    scan_id: int
    target: str
    status: str
    candidates: int
    resolved: int
    partial: int
    unresolved: int
    errors: int
    assets: int
    evidence: int


class ScanOrchestrator:
    """
    Coordinate the complete DNS reconnaissance workflow.
    """

    def __init__(
        self,
        scope_manager: Optional[ScopeManager] = None,
        resolver: Optional[DNSResolver] = None,
        max_candidates: int = 10_000,
    ) -> None:
        self.scope_manager = scope_manager or ScopeManager()

        self.discovery = SubdomainDiscovery(
            scope_manager=self.scope_manager,
            max_candidates=max_candidates,
        )

        self.resolver = resolver or DNSResolver()

        self.resolution_engine = DNSResolutionEngine(
            scope_manager=self.scope_manager,
            resolver=self.resolver,
            max_candidates=max_candidates,
        )

        self.asset_intelligence = AssetIntelligence()

    def run(
        self,
        target: str,
        wordlist: Optional[Path] = None,
    ) -> ScanSummary:
        """
        Execute a complete DNS scan.
        """

        normalized_target = self._validate_domain_target(target)

        if wordlist is not None and not wordlist.exists():
            raise FileNotFoundError(
                f"Wordlist does not exist: {wordlist}"
            )

        candidates = self._build_candidates(
            normalized_target,
            wordlist,
        )

        scan_id = self._create_scan(normalized_target)

        try:
            results = self.resolution_engine.resolve_candidates(
                candidates
            )

            asset_count = 0
            evidence_count = 0

            with session_scope() as session:
                for result in results:
                    assets = self.asset_intelligence.persist_resolution(
                        session=session,
                        scan_id=scan_id,
                        result=result,
                    )

                    asset_count += len(assets)

                # Make newly-added Asset and Evidence objects visible
                # to database queries before counting them.
                session.flush()

                evidence_count = (
                    session.query(Evidence)
                    .filter(Evidence.scan_id == scan_id)
                    .count()
                )

                scan = session.get(Scan, scan_id)

                if scan is None:
                    raise RuntimeError(
                        f"Scan record not found: {scan_id}"
                    )

                scan.status = "completed"
                scan.completed_at = datetime.now(timezone.utc)

                # Explicitly flush the final scan state so the
                # completed timestamp is persisted before leaving
                # the transaction.
                session.flush()

            return self._build_summary(
                scan_id=scan_id,
                target=normalized_target,
                results=results,
                asset_count=asset_count,
                evidence_count=evidence_count,
            )

        except Exception as exc:
            self._mark_scan_failed(
                scan_id=scan_id,
                error_message=str(exc),
            )
            raise

    def _validate_domain_target(self, target: str) -> str:
        """
        Validate that the target is a domain.

        IP addresses are rejected before scope validation because
        this phase only supports DNS/domain scanning.
        """

        if not target or not target.strip():
            raise ValueError("Scan target cannot be empty.")

        normalized_target = target.strip()

        try:
            ipaddress.ip_address(normalized_target)
        except ValueError:
            pass
        else:
            raise ValueError(
                "The current DNS scan supports domain targets only. "
                "IP scanning will be added in a later scanner phase."
            )

        return self.scope_manager.validate(normalized_target)

    def _build_candidates(
        self,
        target: str,
        wordlist: Optional[Path],
    ) -> list[SubdomainCandidate]:
        """
        Build the ordered candidate list.

        The root domain is always included first.
        """

        candidates = [
            SubdomainCandidate(
                name=target,
                root_domain=target,
                source="root",
            )
        ]

        if wordlist is not None:
            discovered = self.discovery.discover_from_wordlist(
                root_domain=target,
                wordlist=wordlist,
            )

            existing = {
                candidate.name
                for candidate in candidates
            }

            for candidate in discovered:
                if candidate.name not in existing:
                    candidates.append(candidate)
                    existing.add(candidate.name)

        return candidates

    def _create_scan(self, target: str) -> int:
        """
        Create and persist a running scan record.
        """

        with session_scope() as session:
            scan = Scan(
                target=target,
                scan_type="dns",
                status="running",
            )

            session.add(scan)
            session.flush()

            return scan.id

    def _mark_scan_failed(
        self,
        scan_id: int,
        error_message: str,
    ) -> None:
        """
        Mark a scan as failed.
        """

        with session_scope() as session:
            scan = session.get(Scan, scan_id)

            if scan is None:
                return

            scan.status = "failed"
            scan.error_message = error_message
            scan.completed_at = datetime.now(timezone.utc)

            session.flush()

    def _build_summary(
        self,
        scan_id: int,
        target: str,
        results: list[ResolutionResult],
        asset_count: int,
        evidence_count: int,
    ) -> ScanSummary:
        """
        Build a deterministic scan summary.
        """

        resolved = sum(
            result.status == ResolutionStatus.RESOLVED
            for result in results
        )

        partial = sum(
            result.status == ResolutionStatus.PARTIAL
            for result in results
        )

        unresolved = sum(
            result.status == ResolutionStatus.UNRESOLVED
            for result in results
        )

        errors = sum(
            result.status == ResolutionStatus.ERROR
            for result in results
        )

        return ScanSummary(
            scan_id=scan_id,
            target=target,
            status="completed",
            candidates=len(results),
            resolved=resolved,
            partial=partial,
            unresolved=unresolved,
            errors=errors,
            assets=asset_count,
            evidence=evidence_count,
        )