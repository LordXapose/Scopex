"""
SCOPEX DNS resolution engine.

Combines controlled subdomain candidates with structured DNS
resolution and produces normalized resolution results.

This module performs observation only. It does not write to the
database, perform exploitation, or interact with targets outside
the authorized scope enforced by ScopeManager.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from scopex.core.scope import ScopeManager, ScopeViolation
from scopex.dns.discovery import SubdomainCandidate
from scopex.dns.resolver import DNSResolver


class ResolutionStatus(str, Enum):
    """
    Overall status of a DNS resolution attempt.
    """

    RESOLVED = "resolved"
    PARTIAL = "partial"
    UNRESOLVED = "unresolved"
    ERROR = "error"


@dataclass(frozen=True)
class ResolutionResult:
    """
    Structured DNS resolution result for one subdomain candidate.
    """

    name: str
    root_domain: str
    source: str
    ipv4: tuple[str, ...] = field(default_factory=tuple)
    ipv6: tuple[str, ...] = field(default_factory=tuple)
    cnames: tuple[str, ...] = field(default_factory=tuple)
    status: ResolutionStatus = ResolutionStatus.UNRESOLVED
    errors: tuple[str, ...] = field(default_factory=tuple)


class DNSResolutionEngine:
    """
    Resolve authorized subdomain candidates.

    The engine keeps candidate generation, DNS resolution, and
    persistence separate. It only produces structured results.
    """

    DEFAULT_RECORD_TYPES = (
        "A",
        "AAAA",
        "CNAME",
    )

    DEFAULT_MAX_CANDIDATES = 10_000

    def __init__(
        self,
        resolver: DNSResolver,
        scope_manager: ScopeManager,
        max_candidates: int = DEFAULT_MAX_CANDIDATES,
        record_types: tuple[str, ...] = DEFAULT_RECORD_TYPES,
    ) -> None:
        if max_candidates <= 0:
            raise ValueError(
                "max_candidates must be greater than zero."
            )

        if not record_types:
            raise ValueError(
                "record_types cannot be empty."
            )

        normalized_types = tuple(
            record_type.strip().upper()
            for record_type in record_types
        )

        if any(not record_type for record_type in normalized_types):
            raise ValueError(
                "record_types cannot contain empty values."
            )

        unsupported = set(normalized_types) - set(
            DNSResolver.SUPPORTED_RECORD_TYPES
        )

        if unsupported:
            unsupported_display = ", ".join(
                sorted(unsupported)
            )

            raise ValueError(
                "Unsupported DNS record type(s): "
                f"{unsupported_display}"
            )

        self.resolver = resolver
        self.scope_manager = scope_manager
        self.max_candidates = max_candidates
        self.record_types = normalized_types

    @staticmethod
    def _append_unique(
        values: list[str],
        new_values: tuple[str, ...],
    ) -> None:
        """
        Append values while preserving insertion order and
        preventing duplicates.
        """

        existing = set(values)

        for value in new_values:
            if value not in existing:
                values.append(value)
                existing.add(value)

    @staticmethod
    def _deduplicate(
        values: list[str] | tuple[str, ...],
    ) -> list[str]:
        """
        Remove duplicates while preserving insertion order.
        """

        return list(dict.fromkeys(values))

    def resolve_candidate(
        self,
        candidate: SubdomainCandidate,
    ) -> ResolutionResult:
        """
        Resolve one authorized subdomain candidate.

        Scope is checked again immediately before resolution so
        callers cannot bypass authorization by constructing a
        candidate manually.
        """

        name = candidate.name.strip().lower().rstrip(".")
        root_domain = (
            candidate.root_domain.strip().lower().rstrip(".")
        )

        if not self.scope_manager.is_domain_allowed(root_domain):
            raise ScopeViolation(
                f"root domain is outside authorized scope: "
                f"{root_domain}"
            )

        if not self.scope_manager.is_domain_allowed(name):
            raise ScopeViolation(
                f"candidate is outside authorized scope: "
                f"{name}"
            )

        ipv4: list[str] = []
        ipv6: list[str] = []
        cnames: list[str] = []
        errors: list[str] = []

        try:
            results = self.resolver.resolve(
                name,
                record_types=self.record_types,
            )
        except Exception as exc:
            return ResolutionResult(
                name=name,
                root_domain=root_domain,
                source=candidate.source,
                status=ResolutionStatus.ERROR,
                errors=(str(exc),),
            )

        for result in results:
            if result.success:
                if result.record_type == "A":
                    self._append_unique(
                        ipv4,
                        result.values,
                    )

                elif result.record_type == "AAAA":
                    self._append_unique(
                        ipv6,
                        result.values,
                    )

                elif result.record_type == "CNAME":
                    self._append_unique(
                        cnames,
                        result.values,
                    )

            elif result.error:
                errors.append(
                    f"{result.record_type}:{result.error}"
                )

        errors = self._deduplicate(errors)

        has_addresses = bool(ipv4 or ipv6)
        has_cname = bool(cnames)

        if has_addresses or has_cname:
            if errors:
                status = ResolutionStatus.PARTIAL
            else:
                status = ResolutionStatus.RESOLVED
        else:
            status = ResolutionStatus.UNRESOLVED

        return ResolutionResult(
            name=name,
            root_domain=root_domain,
            source=candidate.source,
            ipv4=tuple(ipv4),
            ipv6=tuple(ipv6),
            cnames=tuple(cnames),
            status=status,
            errors=tuple(errors),
        )

    def resolve_candidates(
        self,
        candidates: list[SubdomainCandidate]
        | tuple[SubdomainCandidate, ...],
    ) -> list[ResolutionResult]:
        """
        Resolve a bounded collection of candidates.

        Processing stops at max_candidates.
        """

        results: list[ResolutionResult] = []

        for candidate in candidates:
            if len(results) >= self.max_candidates:
                break

            results.append(
                self.resolve_candidate(candidate)
            )

        return results