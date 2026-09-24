"""
SCOPEX subdomain discovery.

Provides controlled subdomain candidate generation for
authorized domains.

This module is responsible for generating and validating
candidate names. DNS resolution is intentionally handled
separately by DNSResolver.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from scopex.core.scope import ScopeManager, ScopeViolation


@dataclass(frozen=True)
class SubdomainCandidate:
    """
    Represents a normalized subdomain discovery candidate.

    Attributes:
        name: Fully qualified normalized domain name.
        root_domain: Authorized root domain.
        source: Discovery source, such as "wordlist".
    """

    name: str
    root_domain: str
    source: str


class SubdomainDiscovery:
    """
    Controlled subdomain candidate generator.

    The discovery engine does not perform DNS queries itself.
    It generates candidates which can later be passed to the
    DNS resolution layer.
    """

    DEFAULT_MAX_CANDIDATES = 10_000

    def __init__(
        self,
        scope_manager: ScopeManager,
        max_candidates: int = DEFAULT_MAX_CANDIDATES,
    ) -> None:
        if max_candidates <= 0:
            raise ValueError(
                "max_candidates must be greater than zero."
            )

        self.scope_manager = scope_manager
        self.max_candidates = max_candidates

    @staticmethod
    def normalize_domain(domain: str) -> str:
        """
        Normalize a domain name.

        Removes:
        - surrounding whitespace
        - HTTP/HTTPS schemes
        - paths
        - query strings
        - fragments
        - trailing DNS root dot

        Returns:
            Normalized lowercase domain.
        """

        normalized = domain.strip().lower()

        if normalized.startswith("https://"):
            normalized = normalized[8:]

        elif normalized.startswith("http://"):
            normalized = normalized[7:]

        normalized = normalized.split("/", 1)[0]
        normalized = normalized.split("?", 1)[0]
        normalized = normalized.split("#", 1)[0]
        normalized = normalized.rstrip(".")

        if not normalized:
            raise ValueError("Domain cannot be empty.")

        return normalized

    @staticmethod
    def normalize_label(label: str) -> str:
        """
        Normalize one subdomain label.
        """

        normalized = label.strip().lower().rstrip(".")

        if not normalized:
            raise ValueError(
                "Subdomain label cannot be empty."
            )

        if "." in normalized:
            raise ValueError(
                "Subdomain label must not contain dots."
            )

        return normalized

    @classmethod
    def build_candidate(
        cls,
        root_domain: str,
        label: str,
        source: str = "wordlist",
    ) -> SubdomainCandidate:
        """
        Build one normalized subdomain candidate.
        """

        root = cls.normalize_domain(root_domain)
        normalized_label = cls.normalize_label(label)

        name = f"{normalized_label}.{root}"

        return SubdomainCandidate(
            name=name,
            root_domain=root,
            source=source,
        )

    def discover_from_wordlist(
        self,
        root_domain: str,
        wordlist: Path,
    ) -> list[SubdomainCandidate]:
        """
        Generate subdomain candidates from a wordlist.

        Each non-empty, non-comment line represents one label.

        Duplicate labels are removed while preserving order.
        Candidates outside the authorized scope are rejected.
        """

        root = self.normalize_domain(root_domain)

        if not self.scope_manager.is_domain_allowed(root):
            raise ScopeViolation(
                f"Root domain is outside authorized scope: {root}"
            )

        if not wordlist.exists():
            raise FileNotFoundError(
                f"Wordlist does not exist: {wordlist}"
            )

        if not wordlist.is_file():
            raise ValueError(
                f"Wordlist path is not a file: {wordlist}"
            )

        candidates: list[SubdomainCandidate] = []
        seen: set[str] = set()

        with wordlist.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as handle:
            for raw_line in handle:
                label = raw_line.strip()

                if not label:
                    continue

                if label.startswith("#"):
                    continue

                try:
                    candidate = self.build_candidate(
                        root,
                        label,
                        source="wordlist",
                    )
                except ValueError:
                    continue

                if candidate.name in seen:
                    continue

                if not self.scope_manager.is_domain_allowed(
                    candidate.name
                ):
                    continue

                seen.add(candidate.name)
                candidates.append(candidate)

                if len(candidates) >= self.max_candidates:
                    break

        return candidates

    def discover_from_labels(
        self,
        root_domain: str,
        labels: list[str] | tuple[str, ...],
        source: str = "manual",
    ) -> list[SubdomainCandidate]:
        """
        Generate candidates from an in-memory collection of labels.

        Useful for testing and future passive discovery sources.
        """

        root = self.normalize_domain(root_domain)

        if not self.scope_manager.is_domain_allowed(root):
            raise ScopeViolation(
                f"Root domain is outside authorized scope: {root}"
            )

        candidates: list[SubdomainCandidate] = []
        seen: set[str] = set()

        for label in labels:
            if len(candidates) >= self.max_candidates:
                break

            try:
                candidate = self.build_candidate(
                    root,
                    label,
                    source=source,
                )
            except ValueError:
                continue

            if candidate.name in seen:
                continue

            if not self.scope_manager.is_domain_allowed(
                candidate.name
            ):
                continue

            seen.add(candidate.name)
            candidates.append(candidate)

        return candidates