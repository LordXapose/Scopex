"""
SCOPEX DNS resolver.

Provides structured DNS resolution for authorized targets.

The resolver performs observation only. It does not perform
exploitation or interact with targets outside the authorized
scope enforced by the caller.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import dns.exception
import dns.resolver

from scopex.core.exceptions import CollectorError


@dataclass(frozen=True)
class DNSResult:
    """
    Represents the result of one DNS query.

    Attributes:
        query_name: Fully qualified name that was queried.
        record_type: DNS record type.
        values: Normalized record values.
        success: Whether the query completed successfully.
        error: Error description when the query failed.
    """

    query_name: str
    record_type: str
    values: tuple[str, ...] = field(default_factory=tuple)
    success: bool = False
    error: str | None = None


class DNSResolver:
    """
    Structured DNS resolver for SCOPEX.

    Uses dnspython instead of shell commands such as nslookup,
    allowing SCOPEX to work with structured DNS responses and
    explicit timeout controls.
    """

    SUPPORTED_RECORD_TYPES = (
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "NS",
        "TXT",
    )

    def __init__(
        self,
        timeout: float = 5.0,
        lifetime: float = 10.0,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero.")

        if lifetime <= 0:
            raise ValueError("lifetime must be greater than zero.")

        self.timeout = timeout
        self.lifetime = lifetime

        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = lifetime

    @staticmethod
    def normalize_name(name: str) -> str:
        """
        Normalize a DNS name.

        Removes whitespace and a trailing DNS root dot.
        """

        normalized = name.strip().lower().rstrip(".")

        if not normalized:
            raise ValueError("DNS name cannot be empty.")

        return normalized

    @staticmethod
    def normalize_value(
        record_type: str,
        value: Any,
    ) -> str:
        """
        Convert a DNS answer into a normalized string.
        """

        record_type = record_type.upper()

        if record_type in {"A", "AAAA"}:
            return str(value).strip()

        if record_type == "CNAME":
            return str(value).rstrip(".").lower()

        if record_type == "NS":
            return str(value).rstrip(".").lower()

        if record_type == "MX":
            preference = getattr(value, "preference", None)
            exchange = getattr(value, "exchange", None)

            if exchange is not None:
                exchange_name = str(exchange).lower()

                # A single "." is a meaningful DNS Null MX value.
                # Do not strip it.
                if exchange_name != ".":
                    exchange_name = exchange_name.rstrip(".")

                if preference is not None:
                    return f"{int(preference)} {exchange_name}"

                return exchange_name

            raw_value = str(value).strip()

            if raw_value:
                return raw_value.lower()

            return ""

        if record_type == "TXT":
            chunks = getattr(value, "strings", None)

            if chunks is not None:
                return "".join(
                    chunk.decode(
                        "utf-8",
                        errors="replace",
                    )
                    if isinstance(chunk, bytes)
                    else str(chunk)
                    for chunk in chunks
                )

            return str(value).strip().strip('"')

        return str(value).strip()

    def resolve_record(
        self,
        name: str,
        record_type: str,
    ) -> DNSResult:
        """
        Resolve one DNS record type.

        Returns a structured DNSResult instead of raising normal
        DNS lookup failures to the caller.
        """

        query_name = self.normalize_name(name)
        record_type = record_type.upper()

        if record_type not in self.SUPPORTED_RECORD_TYPES:
            raise ValueError(
                f"Unsupported DNS record type: {record_type}"
            )

        try:
            answer = self.resolver.resolve(
                query_name,
                record_type,
            )

            values = tuple(
                self.normalize_value(
                    record_type,
                    record,
                )
                for record in answer
            )

            return DNSResult(
                query_name=query_name,
                record_type=record_type,
                values=values,
                success=True,
            )

        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ) as exc:
            return DNSResult(
                query_name=query_name,
                record_type=record_type,
                success=False,
                error=self._format_dns_error(exc),
            )

        except Exception as exc:
            raise CollectorError(
                f"Unexpected DNS resolution error for "
                f"{query_name} ({record_type}): {exc}"
            ) from exc

    def resolve(
        self,
        name: str,
        record_types: tuple[str, ...] | None = None,
    ) -> list[DNSResult]:
        """
        Resolve multiple DNS record types for a name.

        By default, all supported record types are queried.
        """

        selected_types = (
            record_types
            if record_types is not None
            else self.SUPPORTED_RECORD_TYPES
        )

        return [
            self.resolve_record(
                name,
                record_type,
            )
            for record_type in selected_types
        ]

    @staticmethod
    def _format_dns_error(
        error: Exception,
    ) -> str:
        """Return a concise human-readable DNS error."""

        if isinstance(error, dns.resolver.NXDOMAIN):
            return "NXDOMAIN"

        if isinstance(error, dns.resolver.NoAnswer):
            return "NO_ANSWER"

        if isinstance(error, dns.resolver.NoNameservers):
            return "NO_NAMESERVERS"

        if isinstance(error, dns.exception.Timeout):
            return "TIMEOUT"

        return error.__class__.__name__