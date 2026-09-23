"""
SCOPEX scope management.

This module defines the authorization boundary for SCOPEX.

Only explicitly authorized domains, IPv4 addresses, and IPv4
networks may be used as reconnaissance targets.

Scope authorization is persisted in SQLite, while normalized
targets are kept in memory for fast validation.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Address, IPv4Network
from typing import Iterable

from scopex.database.database import session_scope
from scopex.database.scope_repository import ScopeRepository


# ============================================================
# Exceptions
# ============================================================


class ScopeViolation(Exception):
    """Raised when a target is outside the authorized scope."""

    def __init__(
        self,
        target: str,
        message: str | None = None,
    ) -> None:
        self.target = target

        if message is None:
            message = (
                f"Target is outside the authorized scope: "
                f"{target}"
            )

        super().__init__(message)


class InvalidTarget(Exception):
    """Raised when a target cannot be normalized or parsed."""


# ============================================================
# Scope Types
# ============================================================


class ScopeType(str, Enum):
    """Supported SCOPEX authorization target types."""

    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"


# ============================================================
# Scope Entry
# ============================================================


@dataclass(frozen=True)
class ScopeEntry:
    """Represents one normalized scope entry."""

    value: str
    scope_type: ScopeType


# ============================================================
# Normalization Helpers
# ============================================================


_DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


def normalize_domain(value: str) -> str:
    """
    Normalize and validate a domain name.

    Supported input examples:

        example.com
        Example.COM
        https://example.com
        https://example.com/path
        example.com.
    """

    if not isinstance(value, str):
        raise InvalidTarget("Domain must be a string.")

    normalized = value.strip().lower()

    if not normalized:
        raise InvalidTarget("Domain cannot be empty.")

    # Remove HTTP(S) scheme.
    if normalized.startswith("https://"):
        normalized = normalized[8:]

    elif normalized.startswith("http://"):
        normalized = normalized[7:]

    # Remove path.
    normalized = normalized.split("/", 1)[0]

    # Remove query string.
    normalized = normalized.split("?", 1)[0]

    # Remove fragment.
    normalized = normalized.split("#", 1)[0]

    # Remove trailing dot.
    normalized = normalized.rstrip(".")

    # Remove port when supplied.
    if ":" in normalized:
        host, port = normalized.rsplit(":", 1)

        if port.isdigit():
            normalized = host

    if not _DOMAIN_PATTERN.fullmatch(normalized):
        raise InvalidTarget(
            f"Invalid domain: {value}"
        )

    return normalized


def normalize_ip(value: str) -> str:
    """
    Normalize and validate an IPv4 address.
    """

    if not isinstance(value, str):
        raise InvalidTarget("IP address must be a string.")

    normalized = value.strip()

    try:
        address = ipaddress.ip_address(normalized)

    except ValueError as exc:
        raise InvalidTarget(
            f"Invalid IP address: {value}"
        ) from exc

    if not isinstance(address, IPv4Address):
        raise InvalidTarget(
            f"Only IPv4 addresses are currently supported: {value}"
        )

    return str(address)


def normalize_cidr(value: str) -> str:
    """
    Normalize and validate an IPv4 CIDR network.

    strict=False allows inputs such as:

        192.168.1.10/24

    which become:

        192.168.1.0/24
    """

    if not isinstance(value, str):
        raise InvalidTarget("CIDR must be a string.")

    normalized = value.strip()

    try:
        network = ipaddress.ip_network(
            normalized,
            strict=False,
        )

    except ValueError as exc:
        raise InvalidTarget(
            f"Invalid CIDR network: {value}"
        ) from exc

    if not isinstance(network, IPv4Network):
        raise InvalidTarget(
            f"Only IPv4 CIDR networks are currently supported: {value}"
        )

    return str(network)


# ============================================================
# Scope Manager
# ============================================================


class ScopeManager:
    """
    Manage authorized SCOPEX targets.

    The manager keeps normalized scope in memory for fast
    authorization checks and loads persisted authorization
    entries from SQLite when initialized.
    """

    def __init__(
        self,
        domains: Iterable[str] | None = None,
        ips: Iterable[str] | None = None,
        cidrs: Iterable[str] | None = None,
    ) -> None:
        self._domains: set[str] = set()
        self._ips: set[IPv4Address] = set()
        self._networks: set[IPv4Network] = set()

        # Load persistent authorization first.
        self._load_persisted_scope()

        # Optional initial in-memory targets.
        if domains:
            for domain in domains:
                self.add_domain(domain)

        if ips:
            for ip_address in ips:
                self.add_ip(ip_address)

        if cidrs:
            for network in cidrs:
                self.add_cidr(network)

    # ========================================================
    # Persistence Loading
    # ========================================================

    def _load_persisted_scope(self) -> None:
        """
        Load enabled authorized targets from SQLite.
        """

        with session_scope() as session:
            repository = ScopeRepository(session)

            targets = repository.get_all(
                enabled_only=True,
            )

            for target in targets:

                if target.target_type == ScopeType.DOMAIN.value:
                    self._domains.add(
                        target.value
                    )

                elif target.target_type == ScopeType.IP.value:
                    self._ips.add(
                        IPv4Address(target.value)
                    )

                elif target.target_type == ScopeType.CIDR.value:
                    self._networks.add(
                        IPv4Network(
                            target.value,
                            strict=False,
                        )
                    )

    # ========================================================
    # Add Targets
    # ========================================================

    def add_domain(
        self,
        domain: str,
    ) -> None:
        """
        Add a domain to the in-memory authorization scope.
        """

        normalized = normalize_domain(domain)

        self._domains.add(normalized)

    def add_ip(
        self,
        ip_address: str,
    ) -> None:
        """
        Add an IPv4 address to the in-memory authorization scope.
        """

        normalized = normalize_ip(ip_address)

        self._ips.add(
            IPv4Address(normalized)
        )

    def add_cidr(
        self,
        network: str,
    ) -> None:
        """
        Add an IPv4 CIDR network to the in-memory authorization scope.
        """

        normalized = normalize_cidr(network)

        self._networks.add(
            IPv4Network(
                normalized,
                strict=False,
            )
        )

    # ========================================================
    # Properties
    # ========================================================

    @property
    def domains(self) -> set[str]:
        """Return a copy of authorized domains."""

        return set(self._domains)

    @property
    def ips(self) -> set[IPv4Address]:
        """Return a copy of authorized IPv4 addresses."""

        return set(self._ips)

    @property
    def networks(self) -> set[IPv4Network]:
        """Return a copy of authorized IPv4 networks."""

        return set(self._networks)

    # ========================================================
    # Authorization Checks
    # ========================================================

    def is_domain_allowed(
        self,
        domain: str,
    ) -> bool:
        """
        Determine whether a domain is authorized.

        Exact domains and subdomains of an authorized domain
        are allowed.

        Example:

            authorized: example.com

            allowed:
                example.com
                api.example.com
                dev.api.example.com

            blocked:
                example.com.evil.com
        """

        normalized = normalize_domain(domain)

        if normalized in self._domains:
            return True

        for authorized_domain in self._domains:
            if normalized.endswith(
                "." + authorized_domain
            ):
                return True

        return False

    def is_ip_allowed(
        self,
        ip_address: str,
    ) -> bool:
        """
        Determine whether an IPv4 address is authorized.
        """

        normalized = IPv4Address(
            normalize_ip(ip_address)
        )

        if normalized in self._ips:
            return True

        for network in self._networks:
            if normalized in network:
                return True

        return False

    def is_allowed(
        self,
        target: str,
    ) -> bool:
        """
        Determine whether a target is authorized.

        The target is interpreted first as an IPv4 address.
        If that fails, it is treated as a domain.
        """

        try:
            return self.is_ip_allowed(target)

        except InvalidTarget:
            pass

        try:
            return self.is_domain_allowed(target)

        except InvalidTarget:
            return False

    # ========================================================
    # Validation
    # ========================================================

    def validate(
        self,
        target: str,
    ) -> str:
        """
        Validate and normalize a target.

        Returns:
            Normalized target.

        Raises:
            ScopeViolation:
                If the target is valid but unauthorized.

            InvalidTarget:
                If the target cannot be parsed.
        """

        try:
            normalized_ip = normalize_ip(target)

            if not self.is_ip_allowed(normalized_ip):
                raise ScopeViolation(
                    target=target,
                    message=(
                        f"IP address is outside the "
                        f"authorized scope: {target}"
                    ),
                )

            return normalized_ip

        except InvalidTarget:
            pass

        normalized_domain = normalize_domain(target)

        if not self.is_domain_allowed(
            normalized_domain
        ):
            raise ScopeViolation(
                target=target,
                message=(
                    f"Domain is outside the "
                    f"authorized scope: {target}"
                ),
            )

        return normalized_domain

    # ========================================================
    # Summary
    # ========================================================

    def summary(self) -> dict[str, list[str]]:
        """
        Return a human-readable scope summary.
        """

        return {
            "domain": sorted(
                self._domains
            ),
            "ip": sorted(
                str(ip)
                for ip in self._ips
            ),
            "cidr": sorted(
                str(network)
                for network in self._networks
            ),
        }