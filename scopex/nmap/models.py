"""
Structured models for Nmap scan results.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class NmapPort:
    """
    Represents one port discovered by Nmap.
    """

    port: int
    protocol: str
    state: str
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None


@dataclass(frozen=True)
class NmapHostResult:
    """
    Represents the structured result for one scanned host.
    """

    address: str
    address_type: str
    hostnames: tuple[str, ...] = field(default_factory=tuple)
    status: str = "unknown"
    ports: tuple[NmapPort, ...] = field(default_factory=tuple)
    os_name: str | None = None
    os_accuracy: int | None = None