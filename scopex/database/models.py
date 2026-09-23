"""
SCOPEX database models.

Core entities:

    ScopeTarget

    Scan
      └── Asset
            └── Service

    Asset
      └── Evidence

The initial schema is intentionally small. More specialized
entities will be introduced as the platform develops.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)

from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)


# ============================================================
# Base
# ============================================================

class Base(DeclarativeBase):
    """Base class for all SCOPEX database models."""

    pass


# ============================================================
# Timestamp Helper
# ============================================================

def utc_now() -> datetime:
    """Return the current UTC time."""

    return datetime.now(timezone.utc)


# ============================================================
# Scope Target
# ============================================================

class ScopeTarget(Base):
    """
    Represents one persistent authorized SCOPEX target.

    Scope targets are independent of individual scans.

    Examples:

        example.com
        192.168.1.10
        192.168.1.0/24
    """

    __tablename__ = "scope_targets"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    target_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    value: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    enabled: Mapped[bool] = mapped_column(
        nullable=False,
        default=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "target_type",
            "value",
            name="uq_scope_target",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<ScopeTarget id={self.id} "
            f"type={self.target_type!r} "
            f"value={self.value!r} "
            f"enabled={self.enabled}>"
        )


# ============================================================
# Scan
# ============================================================

class Scan(Base):
    """
    Represents one SCOPEX reconnaissance operation.
    """

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    target: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    scan_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="recon",
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="running",
    )

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # Relationships

    assets: Mapped[list["Asset"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )

    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return (
            f"<Scan id={self.id} "
            f"target={self.target!r} "
            f"status={self.status!r}>"
        )


# ============================================================
# Asset
# ============================================================

class Asset(Base):
    """
    Represents a discovered external asset.

    Examples:

        example.com
        api.example.com
        203.0.113.10
    """

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id"),
        nullable=False,
        index=True,
    )

    asset_type: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        index=True,
    )

    value: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    hostname: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    ip_address: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="active",
    )

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    # Relationships

    scan: Mapped["Scan"] = relationship(
        back_populates="assets",
    )

    services: Mapped[list["Service"]] = relationship(
        back_populates="asset",
        cascade="all, delete-orphan",
    )

    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="asset",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "asset_type",
            "value",
            name="uq_scan_asset",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<Asset id={self.id} "
            f"type={self.asset_type!r} "
            f"value={self.value!r}>"
        )


# ============================================================
# Service
# ============================================================

class Service(Base):
    """
    Represents a network service discovered on an asset.
    """

    __tablename__ = "services"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id"),
        nullable=False,
        index=True,
    )

    port: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    protocol: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default="tcp",
    )

    state: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="open",
    )

    service_name: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    product: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    version: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    # Relationship

    asset: Mapped["Asset"] = relationship(
        back_populates="services",
    )

    __table_args__ = (
        UniqueConstraint(
            "asset_id",
            "port",
            "protocol",
            name="uq_asset_service",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<Service id={self.id} "
            f"port={self.port}/{self.protocol} "
            f"service={self.service_name!r}>"
        )


# ============================================================
# Evidence
# ============================================================

class Evidence(Base):
    """
    Represents raw or structured evidence collected by SCOPEX.

    Evidence is deliberately separated from findings.

    SCOPEX should store what was actually observed before
    attempting to interpret it.
    """

    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id"),
        nullable=False,
        index=True,
    )

    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id"),
        nullable=True,
        index=True,
    )

    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    evidence_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    data: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    confidence: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=50,
    )

    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    # Relationships

    scan: Mapped["Scan"] = relationship(
        back_populates="evidence",
    )

    asset: Mapped["Asset | None"] = relationship(
        back_populates="evidence",
    )

    def __repr__(self) -> str:
        return (
            f"<Evidence id={self.id} "
            f"source={self.source!r} "
            f"type={self.evidence_type!r} "
            f"confidence={self.confidence}>"
        )