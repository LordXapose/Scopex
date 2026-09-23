"""
SCOPEX database repositories.

Repositories provide a clean interface between the application
logic and the SQLAlchemy database layer.

Application components should use repositories instead of
performing raw SQLAlchemy queries directly.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from scopex.database.models import (
    Asset,
    Evidence,
    Scan,
    Service,
)


# ============================================================
# Scan Repository
# ============================================================

class ScanRepository:
    """Database operations related to scans."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create(
        self,
        target: str,
        scan_type: str = "recon",
        status: str = "running",
    ) -> Scan:
        """Create and persist a new scan."""

        scan = Scan(
            target=target,
            scan_type=scan_type,
            status=status,
        )

        self.session.add(scan)
        self.session.flush()

        return scan

    def get_by_id(self, scan_id: int) -> Optional[Scan]:
        """Return a scan by ID."""

        return self.session.get(Scan, scan_id)

    def get_latest(self) -> Optional[Scan]:
        """Return the most recently created scan."""

        return (
            self.session.query(Scan)
            .order_by(Scan.id.desc())
            .first()
        )

    def update_status(
        self,
        scan_id: int,
        status: str,
        error_message: Optional[str] = None,
    ) -> Optional[Scan]:
        """Update scan status and optionally record an error."""

        scan = self.get_by_id(scan_id)

        if scan is None:
            return None

        scan.status = status
        scan.error_message = error_message

        return scan


# ============================================================
# Asset Repository
# ============================================================

class AssetRepository:
    """Database operations related to assets."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create(
        self,
        scan_id: int,
        asset_type: str,
        value: str,
        hostname: Optional[str] = None,
        ip_address: Optional[str] = None,
        status: str = "active",
    ) -> Asset:
        """Create and persist an asset."""

        asset = Asset(
            scan_id=scan_id,
            asset_type=asset_type,
            value=value,
            hostname=hostname,
            ip_address=ip_address,
            status=status,
        )

        self.session.add(asset)
        self.session.flush()

        return asset

    def get_by_id(self, asset_id: int) -> Optional[Asset]:
        """Return an asset by ID."""

        return self.session.get(Asset, asset_id)

    def get_by_scan(self, scan_id: int) -> list[Asset]:
        """Return all assets belonging to a scan."""

        return (
            self.session.query(Asset)
            .filter(Asset.scan_id == scan_id)
            .order_by(Asset.id)
            .all()
        )

    def get_by_value(
        self,
        scan_id: int,
        asset_type: str,
        value: str,
    ) -> Optional[Asset]:
        """Find an asset by scan, type, and value."""

        return (
            self.session.query(Asset)
            .filter(
                Asset.scan_id == scan_id,
                Asset.asset_type == asset_type,
                Asset.value == value,
            )
            .first()
        )


# ============================================================
# Service Repository
# ============================================================

class ServiceRepository:
    """Database operations related to network services."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create(
        self,
        asset_id: int,
        port: int,
        protocol: str = "tcp",
        state: str = "open",
        service_name: Optional[str] = None,
        product: Optional[str] = None,
        version: Optional[str] = None,
    ) -> Service:
        """Create and persist a discovered service."""

        service = Service(
            asset_id=asset_id,
            port=port,
            protocol=protocol,
            state=state,
            service_name=service_name,
            product=product,
            version=version,
        )

        self.session.add(service)
        self.session.flush()

        return service

    def get_by_id(self, service_id: int) -> Optional[Service]:
        """Return a service by ID."""

        return self.session.get(Service, service_id)

    def get_by_asset(self, asset_id: int) -> list[Service]:
        """Return all services belonging to an asset."""

        return (
            self.session.query(Service)
            .filter(Service.asset_id == asset_id)
            .order_by(Service.port)
            .all()
        )


# ============================================================
# Evidence Repository
# ============================================================

class EvidenceRepository:
    """Database operations related to collected evidence."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create(
        self,
        scan_id: int,
        source: str,
        evidence_type: str,
        data: str,
        asset_id: Optional[int] = None,
        confidence: int = 50,
    ) -> Evidence:
        """Create and persist a piece of evidence."""

        evidence = Evidence(
            scan_id=scan_id,
            asset_id=asset_id,
            source=source,
            evidence_type=evidence_type,
            data=data,
            confidence=confidence,
        )

        self.session.add(evidence)
        self.session.flush()

        return evidence

    def get_by_id(self, evidence_id: int) -> Optional[Evidence]:
        """Return evidence by ID."""

        return self.session.get(Evidence, evidence_id)

    def get_by_scan(self, scan_id: int) -> list[Evidence]:
        """Return all evidence belonging to a scan."""

        return (
            self.session.query(Evidence)
            .filter(Evidence.scan_id == scan_id)
            .order_by(Evidence.id)
            .all()
        )

    def get_by_asset(self, asset_id: int) -> list[Evidence]:
        """Return all evidence belonging to an asset."""

        return (
            self.session.query(Evidence)
            .filter(Evidence.asset_id == asset_id)
            .order_by(Evidence.id)
            .all()
        )