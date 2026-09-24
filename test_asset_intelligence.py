"""
Tests for SCOPEX asset intelligence.
"""

from __future__ import annotations

import json

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from scopex.assets.intelligence import AssetIntelligence
from scopex.database.models import Asset, Base, Evidence, Scan
from scopex.dns.resolution import (
    ResolutionResult,
    ResolutionStatus,
)


def create_test_database():
    """
    Create an isolated in-memory SQLite database.
    """

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )

    Base.metadata.create_all(engine)

    return engine


def create_scan(session: Session) -> Scan:
    """
    Create a test scan.
    """

    scan = Scan(
        target="example.com",
        scan_type="dns",
        status="running",
    )

    session.add(scan)
    session.flush()

    return scan


def test_persist_domain_asset():
    engine = create_test_database()

    with Session(engine) as session:
        scan = create_scan(session)

        result = ResolutionResult(
            name="api.example.com",
            root_domain="example.com",
            source="wordlist",
            status=ResolutionStatus.UNRESOLVED,
        )

        intelligence = AssetIntelligence()

        assets = intelligence.persist_resolution(
            session=session,
            scan_id=scan.id,
            result=result,
        )

        session.commit()

        assert len(assets) == 1

        asset = assets[0]

        assert asset.asset_type == "domain"
        assert asset.value == "api.example.com"
        assert asset.hostname == "api.example.com"
        assert asset.status == "active"


def test_persist_ipv4_and_ipv6_assets():
    engine = create_test_database()

    with Session(engine) as session:
        scan = create_scan(session)

        result = ResolutionResult(
            name="api.example.com",
            root_domain="example.com",
            source="wordlist",
            ipv4=("203.0.113.10",),
            ipv6=("2001:db8::10",),
            status=ResolutionStatus.RESOLVED,
        )

        intelligence = AssetIntelligence()

        assets = intelligence.persist_resolution(
            session=session,
            scan_id=scan.id,
            result=result,
        )

        session.commit()

        assert len(assets) == 3

        asset_types = {
            asset.asset_type
            for asset in assets
        }

        assert asset_types == {
            "domain",
            "ipv4",
            "ipv6",
        }


def test_ip_assets_reference_hostname():
    engine = create_test_database()

    with Session(engine) as session:
        scan = create_scan(session)

        result = ResolutionResult(
            name="api.example.com",
            root_domain="example.com",
            source="wordlist",
            ipv4=("203.0.113.10",),
            status=ResolutionStatus.RESOLVED,
        )

        intelligence = AssetIntelligence()

        assets = intelligence.persist_resolution(
            session=session,
            scan_id=scan.id,
            result=result,
        )

        session.commit()

        ipv4_asset = next(
            asset
            for asset in assets
            if asset.asset_type == "ipv4"
        )

        assert ipv4_asset.value == "203.0.113.10"
        assert ipv4_asset.hostname == "api.example.com"
        assert ipv4_asset.ip_address == "203.0.113.10"


def test_dns_evidence_is_persisted():
    engine = create_test_database()

    with Session(engine) as session:
        scan = create_scan(session)

        result = ResolutionResult(
            name="api.example.com",
            root_domain="example.com",
            source="wordlist",
            ipv4=("203.0.113.10",),
            cnames=("edge.example.net",),
            status=ResolutionStatus.RESOLVED,
        )

        intelligence = AssetIntelligence()

        intelligence.persist_resolution(
            session=session,
            scan_id=scan.id,
            result=result,
        )

        session.commit()

        evidence = session.scalar(
            select(Evidence).where(
                Evidence.scan_id == scan.id
            )
        )

        assert evidence is not None
        assert evidence.source == "dns"
        assert evidence.evidence_type == "dns_resolution"
        assert evidence.confidence == 100

        data = json.loads(evidence.data)

        assert data["name"] == "api.example.com"
        assert data["ipv4"] == ["203.0.113.10"]
        assert data["cnames"] == ["edge.example.net"]
        assert data["status"] == "resolved"


def test_partial_resolution_gets_75_confidence():
    engine = create_test_database()

    with Session(engine) as session:
        scan = create_scan(session)

        result = ResolutionResult(
            name="api.example.com",
            root_domain="example.com",
            source="wordlist",
            ipv4=("203.0.113.10",),
            status=ResolutionStatus.PARTIAL,
            errors=("AAAA:TIMEOUT",),
        )

        intelligence = AssetIntelligence()

        intelligence.persist_resolution(
            session=session,
            scan_id=scan.id,
            result=result,
        )

        session.commit()

        evidence = session.scalar(
            select(Evidence).where(
                Evidence.scan_id == scan.id
            )
        )

        assert evidence is not None
        assert evidence.confidence == 75


def test_error_resolution_gets_zero_confidence():
    engine = create_test_database()

    with Session(engine) as session:
        scan = create_scan(session)

        result = ResolutionResult(
            name="api.example.com",
            root_domain="example.com",
            source="wordlist",
            status=ResolutionStatus.ERROR,
            errors=("resolver failure",),
        )

        intelligence = AssetIntelligence()

        intelligence.persist_resolution(
            session=session,
            scan_id=scan.id,
            result=result,
        )

        session.commit()

        evidence = session.scalar(
            select(Evidence).where(
                Evidence.scan_id == scan.id
            )
        )

        assert evidence is not None
        assert evidence.confidence == 0


def test_asset_creation_is_idempotent():
    engine = create_test_database()

    with Session(engine) as session:
        scan = create_scan(session)

        result = ResolutionResult(
            name="api.example.com",
            root_domain="example.com",
            source="wordlist",
            ipv4=("203.0.113.10",),
            status=ResolutionStatus.RESOLVED,
        )

        intelligence = AssetIntelligence()

        first = intelligence.persist_resolution(
            session=session,
            scan_id=scan.id,
            result=result,
        )

        session.flush()

        first_ids = {
            asset.id
            for asset in first
        }

        second = intelligence.persist_resolution(
            session=session,
            scan_id=scan.id,
            result=result,
        )

        session.flush()

        second_ids = {
            asset.id
            for asset in second
        }

        assert first_ids == second_ids

        stored_assets = session.scalars(
            select(Asset).where(
                Asset.scan_id == scan.id
            )
        ).all()

        assert len(stored_assets) == 2


def test_multiple_resolutions_are_persisted():
    engine = create_test_database()

    with Session(engine) as session:
        scan = create_scan(session)

        results = [
            ResolutionResult(
                name="api.example.com",
                root_domain="example.com",
                source="wordlist",
                ipv4=("203.0.113.10",),
                status=ResolutionStatus.RESOLVED,
            ),
            ResolutionResult(
                name="mail.example.com",
                root_domain="example.com",
                source="wordlist",
                ipv4=("203.0.113.20",),
                status=ResolutionStatus.RESOLVED,
            ),
        ]

        intelligence = AssetIntelligence()

        assets = intelligence.persist_resolutions(
            session=session,
            scan_id=scan.id,
            results=results,
        )

        session.commit()

        assert len(assets) == 4

        stored_assets = session.scalars(
            select(Asset).where(
                Asset.scan_id == scan.id
            )
        ).all()

        assert len(stored_assets) == 4