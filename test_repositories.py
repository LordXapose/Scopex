"""
SCOPEX repository integration tests.

These tests use an isolated temporary SQLite database so that
test data cannot interfere with the application's real database.
"""

from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from scopex.database.models import Base
from scopex.database.repositories import (
    AssetRepository,
    EvidenceRepository,
    ScanRepository,
    ServiceRepository,
)


@pytest.fixture()
def test_session(tmp_path: Path):
    """
    Create a completely isolated SQLite database for each test.
    """

    database_path = tmp_path / "test_scopex.db"

    engine = create_engine(
        f"sqlite:///{database_path.as_posix()}",
        connect_args={
            "check_same_thread": False,
        },
        echo=False,
    )

    Base.metadata.create_all(bind=engine)

    SessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )

    session = SessionLocal()

    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
        engine.dispose()


def test_repository_create_and_relationships(test_session):
    """Test repository creation and entity relationships."""

    session = test_session

    scans = ScanRepository(session)

    scan = scans.create(
        target="pytest.scopex.local",
        scan_type="recon",
    )

    assert scan.id is not None
    assert scan.target == "pytest.scopex.local"

    assets = AssetRepository(session)

    asset = assets.create(
        scan_id=scan.id,
        asset_type="domain",
        value="pytest.scopex.local",
        hostname="pytest.scopex.local",
    )

    assert asset.id is not None
    assert asset.scan_id == scan.id

    services = ServiceRepository(session)

    service = services.create(
        asset_id=asset.id,
        port=443,
        protocol="tcp",
        state="open",
        service_name="https",
        product="Test Web Server",
        version="1.0",
    )

    assert service.id is not None
    assert service.asset_id == asset.id
    assert service.port == 443
    assert service.protocol == "tcp"
    assert service.state == "open"

    evidence_repo = EvidenceRepository(session)

    evidence = evidence_repo.create(
        scan_id=scan.id,
        asset_id=asset.id,
        source="pytest",
        evidence_type="http",
        data='{"status_code": 200}',
        confidence=90,
    )

    assert evidence.id is not None
    assert evidence.scan_id == scan.id
    assert evidence.asset_id == asset.id
    assert evidence.confidence == 90

    retrieved_scan = scans.get_by_id(
        scan.id
    )

    assert retrieved_scan is not None
    assert retrieved_scan.id == scan.id

    retrieved_assets = assets.get_by_scan(
        scan.id
    )

    assert len(retrieved_assets) >= 1

    assert any(
        item.id == asset.id
        for item in retrieved_assets
    )

    retrieved_services = services.get_by_asset(
        asset.id
    )

    assert len(retrieved_services) >= 1

    assert any(
        item.id == service.id
        for item in retrieved_services
    )

    retrieved_evidence = evidence_repo.get_by_asset(
        asset.id
    )

    assert len(retrieved_evidence) >= 1

    assert any(
        item.id == evidence.id
        for item in retrieved_evidence
    )


def test_scan_repository_lookup(test_session):
    """Test ScanRepository lookup operations."""

    session = test_session

    repository = ScanRepository(session)

    scan = repository.create(
        target="lookup.scopex.local",
        scan_type="recon",
    )

    found = repository.get_by_id(
        scan.id
    )

    assert found is not None
    assert found.id == scan.id

    latest = repository.get_latest()

    assert latest is not None
    assert latest.id == scan.id


def test_asset_repository_lookup(test_session):
    """Test AssetRepository lookup operations."""

    session = test_session

    scans = ScanRepository(session)
    assets = AssetRepository(session)

    scan = scans.create(
        target="asset-lookup.scopex.local",
        scan_type="recon",
    )

    asset = assets.create(
        scan_id=scan.id,
        asset_type="domain",
        value="asset-lookup.scopex.local",
        hostname="asset-lookup.scopex.local",
    )

    found_by_id = assets.get_by_id(
        asset.id
    )

    assert found_by_id is not None
    assert found_by_id.id == asset.id

    found_by_value = assets.get_by_value(
        scan.id,
        "domain",
        "asset-lookup.scopex.local",
    )

    assert found_by_value is not None
    assert found_by_value.id == asset.id
    assert found_by_value.asset_type == "domain"
    assert found_by_value.value == (
        "asset-lookup.scopex.local"
    )