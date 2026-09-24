"""
Tests for the SCOPEX end-to-end scan orchestration layer.
"""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from scopex.cli.main import app
from scopex.core.scope import ScopeManager, ScopeViolation
from scopex.database.database import init_database, session_scope
from scopex.database.models import Asset, Evidence, Scan, ScopeTarget
from scopex.database.scope_repository import ScopeRepository
from scopex.dns.resolver import DNSResult
from scopex.scan.orchestrator import ScanOrchestrator


class FakeResolver:
    """Deterministic DNS resolver used for orchestration tests."""

    def resolve(self, name, record_types=None):
        if name == "example.com":
            return [
                DNSResult(
                    query_name=name,
                    record_type="A",
                    values=["203.0.113.10"],
                    success=True,
                ),
                DNSResult(
                    query_name=name,
                    record_type="AAAA",
                    values=[],
                    success=False,
                    error="NO_ANSWER",
                ),
                DNSResult(
                    query_name=name,
                    record_type="CNAME",
                    values=[],
                    success=False,
                    error="NO_ANSWER",
                ),
            ]

        if name == "api.example.com":
            return [
                DNSResult(
                    query_name=name,
                    record_type="A",
                    values=["203.0.113.20"],
                    success=True,
                ),
                DNSResult(
                    query_name=name,
                    record_type="AAAA",
                    values=[],
                    success=False,
                    error="NO_ANSWER",
                ),
                DNSResult(
                    query_name=name,
                    record_type="CNAME",
                    values=["edge.example.net"],
                    success=True,
                ),
            ]

        return [
            DNSResult(
                query_name=name,
                record_type="A",
                values=[],
                success=False,
                error="NXDOMAIN",
            ),
            DNSResult(
                query_name=name,
                record_type="AAAA",
                values=[],
                success=False,
                error="NXDOMAIN",
            ),
            DNSResult(
                query_name=name,
                record_type="CNAME",
                values=[],
                success=False,
                error="NXDOMAIN",
            ),
        ]


@pytest.fixture(autouse=True)
def clean_database():
    """Initialize the database and clear test data before each test."""

    init_database()

    with session_scope() as session:
        session.query(Evidence).delete()
        session.query(Asset).delete()
        session.query(Scan).delete()
        session.query(ScopeTarget).delete()

    yield

    with session_scope() as session:
        session.query(Evidence).delete()
        session.query(Asset).delete()
        session.query(Scan).delete()
        session.query(ScopeTarget).delete()


@pytest.fixture
def scope_manager():
    """Return a scope manager authorized for example.com."""

    manager = ScopeManager()
    manager.add_domain("example.com")
    return manager


@pytest.fixture
def orchestrator(scope_manager):
    """Return an orchestrator using deterministic DNS responses."""

    return ScanOrchestrator(
        scope_manager=scope_manager,
        resolver=FakeResolver(),
    )


def test_scan_root_domain_only(orchestrator):
    summary = orchestrator.run("example.com")

    assert summary.target == "example.com"
    assert summary.status == "completed"
    assert summary.candidates == 1
    assert summary.resolved == 0
    assert summary.partial == 1
    assert summary.unresolved == 0
    assert summary.errors == 0
    assert summary.assets == 2
    assert summary.evidence == 1


def test_scan_with_wordlist(orchestrator, tmp_path):
    wordlist = tmp_path / "subdomains.txt"

    wordlist.write_text(
        "www\n"
        "api\n"
        "api\n"
        "# comment\n"
        "\n"
        "unknown\n",
        encoding="utf-8",
    )

    summary = orchestrator.run(
        "example.com",
        wordlist=wordlist,
    )

    assert summary.target == "example.com"
    assert summary.status == "completed"
    assert summary.candidates == 4
    assert summary.resolved == 0
    assert summary.partial == 2
    assert summary.unresolved == 2
    assert summary.errors == 0


def test_scan_persists_scan_record(orchestrator):
    summary = orchestrator.run("example.com")

    with session_scope() as session:
        scan = session.get(Scan, summary.scan_id)

        assert scan is not None
        assert scan.target == "example.com"
        assert scan.scan_type == "dns"
        assert scan.status == "completed"
        assert scan.completed_at is not None


def test_scan_persists_assets(orchestrator):
    summary = orchestrator.run("example.com")

    with session_scope() as session:
        assets = (
            session.query(Asset)
            .filter(Asset.scan_id == summary.scan_id)
            .all()
        )

        values = {asset.value for asset in assets}

        assert values == {
            "example.com",
            "203.0.113.10",
        }


def test_scan_persists_dns_evidence(orchestrator):
    summary = orchestrator.run("example.com")

    with session_scope() as session:
        evidence = (
            session.query(Evidence)
            .filter(Evidence.scan_id == summary.scan_id)
            .all()
        )

        assert len(evidence) == 1
        assert evidence[0].source == "dns"
        assert evidence[0].evidence_type == "dns_resolution"
        assert evidence[0].confidence == 75


def test_scan_rejects_out_of_scope_target(orchestrator):
    with pytest.raises(ScopeViolation) as exc_info:
        orchestrator.run("evil.com")

    assert "outside the authorized scope" in str(exc_info.value)


def test_scan_rejects_ip_target(orchestrator):
    with pytest.raises(ValueError) as exc_info:
        orchestrator.run("203.0.113.10")

    assert "domain targets only" in str(exc_info.value)


def test_scan_rejects_missing_wordlist(orchestrator):
    missing_wordlist = Path("does-not-exist.txt")

    with pytest.raises(FileNotFoundError):
        orchestrator.run(
            "example.com",
            wordlist=missing_wordlist,
        )


def test_scan_deduplicates_wordlist_candidates(orchestrator, tmp_path):
    wordlist = tmp_path / "subdomains.txt"

    wordlist.write_text(
        "api\n"
        "api\n"
        "api\n",
        encoding="utf-8",
    )

    summary = orchestrator.run(
        "example.com",
        wordlist=wordlist,
    )

    assert summary.candidates == 2


def test_cli_exposes_scan_command():
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["--help"],
    )

    assert result.exit_code == 0
    assert "scan" in result.stdout


def test_cli_scan_help():
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "scan",
            "--help",
        ],
    )

    assert result.exit_code == 0
    assert "wordlist" in result.stdout.lower()
    assert "target" in result.stdout.lower()


def test_cli_scan_rejects_missing_wordlist():
    with session_scope() as session:
        repository = ScopeRepository(session)

        repository.create(
            target_type="domain",
            value="example.com",
        )

    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--wordlist",
            "does-not-exist.txt",
        ],
    )

    assert result.exit_code == 2
    assert "WORDLIST ERROR" in result.stdout