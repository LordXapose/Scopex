"""
Tests for the SCOPEX DNS resolution engine.

All DNSResolver calls are mocked.

These tests do not perform live DNS requests.
"""

from unittest.mock import Mock

import pytest

from scopex.core.scope import ScopeManager, ScopeViolation
from scopex.dns import DNSResolver, DNSResult, SubdomainCandidate
from scopex.dns.resolution import (
    DNSResolutionEngine,
    ResolutionResult,
    ResolutionStatus,
)


def build_scope_manager(
    domain: str = "example.com",
) -> ScopeManager:
    """
    Create a scope manager with one authorized domain.
    """

    manager = ScopeManager()
    manager.add_domain(domain)
    return manager


def build_candidate(
    name: str = "api.example.com",
    root_domain: str = "example.com",
    source: str = "wordlist",
) -> SubdomainCandidate:
    """
    Create a standard test candidate.
    """

    return SubdomainCandidate(
        name=name,
        root_domain=root_domain,
        source=source,
    )


def build_engine(
    resolver: Mock | None = None,
    scope_manager: ScopeManager | None = None,
    max_candidates: int = 10_000,
    record_types: tuple[str, ...] = (
        "A",
        "AAAA",
        "CNAME",
    ),
) -> DNSResolutionEngine:
    """
    Create a resolution engine for tests.
    """

    if resolver is None:
        resolver = Mock(spec=DNSResolver)

    if scope_manager is None:
        scope_manager = build_scope_manager()

    return DNSResolutionEngine(
        resolver=resolver,
        scope_manager=scope_manager,
        max_candidates=max_candidates,
        record_types=record_types,
    )


class TestResolutionResult:
    """
    Tests for ResolutionResult.
    """

    def test_default_values(self) -> None:
        result = ResolutionResult(
            name="api.example.com",
            root_domain="example.com",
            source="wordlist",
        )

        assert result.name == "api.example.com"
        assert result.root_domain == "example.com"
        assert result.source == "wordlist"
        assert result.ipv4 == ()
        assert result.ipv6 == ()
        assert result.cnames == ()
        assert result.status == ResolutionStatus.UNRESOLVED
        assert result.errors == ()

    def test_successful_result(self) -> None:
        result = ResolutionResult(
            name="api.example.com",
            root_domain="example.com",
            source="manual",
            ipv4=("192.0.2.10",),
            ipv6=("2001:db8::10",),
            cnames=("api.cdn.example.net",),
            status=ResolutionStatus.RESOLVED,
        )

        assert result.ipv4 == ("192.0.2.10",)
        assert result.ipv6 == ("2001:db8::10",)
        assert result.cnames == ("api.cdn.example.net",)
        assert result.status == ResolutionStatus.RESOLVED


class TestResolutionEngineInitialization:
    """
    Tests for DNSResolutionEngine initialization.
    """

    def test_default_configuration(self) -> None:
        resolver = Mock(spec=DNSResolver)
        manager = build_scope_manager()

        engine = DNSResolutionEngine(
            resolver=resolver,
            scope_manager=manager,
        )

        assert engine.resolver is resolver
        assert engine.scope_manager is manager
        assert engine.max_candidates == 10_000
        assert engine.record_types == (
            "A",
            "AAAA",
            "CNAME",
        )

    def test_custom_configuration(self) -> None:
        engine = build_engine(
            max_candidates=25,
            record_types=("A", "MX"),
        )

        assert engine.max_candidates == 25
        assert engine.record_types == ("A", "MX")

    def test_record_types_are_normalized(self) -> None:
        engine = build_engine(
            record_types=(" a ", "aaaa", "Cname"),
        )

        assert engine.record_types == (
            "A",
            "AAAA",
            "CNAME",
        )

    def test_invalid_max_candidates(self) -> None:
        with pytest.raises(
            ValueError,
            match="max_candidates",
        ):
            build_engine(max_candidates=0)

    def test_negative_max_candidates(self) -> None:
        with pytest.raises(
            ValueError,
            match="max_candidates",
        ):
            build_engine(max_candidates=-1)

    def test_empty_record_types(self) -> None:
        with pytest.raises(
            ValueError,
            match="record_types",
        ):
            build_engine(record_types=())

    def test_unsupported_record_type(self) -> None:
        with pytest.raises(
            ValueError,
            match="Unsupported DNS record type",
        ):
            build_engine(record_types=("HTTPS",))


class TestResolveCandidate:
    """
    Tests for resolving one candidate.
    """

    def test_successful_a_resolution(self) -> None:
        resolver = Mock(spec=DNSResolver)

        resolver.resolve.return_value = [
            DNSResult(
                query_name="api.example.com",
                record_type="A",
                values=(
                    "192.0.2.10",
                    "192.0.2.20",
                ),
                success=True,
            ),
            DNSResult(
                query_name="api.example.com",
                record_type="AAAA",
                values=(),
                success=True,
            ),
            DNSResult(
                query_name="api.example.com",
                record_type="CNAME",
                values=(),
                success=False,
                error="NO_ANSWER",
            ),
        ]

        engine = build_engine(resolver=resolver)

        result = engine.resolve_candidate(
            build_candidate()
        )

        assert result.name == "api.example.com"
        assert result.root_domain == "example.com"
        assert result.source == "wordlist"
        assert result.ipv4 == (
            "192.0.2.10",
            "192.0.2.20",
        )
        assert result.ipv6 == ()
        assert result.cnames == ()
        assert result.status == ResolutionStatus.PARTIAL
        assert result.errors == (
            "CNAME:NO_ANSWER",
        )

        resolver.resolve.assert_called_once_with(
            "api.example.com",
            record_types=(
                "A",
                "AAAA",
                "CNAME",
            ),
        )

    def test_successful_ipv6_resolution(self) -> None:
        resolver = Mock(spec=DNSResolver)

        resolver.resolve.return_value = [
            DNSResult(
                query_name="ipv6.example.com",
                record_type="A",
                values=(),
                success=True,
            ),
            DNSResult(
                query_name="ipv6.example.com",
                record_type="AAAA",
                values=("2001:db8::10",),
                success=True,
            ),
            DNSResult(
                query_name="ipv6.example.com",
                record_type="CNAME",
                values=(),
                success=True,
            ),
        ]

        engine = build_engine(resolver=resolver)

        result = engine.resolve_candidate(
            build_candidate(
                name="ipv6.example.com",
            )
        )

        assert result.ipv4 == ()
        assert result.ipv6 == ("2001:db8::10",)
        assert result.cnames == ()
        assert result.status == ResolutionStatus.RESOLVED
        assert result.errors == ()

    def test_successful_cname_resolution(self) -> None:
        resolver = Mock(spec=DNSResolver)

        resolver.resolve.return_value = [
            DNSResult(
                query_name="www.example.com",
                record_type="A",
                values=(),
                success=True,
            ),
            DNSResult(
                query_name="www.example.com",
                record_type="AAAA",
                values=(),
                success=True,
            ),
            DNSResult(
                query_name="www.example.com",
                record_type="CNAME",
                values=("edge.example.net",),
                success=True,
            ),
        ]

        engine = build_engine(resolver=resolver)

        result = engine.resolve_candidate(
            build_candidate(
                name="www.example.com",
            )
        )

        assert result.cnames == (
            "edge.example.net",
        )
        assert result.status == ResolutionStatus.RESOLVED

    def test_preserves_candidate_source(self) -> None:
        resolver = Mock(spec=DNSResolver)

        resolver.resolve.return_value = [
            DNSResult(
                query_name="dev.example.com",
                record_type="A",
                values=("192.0.2.50",),
                success=True,
            ),
        ]

        engine = build_engine(resolver=resolver)

        result = engine.resolve_candidate(
            build_candidate(
                name="dev.example.com",
                source="passive",
            )
        )

        assert result.source == "passive"

    def test_normalizes_candidate_name(self) -> None:
        resolver = Mock(spec=DNSResolver)

        resolver.resolve.return_value = [
            DNSResult(
                query_name="api.example.com",
                record_type="A",
                values=("192.0.2.10",),
                success=True,
            ),
        ]

        engine = build_engine(resolver=resolver)

        result = engine.resolve_candidate(
            build_candidate(
                name="API.EXAMPLE.COM.",
            )
        )

        assert result.name == "api.example.com"

        resolver.resolve.assert_called_once_with(
            "api.example.com",
            record_types=(
                "A",
                "AAAA",
                "CNAME",
            ),
        )

    def test_deduplicates_ipv4_addresses(self) -> None:
        resolver = Mock(spec=DNSResolver)

        resolver.resolve.return_value = [
            DNSResult(
                query_name="api.example.com",
                record_type="A",
                values=(
                    "192.0.2.10",
                    "192.0.2.10",
                    "192.0.2.20",
                    "192.0.2.20",
                ),
                success=True,
            ),
        ]

        engine = build_engine(
            resolver=resolver,
            record_types=("A",),
        )

        result = engine.resolve_candidate(
            build_candidate()
        )

        assert result.ipv4 == (
            "192.0.2.10",
            "192.0.2.20",
        )

    def test_deduplicates_ipv6_addresses(self) -> None:
        resolver = Mock(spec=DNSResolver)

        resolver.resolve.return_value = [
            DNSResult(
                query_name="api.example.com",
                record_type="AAAA",
                values=(
                    "2001:db8::1",
                    "2001:db8::1",
                    "2001:db8::2",
                ),
                success=True,
            ),
        ]

        engine = build_engine(
            resolver=resolver,
            record_types=("AAAA",),
        )

        result = engine.resolve_candidate(
            build_candidate()
        )

        assert result.ipv6 == (
            "2001:db8::1",
            "2001:db8::2",
        )

    def test_deduplicates_cnames(self) -> None:
        resolver = Mock(spec=DNSResolver)

        resolver.resolve.return_value = [
            DNSResult(
                query_name="www.example.com",
                record_type="CNAME",
                values=(
                    "edge.example.net",
                    "edge.example.net",
                ),
                success=True,
            ),
        ]

        engine = build_engine(
            resolver=resolver,
            record_types=("CNAME",),
        )

        result = engine.resolve_candidate(
            build_candidate(
                name="www.example.com",
            )
        )

        assert result.cnames == (
            "edge.example.net",
        )

    def test_successful_resolution_status(self) -> None:
        resolver = Mock(spec=DNSResolver)

        resolver.resolve.return_value = [
            DNSResult(
                query_name="api.example.com",
                record_type="A",
                values=("192.0.2.10",),
                success=True,
            ),
            DNSResult(
                query_name="api.example.com",
                record_type="AAAA",
                values=("2001:db8::10",),
                success=True,
            ),
            DNSResult(
                query_name="api.example.com",
                record_type="CNAME",
                values=(),
                success=True,
            ),
        ]

        engine = build_engine(resolver=resolver)

        result = engine.resolve_candidate(
            build_candidate()
        )

        assert result.status == ResolutionStatus.RESOLVED

    def test_partial_resolution_status(self) -> None:
        resolver = Mock(spec=DNSResolver)

        resolver.resolve.return_value = [
            DNSResult(
                query_name="api.example.com",
                record_type="A",
                values=("192.0.2.10",),
                success=True,
            ),
            DNSResult(
                query_name="api.example.com",
                record_type="AAAA",
                values=(),
                success=False,
                error="TIMEOUT",
            ),
            DNSResult(
                query_name="api.example.com",
                record_type="CNAME",
                values=(),
                success=False,
                error="NO_ANSWER",
            ),
        ]

        engine = build_engine(resolver=resolver)

        result = engine.resolve_candidate(
            build_candidate()
        )

        assert result.status == ResolutionStatus.PARTIAL
        assert result.errors == (
            "AAAA:TIMEOUT",
            "CNAME:NO_ANSWER",
        )

    def test_unresolved_status_for_nxdomain(self) -> None:
        resolver = Mock(spec=DNSResolver)

        resolver.resolve.return_value = [
            DNSResult(
                query_name="missing.example.com",
                record_type="A",
                success=False,
                error="NXDOMAIN",
            ),
            DNSResult(
                query_name="missing.example.com",
                record_type="AAAA",
                success=False,
                error="NXDOMAIN",
            ),
            DNSResult(
                query_name="missing.example.com",
                record_type="CNAME",
                success=False,
                error="NXDOMAIN",
            ),
        ]

        engine = build_engine(resolver=resolver)

        result = engine.resolve_candidate(
            build_candidate(
                name="missing.example.com",
            )
        )

        assert result.status == ResolutionStatus.UNRESOLVED
        assert result.ipv4 == ()
        assert result.ipv6 == ()
        assert result.cnames == ()
        assert result.errors == (
            "A:NXDOMAIN",
            "AAAA:NXDOMAIN",
            "CNAME:NXDOMAIN",
        )

    def test_successful_empty_answers_are_unresolved(self) -> None:
        resolver = Mock(spec=DNSResolver)

        resolver.resolve.return_value = [
            DNSResult(
                query_name="empty.example.com",
                record_type="A",
                values=(),
                success=True,
            ),
            DNSResult(
                query_name="empty.example.com",
                record_type="AAAA",
                values=(),
                success=True,
            ),
            DNSResult(
                query_name="empty.example.com",
                record_type="CNAME",
                values=(),
                success=True,
            ),
        ]

        engine = build_engine(resolver=resolver)

        result = engine.resolve_candidate(
            build_candidate(
                name="empty.example.com",
            )
        )

        assert result.status == ResolutionStatus.UNRESOLVED
        assert result.errors == ()

    def test_unexpected_resolver_error_becomes_error_result(
        self,
    ) -> None:
        resolver = Mock(spec=DNSResolver)

        resolver.resolve.side_effect = RuntimeError(
            "resolver failure"
        )

        engine = build_engine(resolver=resolver)

        result = engine.resolve_candidate(
            build_candidate()
        )

        assert result.status == ResolutionStatus.ERROR
        assert result.errors == (
            "resolver failure",
        )
        assert result.ipv4 == ()
        assert result.ipv6 == ()
        assert result.cnames == ()

    def test_candidate_outside_scope_is_rejected(self) -> None:
        resolver = Mock(spec=DNSResolver)

        engine = build_engine(
            resolver=resolver,
        )

        candidate = build_candidate(
            name="api.attacker.example",
            root_domain="example.com",
        )

        with pytest.raises(
            ScopeViolation,
            match="outside authorized scope",
        ):
            engine.resolve_candidate(candidate)

        resolver.resolve.assert_not_called()

    def test_root_domain_outside_scope_is_rejected(self) -> None:
        resolver = Mock(spec=DNSResolver)

        manager = build_scope_manager(
            "example.com",
        )

        engine = build_engine(
            resolver=resolver,
            scope_manager=manager,
        )

        candidate = build_candidate(
            name="api.example.com",
            root_domain="attacker.com",
        )

        with pytest.raises(
            ScopeViolation,
            match="root domain is outside",
        ):
            engine.resolve_candidate(candidate)

        resolver.resolve.assert_not_called()

    def test_selected_record_types_are_used(self) -> None:
        resolver = Mock(spec=DNSResolver)

        resolver.resolve.return_value = [
            DNSResult(
                query_name="mail.example.com",
                record_type="MX",
                values=("10 mail.example.com",),
                success=True,
            ),
        ]

        engine = build_engine(
            resolver=resolver,
            record_types=("MX",),
        )

        result = engine.resolve_candidate(
            build_candidate(
                name="mail.example.com",
            )
        )

        assert result.ipv4 == ()
        assert result.ipv6 == ()
        assert result.cnames == ()
        assert result.status == ResolutionStatus.UNRESOLVED

        resolver.resolve.assert_called_once_with(
            "mail.example.com",
            record_types=("MX",),
        )


class TestResolveCandidates:
    """
    Tests for resolving multiple candidates.
    """

    def test_resolves_multiple_candidates(self) -> None:
        resolver = Mock(spec=DNSResolver)

        resolver.resolve.side_effect = [
            [
                DNSResult(
                    query_name="api.example.com",
                    record_type="A",
                    values=("192.0.2.10",),
                    success=True,
                ),
            ],
            [
                DNSResult(
                    query_name="www.example.com",
                    record_type="A",
                    values=("192.0.2.20",),
                    success=True,
                ),
            ],
        ]

        engine = build_engine(
            resolver=resolver,
            record_types=("A",),
        )

        candidates = [
            build_candidate(
                name="api.example.com",
            ),
            build_candidate(
                name="www.example.com",
            ),
        ]

        results = engine.resolve_candidates(
            candidates,
        )

        assert len(results) == 2
        assert results[0].name == "api.example.com"
        assert results[0].ipv4 == ("192.0.2.10",)
        assert results[1].name == "www.example.com"
        assert results[1].ipv4 == ("192.0.2.20",)

        assert resolver.resolve.call_count == 2

    def test_empty_candidate_list(self) -> None:
        resolver = Mock(spec=DNSResolver)

        engine = build_engine(
            resolver=resolver,
        )

        results = engine.resolve_candidates([])

        assert results == []

        resolver.resolve.assert_not_called()

    def test_candidate_limit_is_enforced(self) -> None:
        resolver = Mock(spec=DNSResolver)

        resolver.resolve.side_effect = [
            [
                DNSResult(
                    query_name="one.example.com",
                    record_type="A",
                    values=("192.0.2.1",),
                    success=True,
                ),
            ],
            [
                DNSResult(
                    query_name="two.example.com",
                    record_type="A",
                    values=("192.0.2.2",),
                    success=True,
                ),
            ],
        ]

        engine = build_engine(
            resolver=resolver,
            max_candidates=2,
            record_types=("A",),
        )

        candidates = [
            build_candidate(
                name="one.example.com",
            ),
            build_candidate(
                name="two.example.com",
            ),
            build_candidate(
                name="three.example.com",
            ),
        ]

        results = engine.resolve_candidates(
            candidates,
        )

        assert len(results) == 2

        assert [
            result.name
            for result in results
        ] == [
            "one.example.com",
            "two.example.com",
        ]

        assert resolver.resolve.call_count == 2

    def test_tuple_candidates_are_supported(self) -> None:
        resolver = Mock(spec=DNSResolver)

        resolver.resolve.return_value = [
            DNSResult(
                query_name="api.example.com",
                record_type="A",
                values=("192.0.2.10",),
                success=True,
            ),
        ]

        engine = build_engine(
            resolver=resolver,
            record_types=("A",),
        )

        candidates = (
            build_candidate(),
        )

        results = engine.resolve_candidates(
            candidates,
        )

        assert len(results) == 1
        assert results[0].name == "api.example.com"


class TestResolutionHelpers:
    """
    Tests for internal helper methods.
    """

    def test_append_unique_preserves_order(self) -> None:
        values = [
            "192.0.2.10",
        ]

        DNSResolutionEngine._append_unique(
            values,
            (
                "192.0.2.20",
                "192.0.2.10",
                "192.0.2.30",
            ),
        )

        assert values == [
            "192.0.2.10",
            "192.0.2.20",
            "192.0.2.30",
        ]

    def test_deduplicate_preserves_order(self) -> None:
        values = [
            "A:NXDOMAIN",
            "AAAA:TIMEOUT",
            "A:NXDOMAIN",
            "CNAME:NO_ANSWER",
            "AAAA:TIMEOUT",
        ]

        result = DNSResolutionEngine._deduplicate(
            values,
        )

        assert result == [
            "A:NXDOMAIN",
            "AAAA:TIMEOUT",
            "CNAME:NO_ANSWER",
        ]