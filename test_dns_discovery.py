"""
Tests for the SCOPEX subdomain discovery engine.

These tests verify candidate generation, normalization,
deduplication, scope enforcement, wordlist handling,
and candidate limits without performing live DNS queries.
"""

from pathlib import Path

import pytest

from scopex.core.scope import ScopeManager, ScopeViolation
from scopex.dns import (
    SubdomainCandidate,
    SubdomainDiscovery,
)


def create_scope(*domains: str) -> ScopeManager:
    """Create a ScopeManager populated with test domains."""

    scope = ScopeManager()

    for domain in domains:
        scope.add_domain(domain)

    return scope


class TestSubdomainCandidate:
    """Tests for the SubdomainCandidate data structure."""

    def test_candidate_fields(self) -> None:
        candidate = SubdomainCandidate(
            name="www.example.com",
            root_domain="example.com",
            source="wordlist",
        )

        assert candidate.name == "www.example.com"
        assert candidate.root_domain == "example.com"
        assert candidate.source == "wordlist"

    def test_candidate_is_immutable(self) -> None:
        candidate = SubdomainCandidate(
            name="www.example.com",
            root_domain="example.com",
            source="wordlist",
        )

        with pytest.raises(AttributeError):
            candidate.name = "admin.example.com"  # type: ignore


class TestSubdomainDiscoveryInitialization:
    """Tests for discovery engine initialization."""

    def test_default_max_candidates(self) -> None:
        scope = create_scope("example.com")
        discovery = SubdomainDiscovery(scope)

        assert (
            discovery.max_candidates
            == SubdomainDiscovery.DEFAULT_MAX_CANDIDATES
        )

    def test_custom_max_candidates(self) -> None:
        scope = create_scope("example.com")
        discovery = SubdomainDiscovery(
            scope,
            max_candidates=100,
        )

        assert discovery.max_candidates == 100

    def test_invalid_max_candidates(self) -> None:
        scope = create_scope("example.com")

        with pytest.raises(
            ValueError,
            match="max_candidates",
        ):
            SubdomainDiscovery(
                scope,
                max_candidates=0,
            )


class TestDomainNormalization:
    """Tests for domain normalization."""

    def test_lowercase(self) -> None:
        assert (
            SubdomainDiscovery.normalize_domain(
                "EXAMPLE.COM"
            )
            == "example.com"
        )

    def test_removes_https(self) -> None:
        assert (
            SubdomainDiscovery.normalize_domain(
                "https://example.com"
            )
            == "example.com"
        )

    def test_removes_http(self) -> None:
        assert (
            SubdomainDiscovery.normalize_domain(
                "http://example.com"
            )
            == "example.com"
        )

    def test_removes_path(self) -> None:
        assert (
            SubdomainDiscovery.normalize_domain(
                "https://example.com/path"
            )
            == "example.com"
        )

    def test_removes_query(self) -> None:
        assert (
            SubdomainDiscovery.normalize_domain(
                "example.com?test=1"
            )
            == "example.com"
        )

    def test_removes_fragment(self) -> None:
        assert (
            SubdomainDiscovery.normalize_domain(
                "example.com#section"
            )
            == "example.com"
        )

    def test_removes_trailing_dot(self) -> None:
        assert (
            SubdomainDiscovery.normalize_domain(
                "Example.COM."
            )
            == "example.com"
        )

    def test_empty_domain(self) -> None:
        with pytest.raises(
            ValueError,
            match="cannot be empty",
        ):
            SubdomainDiscovery.normalize_domain("")


class TestLabelNormalization:
    """Tests for subdomain label normalization."""

    def test_lowercase(self) -> None:
        assert (
            SubdomainDiscovery.normalize_label("WWW")
            == "www"
        )

    def test_removes_trailing_dot(self) -> None:
        assert (
            SubdomainDiscovery.normalize_label("www.")
            == "www"
        )

    def test_rejects_empty_label(self) -> None:
        with pytest.raises(
            ValueError,
            match="cannot be empty",
        ):
            SubdomainDiscovery.normalize_label("")

    def test_rejects_multi_label_input(self) -> None:
        with pytest.raises(
            ValueError,
            match="must not contain dots",
        ):
            SubdomainDiscovery.normalize_label(
                "foo.bar"
            )


class TestCandidateBuilding:
    """Tests for candidate construction."""

    def test_build_candidate(self) -> None:
        candidate = SubdomainDiscovery.build_candidate(
            "EXAMPLE.COM.",
            "WWW",
        )

        assert candidate.name == "www.example.com"
        assert candidate.root_domain == "example.com"
        assert candidate.source == "wordlist"

    def test_custom_source(self) -> None:
        candidate = SubdomainDiscovery.build_candidate(
            "example.com",
            "api",
            source="passive",
        )

        assert candidate.name == "api.example.com"
        assert candidate.source == "passive"


class TestLabelDiscovery:
    """Tests for in-memory label discovery."""

    def test_discovers_labels(self) -> None:
        scope = create_scope("example.com")
        discovery = SubdomainDiscovery(scope)

        results = discovery.discover_from_labels(
            "example.com",
            ["www", "api", "mail"],
        )

        assert results == [
            SubdomainCandidate(
                name="www.example.com",
                root_domain="example.com",
                source="manual",
            ),
            SubdomainCandidate(
                name="api.example.com",
                root_domain="example.com",
                source="manual",
            ),
            SubdomainCandidate(
                name="mail.example.com",
                root_domain="example.com",
                source="manual",
            ),
        ]

    def test_deduplicates_labels(self) -> None:
        scope = create_scope("example.com")
        discovery = SubdomainDiscovery(scope)

        results = discovery.discover_from_labels(
            "example.com",
            ["www", "WWW", "www", "api"],
        )

        assert [
            candidate.name
            for candidate in results
        ] == [
            "www.example.com",
            "api.example.com",
        ]

    def test_skips_empty_labels(self) -> None:
        scope = create_scope("example.com")
        discovery = SubdomainDiscovery(scope)

        results = discovery.discover_from_labels(
            "example.com",
            ["", "www", "   ", "api"],
        )

        assert [
            candidate.name
            for candidate in results
        ] == [
            "www.example.com",
            "api.example.com",
        ]

    def test_skips_invalid_labels(self) -> None:
        scope = create_scope("example.com")
        discovery = SubdomainDiscovery(scope)

        results = discovery.discover_from_labels(
            "example.com",
            [
                "www",
                "foo.bar",
                "api",
            ],
        )

        assert [
            candidate.name
            for candidate in results
        ] == [
            "www.example.com",
            "api.example.com",
        ]

    def test_custom_source(self) -> None:
        scope = create_scope("example.com")
        discovery = SubdomainDiscovery(scope)

        results = discovery.discover_from_labels(
            "example.com",
            ["www"],
            source="passive",
        )

        assert results[0].source == "passive"

    def test_candidate_limit(self) -> None:
        scope = create_scope("example.com")
        discovery = SubdomainDiscovery(
            scope,
            max_candidates=2,
        )

        results = discovery.discover_from_labels(
            "example.com",
            ["one", "two", "three", "four"],
        )

        assert len(results) == 2

    def test_root_domain_must_be_in_scope(self) -> None:
        scope = create_scope("authorized.com")
        discovery = SubdomainDiscovery(scope)

        with pytest.raises(
            ScopeViolation,
            match="outside authorized scope",
        ):
            discovery.discover_from_labels(
                "example.com",
                ["www"],
            )


class TestWordlistDiscovery:
    """Tests for wordlist-based discovery."""

    def test_discovers_from_wordlist(
        self,
        tmp_path: Path,
    ) -> None:
        wordlist = tmp_path / "subdomains.txt"

        wordlist.write_text(
            "www\n"
            "api\n"
            "mail\n",
            encoding="utf-8",
        )

        scope = create_scope("example.com")
        discovery = SubdomainDiscovery(scope)

        results = discovery.discover_from_wordlist(
            "example.com",
            wordlist,
        )

        assert [
            candidate.name
            for candidate in results
        ] == [
            "www.example.com",
            "api.example.com",
            "mail.example.com",
        ]

    def test_ignores_empty_lines(
        self,
        tmp_path: Path,
    ) -> None:
        wordlist = tmp_path / "subdomains.txt"

        wordlist.write_text(
            "\n"
            "www\n"
            "\n"
            "api\n",
            encoding="utf-8",
        )

        scope = create_scope("example.com")
        discovery = SubdomainDiscovery(scope)

        results = discovery.discover_from_wordlist(
            "example.com",
            wordlist,
        )

        assert len(results) == 2

    def test_ignores_comments(
        self,
        tmp_path: Path,
    ) -> None:
        wordlist = tmp_path / "subdomains.txt"

        wordlist.write_text(
            "# common subdomains\n"
            "www\n"
            "# administration\n"
            "admin\n",
            encoding="utf-8",
        )

        scope = create_scope("example.com")
        discovery = SubdomainDiscovery(scope)

        results = discovery.discover_from_wordlist(
            "example.com",
            wordlist,
        )

        assert [
            candidate.name
            for candidate in results
        ] == [
            "www.example.com",
            "admin.example.com",
        ]

    def test_deduplicates_wordlist(
        self,
        tmp_path: Path,
    ) -> None:
        wordlist = tmp_path / "subdomains.txt"

        wordlist.write_text(
            "www\n"
            "WWW\n"
            "api\n"
            "www\n",
            encoding="utf-8",
        )

        scope = create_scope("example.com")
        discovery = SubdomainDiscovery(scope)

        results = discovery.discover_from_wordlist(
            "example.com",
            wordlist,
        )

        assert [
            candidate.name
            for candidate in results
        ] == [
            "www.example.com",
            "api.example.com",
        ]

    def test_candidate_limit(
        self,
        tmp_path: Path,
    ) -> None:
        wordlist = tmp_path / "subdomains.txt"

        wordlist.write_text(
            "one\n"
            "two\n"
            "three\n"
            "four\n",
            encoding="utf-8",
        )

        scope = create_scope("example.com")
        discovery = SubdomainDiscovery(
            scope,
            max_candidates=2,
        )

        results = discovery.discover_from_wordlist(
            "example.com",
            wordlist,
        )

        assert len(results) == 2

    def test_missing_wordlist(
        self,
        tmp_path: Path,
    ) -> None:
        wordlist = tmp_path / "missing.txt"

        scope = create_scope("example.com")
        discovery = SubdomainDiscovery(scope)

        with pytest.raises(
            FileNotFoundError,
            match="Wordlist does not exist",
        ):
            discovery.discover_from_wordlist(
                "example.com",
                wordlist,
            )

    def test_wordlist_path_must_be_file(
        self,
        tmp_path: Path,
    ) -> None:
        scope = create_scope("example.com")
        discovery = SubdomainDiscovery(scope)

        with pytest.raises(
            ValueError,
            match="is not a file",
        ):
            discovery.discover_from_wordlist(
                "example.com",
                tmp_path,
            )

    def test_wordlist_root_must_be_in_scope(
        self,
        tmp_path: Path,
    ) -> None:
        wordlist = tmp_path / "subdomains.txt"

        wordlist.write_text(
            "www\n",
            encoding="utf-8",
        )

        scope = create_scope("authorized.com")
        discovery = SubdomainDiscovery(scope)

        with pytest.raises(
            ScopeViolation,
            match="outside authorized scope",
        ):
            discovery.discover_from_wordlist(
                "example.com",
                wordlist,
            )