"""
Tests for the SCOPEX DNS resolver.

These tests avoid live DNS dependencies wherever possible and
verify normalization, validation, error handling, and resolver
behavior using mocked DNS responses.
"""

from unittest.mock import Mock

import dns.exception
import dns.resolver
import pytest

from scopex.core.exceptions import CollectorError
from scopex.dns import DNSResolver, DNSResult


class TestDNSResult:
    """Tests for the DNSResult data structure."""

    def test_default_values(self) -> None:
        result = DNSResult(
            query_name="example.com",
            record_type="A",
        )

        assert result.query_name == "example.com"
        assert result.record_type == "A"
        assert result.values == ()
        assert result.success is False
        assert result.error is None

    def test_successful_result(self) -> None:
        result = DNSResult(
            query_name="example.com",
            record_type="A",
            values=("93.184.216.34",),
            success=True,
        )

        assert result.values == ("93.184.216.34",)
        assert result.success is True
        assert result.error is None

    def test_failed_result(self) -> None:
        result = DNSResult(
            query_name="missing.example.com",
            record_type="A",
            success=False,
            error="NXDOMAIN",
        )

        assert result.success is False
        assert result.error == "NXDOMAIN"


class TestDNSResolverInitialization:
    """Tests for DNSResolver initialization."""

    def test_default_configuration(self) -> None:
        resolver = DNSResolver()

        assert resolver.timeout == 5.0
        assert resolver.lifetime == 10.0
        assert resolver.resolver.timeout == 5.0
        assert resolver.resolver.lifetime == 10.0

    def test_custom_configuration(self) -> None:
        resolver = DNSResolver(
            timeout=2.5,
            lifetime=7.5,
        )

        assert resolver.timeout == 2.5
        assert resolver.lifetime == 7.5

    def test_invalid_timeout(self) -> None:
        with pytest.raises(ValueError, match="timeout"):
            DNSResolver(timeout=0)

    def test_negative_timeout(self) -> None:
        with pytest.raises(ValueError, match="timeout"):
            DNSResolver(timeout=-1)

    def test_invalid_lifetime(self) -> None:
        with pytest.raises(ValueError, match="lifetime"):
            DNSResolver(lifetime=0)

    def test_negative_lifetime(self) -> None:
        with pytest.raises(ValueError, match="lifetime"):
            DNSResolver(lifetime=-1)


class TestDNSNameNormalization:
    """Tests for DNS name normalization."""

    def test_lowercases_name(self) -> None:
        assert (
            DNSResolver.normalize_name("EXAMPLE.COM")
            == "example.com"
        )

    def test_removes_trailing_dot(self) -> None:
        assert (
            DNSResolver.normalize_name("example.com.")
            == "example.com"
        )

    def test_strips_whitespace(self) -> None:
        assert (
            DNSResolver.normalize_name("  Example.COM.  ")
            == "example.com"
        )

    def test_empty_name_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="cannot be empty"):
            DNSResolver.normalize_name("")

    def test_whitespace_only_name_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="cannot be empty"):
            DNSResolver.normalize_name("   ")


class TestDNSValueNormalization:
    """Tests for individual DNS record normalization."""

    def test_a_record(self) -> None:
        assert (
            DNSResolver.normalize_value(
                "A",
                "  192.0.2.10  ",
            )
            == "192.0.2.10"
        )

    def test_aaaa_record(self) -> None:
        assert (
            DNSResolver.normalize_value(
                "AAAA",
                "  2001:db8::1  ",
            )
            == "2001:db8::1"
        )

    def test_cname_record(self) -> None:
        assert (
            DNSResolver.normalize_value(
                "CNAME",
                "WWW.Example.COM.",
            )
            == "www.example.com"
        )

    def test_ns_record(self) -> None:
        assert (
            DNSResolver.normalize_value(
                "NS",
                "NS1.Example.COM.",
            )
            == "ns1.example.com"
        )

    def test_mx_record_with_preference(self) -> None:
        record = Mock()
        record.preference = 10
        record.exchange = "MAIL.Example.COM."

        assert (
            DNSResolver.normalize_value(
                "MX",
                record,
            )
            == "10 mail.example.com"
        )

    def test_mx_null_record(self) -> None:
        """
        RFC 7505 Null MX is represented as preference 0
        and exchange ".".

        The root dot must be preserved.
        """

        record = Mock()
        record.preference = 0
        record.exchange = "."

        assert (
            DNSResolver.normalize_value(
                "MX",
                record,
            )
            == "0 ."
        )

    def test_mx_without_structured_attributes(self) -> None:
        assert (
            DNSResolver.normalize_value(
                "MX",
                "10 mail.example.com.",
            )
            == "10 mail.example.com."
        )

    def test_txt_record_with_chunks(self) -> None:
        record = Mock()
        record.strings = (
            b"v=spf1 ",
            b"-all",
        )

        assert (
            DNSResolver.normalize_value(
                "TXT",
                record,
            )
            == "v=spf1 -all"
        )

    def test_txt_record_with_string(self) -> None:
        record = Mock()
        record.strings = None

        assert (
            DNSResolver.normalize_value(
                "TXT",
                '"hello world"',
            )
            == "hello world"
        )

    def test_unknown_record_type(self) -> None:
        assert (
            DNSResolver.normalize_value(
                "UNKNOWN",
                "  value  ",
            )
            == "value"
        )


class TestResolveRecord:
    """Tests for resolving individual DNS record types."""

    def test_successful_a_lookup(self) -> None:
        resolver = DNSResolver()
        resolver.resolver.resolve = Mock(
            return_value=["192.0.2.10", "192.0.2.20"]
        )

        result = resolver.resolve_record(
            "Example.COM.",
            "a",
        )

        assert result.query_name == "example.com"
        assert result.record_type == "A"
        assert result.values == (
            "192.0.2.10",
            "192.0.2.20",
        )
        assert result.success is True
        assert result.error is None

        resolver.resolver.resolve.assert_called_once_with(
            "example.com",
            "A",
        )

    def test_successful_cname_lookup(self) -> None:
        resolver = DNSResolver()
        resolver.resolver.resolve = Mock(
            return_value=["Target.Example.COM."]
        )

        result = resolver.resolve_record(
            "www.example.com",
            "CNAME",
        )

        assert result.values == ("target.example.com",)
        assert result.success is True

    def test_successful_mx_lookup(self) -> None:
        mx_record = Mock()
        mx_record.preference = 10
        mx_record.exchange = "mail.example.com."

        resolver = DNSResolver()
        resolver.resolver.resolve = Mock(
            return_value=[mx_record]
        )

        result = resolver.resolve_record(
            "example.com",
            "MX",
        )

        assert result.values == ("10 mail.example.com",)
        assert result.success is True

    def test_nxdomain(self) -> None:
        resolver = DNSResolver()
        resolver.resolver.resolve = Mock(
            side_effect=dns.resolver.NXDOMAIN()
        )

        result = resolver.resolve_record(
            "does-not-exist.example",
            "A",
        )

        assert result.query_name == "does-not-exist.example"
        assert result.record_type == "A"
        assert result.values == ()
        assert result.success is False
        assert result.error == "NXDOMAIN"

    def test_no_answer(self) -> None:
        resolver = DNSResolver()
        resolver.resolver.resolve = Mock(
            side_effect=dns.resolver.NoAnswer()
        )

        result = resolver.resolve_record(
            "example.com",
            "CNAME",
        )

        assert result.success is False
        assert result.error == "NO_ANSWER"

    def test_no_nameservers(self) -> None:
        resolver = DNSResolver()
        resolver.resolver.resolve = Mock(
            side_effect=dns.resolver.NoNameservers()
        )

        result = resolver.resolve_record(
            "example.com",
            "A",
        )

        assert result.success is False
        assert result.error == "NO_NAMESERVERS"

    def test_timeout(self) -> None:
        resolver = DNSResolver()
        resolver.resolver.resolve = Mock(
            side_effect=dns.exception.Timeout()
        )

        result = resolver.resolve_record(
            "example.com",
            "A",
        )

        assert result.success is False
        assert result.error == "TIMEOUT"

    def test_unexpected_error_becomes_collector_error(self) -> None:
        resolver = DNSResolver()
        resolver.resolver.resolve = Mock(
            side_effect=RuntimeError("resolver failure")
        )

        with pytest.raises(
            CollectorError,
            match="Unexpected DNS resolution error",
        ):
            resolver.resolve_record(
                "example.com",
                "A",
            )

    def test_unsupported_record_type(self) -> None:
        resolver = DNSResolver()

        with pytest.raises(
            ValueError,
            match="Unsupported DNS record type",
        ):
            resolver.resolve_record(
                "example.com",
                "HTTPS",
            )


class TestResolve:
    """Tests for multi-record DNS resolution."""

    def test_resolve_all_supported_record_types(self) -> None:
        resolver = DNSResolver()

        resolver.resolve_record = Mock(
            side_effect=[
                DNSResult(
                    query_name="example.com",
                    record_type="A",
                    values=("192.0.2.10",),
                    success=True,
                ),
                DNSResult(
                    query_name="example.com",
                    record_type="AAAA",
                    values=("2001:db8::10",),
                    success=True,
                ),
                DNSResult(
                    query_name="example.com",
                    record_type="CNAME",
                    success=False,
                    error="NO_ANSWER",
                ),
                DNSResult(
                    query_name="example.com",
                    record_type="MX",
                    values=("0 .",),
                    success=True,
                ),
                DNSResult(
                    query_name="example.com",
                    record_type="NS",
                    values=("ns1.example.com",),
                    success=True,
                ),
                DNSResult(
                    query_name="example.com",
                    record_type="TXT",
                    values=("v=spf1 -all",),
                    success=True,
                ),
            ]
        )

        results = resolver.resolve("Example.COM.")

        assert len(results) == 6

        assert [
            result.record_type
            for result in results
        ] == [
            "A",
            "AAAA",
            "CNAME",
            "MX",
            "NS",
            "TXT",
        ]

        resolver.resolve_record.assert_any_call(
            "Example.COM.",
            "A",
        )

        resolver.resolve_record.assert_any_call(
            "Example.COM.",
            "AAAA",
        )

        resolver.resolve_record.assert_any_call(
            "Example.COM.",
            "CNAME",
        )

        resolver.resolve_record.assert_any_call(
            "Example.COM.",
            "MX",
        )

        resolver.resolve_record.assert_any_call(
            "Example.COM.",
            "NS",
        )

        resolver.resolve_record.assert_any_call(
            "Example.COM.",
            "TXT",
        )

    def test_resolve_selected_record_types(self) -> None:
        resolver = DNSResolver()

        resolver.resolve_record = Mock(
            side_effect=[
                DNSResult(
                    query_name="example.com",
                    record_type="A",
                    values=("192.0.2.10",),
                    success=True,
                ),
                DNSResult(
                    query_name="example.com",
                    record_type="MX",
                    values=("0 .",),
                    success=True,
                ),
            ]
        )

        results = resolver.resolve(
            "example.com",
            record_types=("A", "MX"),
        )

        assert len(results) == 2

        assert [
            result.record_type
            for result in results
        ] == ["A", "MX"]

        resolver.resolve_record.assert_any_call(
            "example.com",
            "A",
        )

        resolver.resolve_record.assert_any_call(
            "example.com",
            "MX",
        )

    def test_resolve_empty_record_type_selection(self) -> None:
        resolver = DNSResolver()
        resolver.resolve_record = Mock()

        results = resolver.resolve(
            "example.com",
            record_types=(),
        )

        assert results == []
        resolver.resolve_record.assert_not_called()


class TestDNSErrorFormatting:
    """Tests for DNS error formatting."""

    def test_nxdomain_format(self) -> None:
        error = dns.resolver.NXDOMAIN()

        assert (
            DNSResolver._format_dns_error(error)
            == "NXDOMAIN"
        )

    def test_no_answer_format(self) -> None:
        error = dns.resolver.NoAnswer()

        assert (
            DNSResolver._format_dns_error(error)
            == "NO_ANSWER"
        )

    def test_no_nameservers_format(self) -> None:
        error = dns.resolver.NoNameservers()

        assert (
            DNSResolver._format_dns_error(error)
            == "NO_NAMESERVERS"
        )

    def test_timeout_format(self) -> None:
        error = dns.exception.Timeout()

        assert (
            DNSResolver._format_dns_error(error)
            == "TIMEOUT"
        )

    def test_unknown_error_format(self) -> None:
        error = RuntimeError("unexpected")

        assert (
            DNSResolver._format_dns_error(error)
            == "RuntimeError"
        )