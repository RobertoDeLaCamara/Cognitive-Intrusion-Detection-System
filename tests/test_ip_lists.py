"""Tests for IP allowlist/blocklist."""

from unittest.mock import patch

from src.enrichment.ip_lists import is_allowlisted, is_blocklisted


class TestAllowlist:
    def test_ip_in_allowlist(self):
        with patch("src.enrichment.ip_lists.IP_ALLOWLIST", {"10.0.0.1", "192.168.1.0/24"}):
            assert is_allowlisted("10.0.0.1") is True
            assert is_allowlisted("192.168.1.100") is True
            assert is_allowlisted("192.168.2.1") is False
            assert is_allowlisted("8.8.8.8") is False

    def test_empty_allowlist(self):
        with patch("src.enrichment.ip_lists.IP_ALLOWLIST", set()):
            assert is_allowlisted("10.0.0.1") is False

    def test_invalid_ip_returns_false(self):
        with patch("src.enrichment.ip_lists.IP_ALLOWLIST", {"10.0.0.0/8"}):
            assert is_allowlisted("not_an_ip") is False


class TestBlocklist:
    def test_ip_in_blocklist(self):
        with patch("src.enrichment.ip_lists.IP_BLOCKLIST", {"5.6.7.8", "10.0.0.0/8"}):
            assert is_blocklisted("5.6.7.8") is True
            assert is_blocklisted("10.0.0.50") is True
            assert is_blocklisted("1.2.3.4") is False

    def test_empty_blocklist(self):
        with patch("src.enrichment.ip_lists.IP_BLOCKLIST", set()):
            assert is_blocklisted("1.2.3.4") is False

    def test_invalid_cidr_in_list_skipped(self):
        with patch("src.enrichment.ip_lists.IP_BLOCKLIST", {"not_valid"}):
            assert is_blocklisted("1.2.3.4") is False


class TestIPV6:
    def test_ipv6_in_cidr(self):
        with patch("src.enrichment.ip_lists.IP_BLOCKLIST", {"fd00::/8"}):
            assert is_blocklisted("fd01::1") is True
            assert is_blocklisted("fe80::1") is False

    def test_ipv6_exact(self):
        with patch("src.enrichment.ip_lists.IP_BLOCKLIST", {"::1"}):
            assert is_blocklisted("::1") is True
            assert is_blocklisted("::2") is False
