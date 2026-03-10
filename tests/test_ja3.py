"""Tests for JA3 TLS fingerprint extraction."""

import struct
import pytest
from src.features.ja3 import (
    extract_ja3, _parse_client_hello, is_malicious_ja3,
    load_malicious_ja3, _MALICIOUS_JA3, _GREASE,
)


def _build_client_hello(
    version=0x0303,
    ciphers=(0xC02C, 0xC02B),
    extensions=(),
    curves=(),
    point_formats=(),
    include_grease=False,
):
    """Build a minimal TLS ClientHello record for testing."""
    ch_version = struct.pack("!H", version)
    random = b"\x00" * 32
    session_id = b"\x00"  # length 0

    # Ciphers
    cipher_list = list(ciphers)
    if include_grease:
        cipher_list.insert(0, 0x0A0A)
    cs_data = b"".join(struct.pack("!H", c) for c in cipher_list)
    cs = struct.pack("!H", len(cs_data)) + cs_data

    compression = b"\x01\x00"

    # Extensions
    ext_payload = b""
    for ext_type in extensions:
        ext_payload += struct.pack("!HH", ext_type, 0)

    # Supported groups extension (0x000A)
    if curves:
        groups_data = b"".join(struct.pack("!H", g) for g in curves)
        groups_ext = struct.pack("!H", len(groups_data)) + groups_data
        ext_payload += struct.pack("!HH", 0x000A, len(groups_ext)) + groups_ext

    # EC point formats extension (0x000B)
    if point_formats:
        pf_data = bytes([len(point_formats)] + list(point_formats))
        ext_payload += struct.pack("!HH", 0x000B, len(pf_data)) + pf_data

    ext_block = struct.pack("!H", len(ext_payload)) + ext_payload

    ch = ch_version + random + session_id + cs + compression + ext_block
    hs = b"\x01" + struct.pack("!I", len(ch))[1:] + ch
    record = struct.pack("!BHH", 22, 0x0301, len(hs)) + hs
    return record


def _make_packet(payload):
    """Create a mock Scapy-like packet with TCP + Raw layers."""
    from unittest.mock import MagicMock
    from scapy.all import TCP, Raw

    pkt = MagicMock()
    pkt.__contains__ = lambda self, layer: layer in (TCP, Raw)
    raw = MagicMock()
    raw.load = payload
    pkt.__getitem__ = lambda self, layer: raw if layer is Raw else MagicMock()
    return pkt


class TestParseClientHello:
    def test_basic_parse(self):
        data = _build_client_hello()
        result = _parse_client_hello(data)
        assert result is not None
        assert result["version"] == 0x0303
        assert result["ciphers"] == [0xC02C, 0xC02B]

    def test_grease_filtered(self):
        data = _build_client_hello(ciphers=(0x0A0A, 0xC02C), include_grease=False)
        # 0x0A0A is GREASE, should be filtered
        result = _parse_client_hello(data)
        assert 0x0A0A not in result["ciphers"]
        assert 0xC02C in result["ciphers"]

    def test_with_extensions(self):
        data = _build_client_hello(extensions=(0x0000, 0x0017))
        result = _parse_client_hello(data)
        assert 0x0000 in result["extensions"]
        assert 0x0017 in result["extensions"]

    def test_with_curves_and_point_formats(self):
        data = _build_client_hello(curves=(0x0017, 0x0018), point_formats=(0, 1))
        result = _parse_client_hello(data)
        assert result["elliptic_curves"] == [0x0017, 0x0018]
        assert result["ec_point_formats"] == [0, 1]

    def test_too_short_returns_none(self):
        assert _parse_client_hello(b"\x16\x03") is None
        assert _parse_client_hello(b"") is None

    def test_non_handshake_returns_none(self):
        # Content type 23 = Application Data, not Handshake
        data = struct.pack("!BHH", 23, 0x0303, 0) + b"\x00"
        assert _parse_client_hello(data) is None

    def test_non_client_hello_returns_none(self):
        # Handshake type 2 = ServerHello
        hs = b"\x02" + b"\x00\x00\x04" + b"\x00" * 4
        record = struct.pack("!BHH", 22, 0x0301, len(hs)) + hs
        assert _parse_client_hello(record) is None


class TestExtractJA3:
    def test_returns_hash_and_string(self):
        data = _build_client_hello()
        pkt = _make_packet(data)
        result = extract_ja3(pkt)
        assert result is not None
        ja3_hash, ja3_str = result
        assert len(ja3_hash) == 32  # MD5 hex
        assert ja3_str.startswith("771,")  # TLS 1.2 = 0x0303 = 771

    def test_non_tls_returns_none(self):
        pkt = _make_packet(b"GET / HTTP/1.1\r\n")
        assert extract_ja3(pkt) is None

    def test_no_raw_layer_returns_none(self):
        from unittest.mock import MagicMock
        from scapy.all import TCP, Raw
        pkt = MagicMock()
        pkt.__contains__ = lambda self, layer: layer is TCP
        assert extract_ja3(pkt) is None

    def test_deterministic_hash(self):
        data = _build_client_hello(ciphers=(0xC02C,), extensions=(0x0000,))
        pkt1 = _make_packet(data)
        pkt2 = _make_packet(data)
        r1 = extract_ja3(pkt1)
        r2 = extract_ja3(pkt2)
        assert r1[0] == r2[0]  # same hash
        assert r1[1] == r2[1]  # same string

    def test_different_ciphers_different_hash(self):
        pkt1 = _make_packet(_build_client_hello(ciphers=(0xC02C,)))
        pkt2 = _make_packet(_build_client_hello(ciphers=(0xC02B,)))
        assert extract_ja3(pkt1)[0] != extract_ja3(pkt2)[0]


class TestMaliciousJA3:
    def test_not_malicious_by_default(self):
        assert is_malicious_ja3("abc123") is False

    def test_malicious_after_add(self):
        _MALICIOUS_JA3.add("deadbeef1234")
        try:
            assert is_malicious_ja3("deadbeef1234") is True
        finally:
            _MALICIOUS_JA3.discard("deadbeef1234")

    def test_load_from_file(self, tmp_path):
        f = tmp_path / "bad_ja3.txt"
        f.write_text("# comment\naaa111\nbbb222\n\n")
        load_malicious_ja3(str(f))
        try:
            assert is_malicious_ja3("aaa111") is True
            assert is_malicious_ja3("bbb222") is True
            assert is_malicious_ja3("ccc333") is False
        finally:
            _MALICIOUS_JA3.discard("aaa111")
            _MALICIOUS_JA3.discard("bbb222")

    def test_load_missing_file_no_error(self):
        load_malicious_ja3("/nonexistent/path/ja3.txt")  # should not raise
