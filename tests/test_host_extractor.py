"""Tests for the host-level feature extractor."""

import pytest
import numpy as np
from unittest.mock import MagicMock

from src.features.host_extractor import HostExtractor, HOST_FEATURE_NAMES


def _make_ip_packet(src="192.168.1.1", proto="TCP", dport=80, size=100):
    pkt = MagicMock()
    pkt.__len__ = lambda self: size

    from scapy.all import IP, TCP, UDP, ICMP, Raw
    ip = MagicMock()
    ip.src = src
    ip.proto = {"TCP": 6, "UDP": 17, "ICMP": 1}[proto]

    tcp = MagicMock()
    tcp.dport = dport
    tcp.payload = MagicMock()

    def contains(layer):
        if layer is IP:
            return True
        if layer is TCP:
            return proto == "TCP"
        if layer is UDP:
            return proto == "UDP"
        if layer is ICMP:
            return proto == "ICMP"
        return False

    pkt.__contains__ = lambda self, layer: contains(layer)
    pkt.__getitem__  = lambda self, layer: ip if layer is IP else tcp
    return pkt


def test_feature_name_count():
    assert len(HOST_FEATURE_NAMES) == 18


def test_no_features_before_min_packets():
    ext = HostExtractor()
    pkt = _make_ip_packet()
    ext.process_packet(pkt)
    ext.process_packet(pkt)
    features = ext.extract_features("192.168.1.1")
    assert features is None


def test_features_after_enough_packets():
    ext = HostExtractor()
    pkt = _make_ip_packet()
    for _ in range(5):
        ext.process_packet(pkt)
    features = ext.extract_features("192.168.1.1")
    assert features is not None
    assert features.shape == (18,)
    assert not np.any(np.isnan(features))


def test_unknown_ip_returns_none():
    ext = HostExtractor()
    assert ext.extract_features("99.99.99.99") is None


def test_multiple_ips_tracked():
    ext = HostExtractor()
    for ip in ["10.0.0.1", "10.0.0.2", "10.0.0.3"]:
        for _ in range(5):
            ext.process_packet(_make_ip_packet(src=ip))
    assert len(ext.tracked_ips()) == 3


def test_eviction_when_max_ips_exceeded():
    import src.features.host_extractor as he_mod
    original = he_mod.MAX_TRACKED_IPS
    he_mod.MAX_TRACKED_IPS = 2
    ext = HostExtractor()
    for ip in ["10.0.0.1", "10.0.0.2", "10.0.0.3"]:
        for _ in range(3):
            ext.process_packet(_make_ip_packet(src=ip))
    he_mod.MAX_TRACKED_IPS = original
    assert len(ext.tracked_ips()) == 2


def test_protocol_ratios():
    ext = HostExtractor()
    for _ in range(3):
        ext.process_packet(_make_ip_packet(src="10.0.0.1", proto="TCP"))
    for _ in range(3):
        ext.process_packet(_make_ip_packet(src="10.0.0.1", proto="UDP"))
    features = ext.extract_features("10.0.0.1")
    assert features is not None
    tcp_ratio_idx = HOST_FEATURE_NAMES.index("tcp_ratio")
    udp_ratio_idx = HOST_FEATURE_NAMES.index("udp_ratio")
    assert features[tcp_ratio_idx] == pytest.approx(0.5)
    assert features[udp_ratio_idx] == pytest.approx(0.5)


# --- windowed volume features (host_extractor schema 2) -----------------------

from unittest import mock  # noqa: E402

from scapy.all import IP, TCP  # noqa: E402

from src.features.host_extractor import HostHistory, HostExtractor as _HX  # noqa: E402

_IDX = {n: i for i, n in enumerate(HOST_FEATURE_NAMES)}


def _vector_after(n_packets, pps, size_pad=0, idle=0.0):
    """Feed n_packets at pps packets/s and compute the vector (optionally idle seconds later)."""
    h = HostHistory()
    t = 1000.0
    for i in range(n_packets):
        t = 1000.0 + i / pps
        h.add_packet(IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=443) / (b"x" * size_pad), t)
    with mock.patch("time.time", return_value=t + idle):
        return _HX()._compute(h)


def test_volume_features_do_not_grow_with_host_lifetime():
    """Stationary traffic gives the same volume features after 10x more packets (was x8 in 40 min)."""
    short = _vector_after(300, pps=50)
    long_ = _vector_after(3000, pps=50)
    for name in ("total_packets", "total_bytes", "session_duration", "packets_per_sec", "bytes_per_sec"):
        i = _IDX[name]
        assert long_[i] == pytest.approx(short[i], rel=0.05), name


def test_total_packets_and_bytes_are_bounded_by_the_window():
    from src.config import HOST_WINDOW_SIZE
    v = _vector_after(HOST_WINDOW_SIZE * 5, pps=100)
    assert v[_IDX["total_packets"]] == HOST_WINDOW_SIZE
    assert v[_IDX["total_bytes"]] > 0


def test_rate_decays_when_the_host_goes_quiet():
    busy = _vector_after(200, pps=100)
    quiet = _vector_after(200, pps=100, idle=60.0)
    assert quiet[_IDX["packets_per_sec"]] < busy[_IDX["packets_per_sec"]] / 10
    assert quiet[_IDX["session_duration"]] > busy[_IDX["session_duration"]]
