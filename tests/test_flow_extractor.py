"""Tests for the CICFlowMeter-compatible flow extractor."""

import time
from unittest.mock import MagicMock

from src.features.flow_extractor import FlowExtractor, FlowRecord, FLOW_FEATURE_NAMES


def _make_tcp_packet(src="192.168.1.1", dst="10.0.0.1", sport=12345, dport=80,
                     size=100, flags=0x02):
    """Create a minimal mock Scapy TCP packet."""
    pkt = MagicMock()
    pkt.__len__ = lambda self: size
    pkt.__contains__ = lambda self, layer: layer.__name__ in ("IP", "TCP")

    ip = MagicMock()
    ip.src = src
    ip.dst = dst
    ip.proto = 6
    ip.ihl = 5

    tcp = MagicMock()
    tcp.sport = sport
    tcp.dport = dport
    tcp.flags = flags
    tcp.window = 65535
    tcp.payload = MagicMock()

    from scapy.all import IP
    pkt.__getitem__ = lambda self, layer: ip if layer is IP else tcp
    return pkt


def test_feature_vector_length():
    """FlowRecord.to_feature_vector() must produce exactly 76 features."""
    rec = FlowRecord(key=("1.2.3.4", "5.6.7.8", 1234, 80, 6))
    rec.start_time = time.time() - 1
    rec.last_time  = time.time()
    rec.fwd_lengths = [100, 200, 150]
    rec.bwd_lengths = [80, 90]
    rec.fwd_times   = [rec.start_time, rec.start_time + 0.1, rec.start_time + 0.3]
    rec.bwd_times   = [rec.start_time + 0.05, rec.start_time + 0.2]
    rec._current_active_start = rec.start_time

    vec = rec.to_feature_vector()
    assert vec is not None
    assert len(vec) == 76
    assert len(FLOW_FEATURE_NAMES) == 76


def test_feature_names_count():
    assert len(FLOW_FEATURE_NAMES) == 76


def test_insufficient_packets():
    rec = FlowRecord(key=("1.2.3.4", "5.6.7.8", 1234, 80, 6))
    rec.start_time = time.time()
    rec.last_time  = time.time()
    rec.fwd_lengths = [100]
    assert rec.to_feature_vector() is None


def test_extractor_flow_count():
    extractor = FlowExtractor()
    assert extractor.active_flow_count == 0


def test_expired_flows_collected():
    """Flows older than FLOW_TIMEOUT should be returned by collect_expired."""
    import src.features.flow_extractor as fe_mod
    original_timeout = fe_mod.FLOW_TIMEOUT

    # Patch timeout to 0 so every flow is immediately expired
    fe_mod.FLOW_TIMEOUT = 0
    extractor = FlowExtractor()

    rec = FlowRecord(key=("1.1.1.1", "2.2.2.2", 100, 80, 6))
    rec.start_time = time.time() - 2
    rec.last_time  = time.time() - 2
    rec.fwd_lengths = [100, 200, 150]
    rec.bwd_lengths = [80]
    rec.fwd_times   = [rec.start_time]
    rec.bwd_times   = [rec.start_time + 0.05]
    rec._current_active_start = rec.start_time

    extractor._flows[rec.key] = rec
    expired = extractor.collect_expired()

    fe_mod.FLOW_TIMEOUT = original_timeout
    assert len(expired) == 1
    assert expired[0][1].shape == (76,)


def test_fwd_payloads_accumulated():
    """FlowRecord should store forward payload samples."""
    rec = FlowRecord(key=("1.2.3.4", "5.6.7.8", 1234, 80, 6))
    assert rec.fwd_payloads == []

    from scapy.all import IP
    pkt = MagicMock()
    pkt.__len__ = lambda self: 200

    ip = MagicMock()
    ip.src = "1.2.3.4"
    ip.dst = "5.6.7.8"
    ip.proto = 6
    ip.ihl = 5

    tcp = MagicMock()
    tcp.sport = 1234
    tcp.dport = 80
    tcp.flags = 0x18  # PSH+ACK
    tcp.window = 65535
    # Use a real bytes object wrapped so bytes() works
    tcp.payload = b"A" * 50

    def contains(layer):
        return layer.__name__ in ("IP", "TCP")
    pkt.__contains__ = lambda self, layer: contains(layer)
    pkt.__getitem__ = lambda self, layer: ip if layer is IP else tcp

    ts = time.time()
    rec.add_packet(pkt, ts, is_forward=True)
    assert len(rec.fwd_payloads) == 1
    assert rec.fwd_payloads[0] == b"A" * 50


def test_fwd_payloads_not_stored_for_backward():
    """Backward packets should not add to fwd_payloads."""
    rec = FlowRecord(key=("1.2.3.4", "5.6.7.8", 1234, 80, 6))

    from scapy.all import IP
    pkt = MagicMock()
    pkt.__len__ = lambda self: 100

    ip = MagicMock()
    ip.src = "5.6.7.8"
    ip.dst = "1.2.3.4"
    ip.proto = 6
    ip.ihl = 5

    tcp = MagicMock()
    tcp.sport = 80
    tcp.dport = 1234
    tcp.flags = 0x10  # ACK
    tcp.window = 65535
    tcp.payload = b"B" * 30

    def contains(layer):
        return layer.__name__ in ("IP", "TCP")
    pkt.__contains__ = lambda self, layer: contains(layer)
    pkt.__getitem__ = lambda self, layer: ip if layer is IP else tcp

    ts = time.time()
    rec.add_packet(pkt, ts, is_forward=False)
    assert len(rec.fwd_payloads) == 0


def test_src_dst_ip_properties():
    rec = FlowRecord(key=("1.2.3.4", "5.6.7.8", 1234, 80, 6))
    assert rec.src_ip == "1.2.3.4"
    assert rec.dst_ip == "5.6.7.8"


def test_collect_all_returns_valid_flows():
    extractor = FlowExtractor()
    rec = FlowRecord(key=("1.1.1.1", "2.2.2.2", 100, 80, 6))
    rec.start_time = time.time() - 1
    rec.last_time = time.time()
    rec.fwd_lengths = [100, 200, 150]
    rec.bwd_lengths = [80]
    rec.fwd_times = [rec.start_time, rec.start_time + 0.1, rec.start_time + 0.3]
    rec.bwd_times = [rec.start_time + 0.05]
    rec._current_active_start = rec.start_time
    extractor._flows[rec.key] = rec

    results = extractor.collect_all()
    assert len(results) == 1
    assert results[0][1].shape == (76,)
    assert extractor.active_flow_count == 0


def test_evict_oldest_when_full():
    import src.features.flow_extractor as fe_mod
    original = fe_mod.MAX_ACTIVE_FLOWS
    fe_mod.MAX_ACTIVE_FLOWS = 2
    extractor = FlowExtractor()

    for i, key in enumerate([
        ("10.0.0.1", "10.0.0.2", 100, 80, 6),
        ("10.0.0.3", "10.0.0.4", 200, 80, 6),
        ("10.0.0.5", "10.0.0.6", 300, 80, 6),
    ]):
        rec = FlowRecord(key=key)
        rec.start_time = float(i)
        rec.last_time = float(i)
        extractor._flows[key] = rec
        if len(extractor._flows) > fe_mod.MAX_ACTIVE_FLOWS:
            extractor._evict_oldest()

    fe_mod.MAX_ACTIVE_FLOWS = original
    assert extractor.active_flow_count == 2
