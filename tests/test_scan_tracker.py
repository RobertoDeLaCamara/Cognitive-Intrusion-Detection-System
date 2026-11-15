"""Host-level port-scan rule (issue #87): tracker, rules engine, dispatcher and replay."""

import numpy as np
from scapy.all import IP, TCP

from src.capture.dispatcher import Dispatcher
from src.engines.rules import RulesEngine
from src.features.host_extractor import HostExtractor
from src.features.scan_tracker import ScanTracker

ATTACKER, TARGET = "10.0.0.66", "10.0.0.9"


def _syn(src, dst, dport, sport=40000, flags="S"):
    return _built(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags))


def _built(pkt):
    """Dissect the packet from bytes, as a captured one is (fills ihl, lengths, checksums)."""
    return IP(bytes(pkt))


def test_scan_across_ports_is_flagged():
    t = ScanTracker(port_threshold=15, window=60)
    for i in range(15):
        t.observe(ATTACKER, TARGET, 1000 + i, 100.0 + i * 0.1)
    assert t.hits(ATTACKER, TARGET, 100.0) == ["port_scan"]  # the very first probe too
    assert t.hits(ATTACKER, TARGET, 101.4) == ["port_scan"]


def test_below_threshold_is_not_flagged():
    t = ScanTracker(port_threshold=15, window=60)
    for i in range(14):
        t.observe(ATTACKER, TARGET, 1000 + i, 100.0 + i)
    assert t.hits(ATTACKER, TARGET, 100.0) == []


def test_same_port_many_times_is_not_a_scan():
    t = ScanTracker(port_threshold=15, window=60)
    for i in range(200):
        t.observe(ATTACKER, TARGET, 443, 100.0 + i * 0.1)
    assert t.hits(ATTACKER, TARGET, 100.0) == []


def test_slow_probing_outside_the_window_is_not_flagged():
    t = ScanTracker(port_threshold=15, window=60)
    for i in range(30):
        t.observe(ATTACKER, TARGET, 1000 + i, 100.0 + i * 10)  # 6 ports per window
    assert t.hits(ATTACKER, TARGET, 100.0) == []


def test_ports_on_different_targets_do_not_add_up():
    t = ScanTracker(port_threshold=15, window=60)
    for i in range(30):
        t.observe(ATTACKER, f"10.0.1.{i}", 22 + i % 2, 100.0 + i * 0.1)
    assert all(t.hits(ATTACKER, f"10.0.1.{i}", 100.0 + i * 0.1) == [] for i in range(30))


def test_allowlisted_source_is_ignored():
    t = ScanTracker(port_threshold=5, window=60, allowlist=[ATTACKER])
    for i in range(20):
        t.observe(ATTACKER, TARGET, 1000 + i, 100.0 + i * 0.1)
    assert t.hits(ATTACKER, TARGET, 100.0) == []


def test_threshold_zero_disables_the_rule():
    t = ScanTracker(port_threshold=0)
    for i in range(50):
        t.observe(ATTACKER, TARGET, 1000 + i, 100.0 + i * 0.1)
    assert t.hits(ATTACKER, TARGET, 100.0) == []


def test_flow_started_after_the_scan_is_not_a_hit():
    t = ScanTracker(port_threshold=15, window=60)
    for i in range(15):
        t.observe(ATTACKER, TARGET, 1000 + i, 100.0 + i * 0.1)
    assert t.hits(ATTACKER, TARGET, 500.0) == []
    assert t.hits(ATTACKER, TARGET, 50.0) == []


def test_flag_survives_until_the_flows_expire_then_is_pruned():
    t = ScanTracker(port_threshold=15, window=60, flag_ttl=600)
    for i in range(15):
        t.observe(ATTACKER, TARGET, 1000 + i, 100.0 + i * 0.1)
    # Unrelated traffic far in the future triggers the prune.
    t.observe("10.0.0.1", "10.0.0.2", 80, 5000.0)
    assert t.hits(ATTACKER, TARGET, 100.0) == []


def test_memory_is_bounded():
    t = ScanTracker(port_threshold=15, window=60, max_pairs=10)
    for i in range(100):
        t.observe(f"10.1.0.{i}", TARGET, 80, 100.0 + i)
    assert len(t._events) <= 10


def test_host_extractor_counts_only_connection_starts():
    h = HostExtractor()
    for i in range(20):  # SYN/ACK replies and plain ACKs are not probes
        h.process_packet(_syn(ATTACKER, TARGET, 2000 + i, flags="SA"), timestamp=100.0 + i * 0.1)
        h.process_packet(_syn(ATTACKER, TARGET, 2000 + i, flags="A"), timestamp=100.0 + i * 0.1)
    assert h.scan_tracker.hits(ATTACKER, TARGET, 100.0) == []
    for i in range(20):
        h.process_packet(_syn(ATTACKER, TARGET, 3000 + i), timestamp=200.0 + i * 0.1)
    assert h.scan_tracker.hits(ATTACKER, TARGET, 200.0) == ["port_scan"]


def test_rules_engine_reports_host_hits():
    class Rec:
        key = (ATTACKER, TARGET, 40000, 1000, 6)
        fwd_lengths = [0]
        bwd_lengths = []
        host_hits = ["port_scan"]

    score, triggered = RulesEngine().evaluate(Rec(), np.zeros(76, dtype=np.float32), [])
    assert score == 1.0 and triggered == ["port_scan"]


def test_port_scan_is_a_critical_rule_by_default():
    from src.config import CRITICAL_RULES
    assert "port_scan" in CRITICAL_RULES


def test_dispatcher_marks_each_probe_flow_of_a_scan():
    seen = {}

    def callback(record, flow_vec, host_vec, payload_matches, payload_features, ja3_info):
        seen[record.key] = list(record.host_hits)

    d = Dispatcher(flow_callback=callback)
    ts = 1_700_000_000.0
    for port in range(1, 41):
        probe = _syn(ATTACKER, TARGET, port, sport=50000 + port)
        reply = _built(IP(src=TARGET, dst=ATTACKER) / TCP(sport=port, dport=50000 + port, flags="RA"))
        d._flow_extractor.process_packet(probe, timestamp=ts)
        d._host_extractor.process_packet(probe, timestamp=ts)
        d._flow_extractor.process_packet(reply, timestamp=ts + 0.002)
        ts += 0.01
    d.flush_all()
    assert len(seen) == 40
    assert all(v == ["port_scan"] for v in seen.values())


def test_normal_client_is_not_flagged():
    seen = {}

    def callback(record, flow_vec, host_vec, payload_matches, payload_features, ja3_info):
        seen[record.key] = list(record.host_hits)

    d = Dispatcher(flow_callback=callback)
    ts = 1_700_000_000.0
    for i in range(30):  # 30 connections, all to :443
        for p in (_syn(ATTACKER, TARGET, 443, sport=41000 + i),
                  _built(IP(src=TARGET, dst=ATTACKER) / TCP(sport=443, dport=41000 + i, flags="RA"))):
            d._flow_extractor.process_packet(p, timestamp=ts)
            d._host_extractor.process_packet(p, timestamp=ts)
            ts += 0.01
    d.flush_all()
    assert seen and all(v == [] for v in seen.values())
