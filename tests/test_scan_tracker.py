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


# ── brute force (issue #88) ────────────────────────────────────────────────

from src.features.scan_tracker import BruteForceTracker  # noqa: E402


def test_many_connections_to_ssh_are_flagged():
    t = BruteForceTracker(conn_threshold=15, window=60, ports=[22])
    for i in range(15):
        t.observe(ATTACKER, TARGET, 22, 51000 + i, 100.0 + i * 0.5)
    assert t.hits(ATTACKER, TARGET, 22, 100.0) == ["brute_force"]
    assert t.hits(ATTACKER, TARGET, 22, 106.0) == ["brute_force"]


def test_retransmitted_syn_is_not_a_new_connection():
    t = BruteForceTracker(conn_threshold=15, window=60, ports=[22])
    for i in range(100):  # same source port every time: one connection, retransmitted
        t.observe(ATTACKER, TARGET, 22, 51000, 100.0 + i * 0.1)
    assert t.hits(ATTACKER, TARGET, 22, 100.0) == []


def test_unwatched_port_is_ignored():
    t = BruteForceTracker(conn_threshold=5, window=60, ports=[22])
    for i in range(50):  # a browser opening many connections to 443
        t.observe(ATTACKER, TARGET, 443, 51000 + i, 100.0 + i * 0.1)
    assert t.hits(ATTACKER, TARGET, 443, 100.0) == []


def test_brute_force_needs_the_same_service():
    t = BruteForceTracker(conn_threshold=15, window=60, ports=[22, 3389])
    for i in range(30):  # alternating services: 15 each
        t.observe(ATTACKER, TARGET, 22 if i % 2 else 3389, 51000 + i, 100.0 + i * 0.1)
    assert t.hits(ATTACKER, TARGET, 22, 102.5) == t.hits(ATTACKER, TARGET, 3389, 102.5) == ["brute_force"]
    t2 = BruteForceTracker(conn_threshold=16, window=60, ports=[22, 3389])
    for i in range(30):
        t2.observe(ATTACKER, TARGET, 22 if i % 2 else 3389, 51000 + i, 100.0 + i * 0.1)
    assert t2.hits(ATTACKER, TARGET, 22, 102.5) == []


def test_brute_force_allowlist_and_disable():
    t = BruteForceTracker(conn_threshold=5, window=60, ports=[22], allowlist=[ATTACKER])
    for i in range(20):
        t.observe(ATTACKER, TARGET, 22, 51000 + i, 100.0 + i * 0.1)
    assert t.hits(ATTACKER, TARGET, 22, 100.0) == []
    off = BruteForceTracker(conn_threshold=0, ports=[22])
    for i in range(20):
        off.observe(ATTACKER, TARGET, 22, 51000 + i, 100.0 + i * 0.1)
    assert off.hits(ATTACKER, TARGET, 22, 100.0) == []


def test_slow_logins_are_not_brute_force():
    t = BruteForceTracker(conn_threshold=15, window=60, ports=[22])
    for i in range(30):  # one login every 10 s: 6 per window
        t.observe(ATTACKER, TARGET, 22, 51000 + i, 100.0 + i * 10)
    assert t.hits(ATTACKER, TARGET, 22, 100.0) == []


def test_host_extractor_feeds_both_trackers():
    h = HostExtractor()
    for i in range(20):
        h.process_packet(_syn(ATTACKER, TARGET, 22, sport=52000 + i), timestamp=100.0 + i * 0.1)
    assert h.host_hits(ATTACKER, TARGET, 22, 100.0) == ["brute_force"]
    assert h.host_hits(ATTACKER, TARGET, 80, 100.0) == []


def test_brute_force_is_critical_and_mapped():
    from src.config import CRITICAL_RULES
    from src.enrichment.mitre import enrich
    assert "brute_force" in CRITICAL_RULES
    assert enrich(None, ["brute_force"])[0]["id"] == "T1110"


def test_dispatcher_marks_each_login_flow_of_a_brute_force():
    seen = {}

    def callback(record, flow_vec, host_vec, payload_matches, payload_features, ja3_info):
        seen[record.key] = list(record.host_hits)

    d = Dispatcher(flow_callback=callback)
    ts = 1_700_000_000.0
    for i in range(30):
        for p in (_syn(ATTACKER, TARGET, 22, sport=53000 + i),
                  _built(IP(src=TARGET, dst=ATTACKER) / TCP(sport=22, dport=53000 + i, flags="SA"))):
            d._flow_extractor.process_packet(p, timestamp=ts)
            d._host_extractor.process_packet(p, timestamp=ts)
            ts += 0.2
    d.flush_all()
    assert len(seen) == 30
    assert all("brute_force" in v for v in seen.values())
    assert all("port_scan" not in v for v in seen.values())


def test_quiet_gap_between_two_scans_is_not_a_hit():
    t = ScanTracker(port_threshold=15, window=60)
    for i in range(15):  # scan 1 at t=100..101.4
        t.observe(ATTACKER, TARGET, 1000 + i, 100.0 + i * 0.1)
    for i in range(15):  # scan 2 at t=300..301.4, inside flag_ttl but far beyond the window
        t.observe(ATTACKER, TARGET, 2000 + i, 300.0 + i * 0.1)
    assert t.hits(ATTACKER, TARGET, 100.5) == ["port_scan"]
    assert t.hits(ATTACKER, TARGET, 200.0) == []  # benign flow in the gap
    assert t.hits(ATTACKER, TARGET, 300.0) == ["port_scan"]


def test_scan_with_short_pauses_stays_one_interval():
    t = ScanTracker(port_threshold=15, window=60)
    for i in range(60):  # 15 ports every 30 s, never a gap as long as the window
        t.observe(ATTACKER, TARGET, 1000 + i, 100.0 + (i // 15) * 30 + (i % 15) * 0.1)
    assert t.hits(ATTACKER, TARGET, 150.0) == ["port_scan"]
    assert len(t._flagged[(ATTACKER, TARGET)]) == 1


def test_old_intervals_are_pruned_one_by_one():
    t = ScanTracker(port_threshold=3, window=10, flag_ttl=100)
    for base in (100.0, 180.0):
        for i in range(3):
            t.observe(ATTACKER, TARGET, int(base) + i, base + i * 0.1)
    assert len(t._flagged[(ATTACKER, TARGET)]) == 2
    t.observe("10.0.0.1", TARGET, 1, 250.0)  # prune at 250: first interval (ends 100.2) is too old
    assert t.hits(ATTACKER, TARGET, 100.0) == []
    assert t.hits(ATTACKER, TARGET, 180.0) == ["port_scan"]
