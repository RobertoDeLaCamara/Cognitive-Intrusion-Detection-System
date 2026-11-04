"""Offline replay must use the packet's capture time, not the wall clock."""
from scapy.all import IP, TCP

from src.features.flow_extractor import FlowExtractor
from src.features.host_extractor import HostExtractor


def _pkt(sport=40000, flags="S"):
    # round-trip through bytes so header fields (ihl, ...) are dissected like on a real capture
    return IP(bytes(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=sport, dport=80, flags=flags)))


def test_flow_times_follow_the_supplied_timestamp():
    fx = FlowExtractor()
    fx.process_packet(_pkt(), timestamp=1000.0)
    fx.process_packet(_pkt(flags="A"), timestamp=1010.0)
    (rec, _vec), = fx.collect_all()
    assert rec.start_time == 1000.0
    assert rec.last_time == 1010.0


def test_collect_expired_uses_the_supplied_now():
    fx = FlowExtractor()
    fx.process_packet(_pkt(), timestamp=1000.0)
    fx.process_packet(_pkt(flags="A"), timestamp=1000.5)
    assert fx.collect_expired(now=1001.0) == []
    expired = fx.collect_expired(now=1000.0 + 10_000)
    assert len(expired) == 1


def test_default_is_still_wall_clock():
    import time
    fx = FlowExtractor()
    before = time.time()
    fx.process_packet(_pkt())
    fx.process_packet(_pkt(flags="A"))
    (rec, _), = fx.collect_all()
    assert before <= rec.start_time <= time.time()


def test_host_rate_window_ends_at_the_supplied_now():
    hx = HostExtractor()
    for i in range(10):
        hx.process_packet(_pkt(sport=40000 + i), timestamp=1000.0 + i)
    a = hx.extract_features("10.0.0.1", now=1010.0)
    b = hx.extract_features("10.0.0.1", now=1010.0 + 3600)
    assert a is not None and b is not None
    assert not (a == b).all()
