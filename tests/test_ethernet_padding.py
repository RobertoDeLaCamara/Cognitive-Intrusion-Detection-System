"""Ethernet frame padding must not count as application data (found with a live SYN flood)."""
from scapy.all import DNS, DNSQR, Ether, IP, Raw, TCP, UDP

from src.features.flow_extractor import FlowExtractor


def _frame(layers, pad_to=60):
    raw = bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / layers)
    return raw + b"\x00" * max(0, pad_to - len(raw))


def _flow(frames, n=1):
    fx = FlowExtractor()
    t = 1000.0
    for _ in range(n):
        for f in frames:
            fx.process_packet(Ether(f), timestamp=t)
            t += 0.05
    (rec, _vec), = fx.collect_all()
    return rec


def test_padded_syn_is_not_data():
    syn = _frame(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S"))
    assert len(syn) == 60
    rec = _flow([syn], n=40)
    assert rec.syn == 40
    assert rec.fwd_act_data_pkts == 0
    assert rec.fwd_payloads == []


def test_padded_pure_ack_is_not_data():
    ack = _frame(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="A"))
    rec = _flow([ack], n=5)
    assert rec.fwd_act_data_pkts == 0


def test_short_real_payload_is_kept_exactly():
    body = b"GET / HTTP/1.1\r\n\r\n"
    req = _frame(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="PA") / Raw(body))
    rec = _flow([req], n=2)
    assert rec.fwd_act_data_pkts == 2
    assert rec.fwd_payloads == [body, body]


def test_padded_tiny_payload_is_not_inflated():
    req = _frame(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="PA") / Raw(b"hi"))
    rec = _flow([req], n=2)
    assert rec.fwd_payloads == [b"hi", b"hi"]


def test_padded_udp_without_payload_is_not_data():
    udp = _frame(IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1234, dport=9999))
    rec = _flow([udp], n=3)
    assert rec.fwd_act_data_pkts == 0


def test_dns_query_payload_still_counts():
    q = _frame(IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1234, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.org")))
    rec = _flow([q], n=2)
    assert rec.fwd_act_data_pkts == 2


def test_syn_flood_flow_triggers_syn_scan_with_padding():
    from src.engines.registry import rules
    syn = _frame(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S"))
    rst = _frame(IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1234, flags="RA"))
    fx = FlowExtractor()
    for i in range(40):
        fx.process_packet(Ether(syn), timestamp=1000 + i * 0.05)
        fx.process_packet(Ether(rst), timestamp=1000 + i * 0.05 + 0.001)
    (rec, vec), = fx.collect_all()
    _score, triggered = rules.evaluate(rec, vec, [])
    assert "syn_scan" in triggered
