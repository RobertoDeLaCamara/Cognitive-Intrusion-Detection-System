"""Tests for Dispatcher payload-match attribution (issue #21)."""

from scapy.all import IP, UDP, Raw

from src.capture.dispatcher import Dispatcher

_ATTACK = b"host=x; cat /etc/passwd"


def _flush(packets) -> dict:
    """Dispatch *packets*, flush every flow, return {flow_key: payload_matches}."""
    seen = {}

    def callback(record, flow_vec, host_vec, payload_matches, payload_features, ja3_info):
        seen[record.key] = payload_matches

    d = Dispatcher(flow_callback=callback)
    for pkt in packets:
        d.dispatch(IP(bytes(pkt)))  # build it, as a captured packet would be
    d.flush_all()
    return seen


def test_payload_match_stays_on_its_own_flow():
    """A match in one flow must not leak onto another flow from the same src_ip."""
    attack = IP(src="10.0.0.5", dst="10.0.0.9") / UDP(sport=40000, dport=8080) / Raw(_ATTACK)
    multicast = IP(src="10.0.0.5", dst="224.0.0.1") / UDP(sport=40001, dport=5353) / Raw(b"\x00\x01")
    # Clean flow first: the old per-src_ip lookup handed the hit to whichever
    # flow from that host was flushed first. Flows need >= 2 packets.
    seen = _flush([multicast, multicast, attack, attack])
    assert seen[("10.0.0.5", "10.0.0.9", 40000, 8080, 17)] == ["command_injection"]
    assert seen[("10.0.0.5", "224.0.0.1", 40001, 5353, 17)] == []


def test_reverse_direction_match_not_attributed_to_initiator():
    """A pattern in the server's response must not flag the client's flow."""
    request = IP(src="10.0.0.5", dst="10.0.0.9") / UDP(sport=40000, dport=8080) / Raw(b"GET /")
    response = IP(src="10.0.0.9", dst="10.0.0.5") / UDP(sport=8080, dport=40000) / Raw(_ATTACK)
    # A separate flow initiated by the server: the old per-src_ip lookup
    # attached the response's match to it.
    server_flow = IP(src="10.0.0.9", dst="10.0.0.20") / UDP(sport=50000, dport=53) / Raw(b"\x12\x34")
    seen = _flush([request, response, server_flow, server_flow])
    assert seen == {
        ("10.0.0.5", "10.0.0.9", 40000, 8080, 17): [],
        ("10.0.0.9", "10.0.0.20", 50000, 53, 17): [],
    }
