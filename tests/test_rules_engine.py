"""Tests for the rules-based detection engine."""

import pytest
import numpy as np
from src.engines.rules import RulesEngine


class _FakeRecord:
    def __init__(self, src="1.2.3.4", dst="5.6.7.8", sport=1234, dport=80,
                 proto=6, fwd_lengths=None, bwd_lengths=None,
                 start_time=0.0, last_time=1.0):
        self.key = (src, dst, sport, dport, proto)
        self.fwd_lengths = fwd_lengths or []
        self.bwd_lengths = bwd_lengths or []
        self.start_time = start_time
        self.last_time = last_time


def _zero_flow_vec():
    return np.zeros(76, dtype=np.float32)


@pytest.fixture
def engine():
    return RulesEngine()


def test_clean_traffic_no_alert(engine):
    rec = _FakeRecord(fwd_lengths=[100, 200], bwd_lengths=[80])
    score, triggered = engine.evaluate(rec, _zero_flow_vec(), [])
    assert score == 0.0
    assert triggered == []


def test_icmp_flood_triggers(engine):
    rec = _FakeRecord(proto=1, fwd_lengths=[28] * 100)
    score, triggered = engine.evaluate(rec, _zero_flow_vec(), [])
    assert score == 1.0
    assert "icmp_flood" in triggered


def test_large_payload_triggers(engine):
    rec = _FakeRecord(fwd_lengths=[15000])
    score, triggered = engine.evaluate(rec, _zero_flow_vec(), [])
    assert score == 1.0
    assert "large_payload" in triggered


def test_payload_match_triggers(engine):
    rec = _FakeRecord(fwd_lengths=[50])
    score, triggered = engine.evaluate(rec, _zero_flow_vec(), ["sql_injection"])
    assert score == 1.0
    assert "payload:sql_injection" in triggered


def test_syn_scan_triggers(engine):
    from src.features.flow_extractor import FLOW_FEATURE_NAMES
    vec = _zero_flow_vec()
    syn_idx = FLOW_FEATURE_NAMES.index("syn_flag_cnt")
    fwd_idx = FLOW_FEATURE_NAMES.index("tot_fwd_pkts")
    vec[syn_idx] = 25  # above PORT_SCAN_THRESHOLD (20)
    vec[fwd_idx] = 3   # below 5
    rec = _FakeRecord(fwd_lengths=[40, 40, 40])
    score, triggered = engine.evaluate(rec, vec, [])
    assert score == 1.0
    assert "syn_scan" in triggered


def test_asymmetric_upload_triggers(engine):
    rec = _FakeRecord(
        fwd_lengths=[1000] * 20,
        bwd_lengths=[10],
        last_time=1.0
    )
    score, triggered = engine.evaluate(rec, _zero_flow_vec(), [])
    assert score == 1.0
    assert "asymmetric_upload" in triggered


def test_malicious_ja3_triggers(engine):
    rec = _FakeRecord(fwd_lengths=[100])
    ja3 = {"hash": "abc123", "string": "771,49196-49195", "malicious": True}
    score, triggered = engine.evaluate(rec, _zero_flow_vec(), [], ja3_info=ja3)
    assert score == 1.0
    assert "malicious_ja3" in triggered


def test_benign_ja3_no_trigger(engine):
    rec = _FakeRecord(fwd_lengths=[100])
    ja3 = {"hash": "abc123", "string": "771,49196-49195", "malicious": False}
    score, triggered = engine.evaluate(rec, _zero_flow_vec(), [], ja3_info=ja3)
    assert "malicious_ja3" not in triggered


def test_no_ja3_no_trigger(engine):
    rec = _FakeRecord(fwd_lengths=[100])
    score, triggered = engine.evaluate(rec, _zero_flow_vec(), [], ja3_info=None)
    assert "malicious_ja3" not in triggered
