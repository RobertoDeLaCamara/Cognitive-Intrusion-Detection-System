"""pcap_replay.py + make_labelled_pcap.py: labelling, per-flow payload attribution, per-class metrics."""
import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("scapy")

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def replay(tmp_path_factory):
    gen, rp = _load("make_labelled_pcap"), _load("pcap_replay")
    d = tmp_path_factory.mktemp("synth")
    pkts, attacks = gen.generate(seed=7, duration=120.0)
    from scapy.all import wrpcap
    wrpcap(str(d / "t.pcap"), pkts)
    import csv
    with open(d / "a.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(attacks[0]))
        w.writeheader()
        w.writerows(attacks)
    result = rp.replay_pcap(str(d / "t.pcap"), attacks=rp.load_attacks(str(d / "a.csv")))
    return rp, result


def test_every_attack_class_is_labelled(replay):
    _, result = replay
    assert set(result.per_class()) == {
        "port_scan", "syn_flood", "sql_injection", "xss", "ssh_bruteforce", "dns_burst"}


def test_signature_attacks_are_detected(replay):
    _, result = replay
    pc = result.per_class()
    assert pc["sql_injection"]["recall"] == 1.0
    assert pc["xss"]["recall"] == 1.0
    assert pc["syn_flood"]["recall"] == 1.0


def test_payload_hits_do_not_leak_to_other_flows_of_the_same_host(replay):
    """The attacker's SQLi payload must not make its later port-scan flows look like SQLi."""
    _, result = replay
    scan = [p for p in result.predictions if p["true_label"] == "port_scan"]
    assert scan and not any("payload:sql_injection" in p["triggered_rules"] for p in scan)


def test_benign_traffic_is_mostly_quiet(replay):
    _, result = replay
    tp, fp, tn, fn = result._counts()
    assert fp / max(fp + tn, 1) < 0.05


def test_attack_window_and_relative_times():
    rp = _load("pcap_replay")
    rule = rp.AttackRule(label="x", src_ip="1.1.1.1", dst_port=80, start="+10", end="+20")
    key = ("1.1.1.1", "2.2.2.2", 1234, 80, 6)
    assert rule.matches(key, start_time=1015.0, t0=1000.0)
    assert not rule.matches(key, start_time=1030.0, t0=1000.0)
    assert not rule.matches(("1.1.1.1", "2.2.2.2", 1234, 81, 6), 1015.0, 1000.0)
    assert not rule.matches(("3.3.3.3", "2.2.2.2", 1234, 80, 6), 1015.0, 1000.0)


def test_flow_labels_match_either_direction():
    rp = _load("pcap_replay")
    labels = {"1.1.1.1-2.2.2.2-1234-80-6": "Web Attack"}
    assert rp.true_label(("2.2.2.2", "1.1.1.1", 80, 1234, 6), 0.0, 0.0, labels, None) == "Web Attack"
    assert rp.true_label(("9.9.9.9", "1.1.1.1", 80, 1234, 6), 0.0, 0.0, labels, None) == "BENIGN"


def test_baseline_engine_is_scored_like_the_pipeline(monkeypatch):
    rp = _load("pcap_replay")

    class Stub:
        is_available = True
        def __init__(self): self.updated = []
        def update(self, ip, vec): self.updated.append(ip)
        def anomaly_score(self, ip, vec): return 0.9

    stub = Stub()
    monkeypatch.setattr(rp, "baseline", stub)
    monkeypatch.setattr(rp, "rules", type("R", (), {"evaluate": staticmethod(lambda *a, **k: (0.0, []))})())

    class Rec:
        key = ("10.0.0.1", "10.0.0.2", 1234, 80, 6)
        src_ip = "10.0.0.1"
        fwd_payloads = []

    import numpy as np
    pred = rp.run_detection(Rec(), None, np.zeros(18, dtype=np.float32), [])
    assert stub.updated == ["10.0.0.1"]
    assert "baseline" in pred["active_engines"]


@pytest.mark.parametrize("label", ["Benign", "BENIGN", "benign"])
def test_benign_label_of_any_casing_scores_zero(monkeypatch, label):
    """The FT-Transformer answers "Benign"; comparing with "BENIGN" scored every flow as an attack."""
    rp = _load("pcap_replay")

    class Sup:
        is_available = True
        def predict(self, vec, payload=None): return label, 0.99

    monkeypatch.setattr(rp, "supervised", Sup())
    monkeypatch.setattr(rp, "iforest", type("X", (), {"is_available": False})())
    monkeypatch.setattr(rp, "lstm", type("X", (), {"is_available": False})())
    monkeypatch.setattr(rp, "baseline", type("X", (), {"is_available": False})())
    monkeypatch.setattr(rp, "rules", type("R", (), {"evaluate": staticmethod(lambda *a, **k: (0.0, []))})())

    class Rec:
        key = ("10.0.0.1", "10.0.0.2", 1234, 80, 6)
        fwd_payloads = []

    import numpy as np
    pred = rp.run_detection(Rec(), np.zeros(76, dtype=np.float32), None, [])
    assert pred["engine_scores"]["supervised"] == 0.0
