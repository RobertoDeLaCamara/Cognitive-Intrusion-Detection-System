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


# ── per-flow export and Hopfield novelty ───────────────────────────────────

def _no_other_engines(rp, monkeypatch):
    off = type("X", (), {"is_available": False})()
    for name in ("iforest", "lstm", "baseline"):
        monkeypatch.setattr(rp, name, off)
    monkeypatch.setattr(rp, "rules", type("R", (), {"evaluate": staticmethod(lambda *a, **k: (0.0, []))})())


class _Rec:
    key = ("10.0.0.1", "10.0.0.2", 1234, 80, 6)
    start_time = 100.0
    fwd_payloads = []


def test_novelty_comes_from_predict_with_novelty(monkeypatch):
    rp = _load("pcap_replay")

    class FT:
        is_available = True
        def predict(self, vec, payload=None): raise AssertionError("must use predict_with_novelty")
        def predict_with_novelty(self, vec, payload=None): return "DoS", 0.8, -0.42

    monkeypatch.setattr(rp, "supervised", FT())
    _no_other_engines(rp, monkeypatch)
    import numpy as np
    pred = rp.run_detection(_Rec(), np.zeros(76, dtype=np.float32), None, [])
    assert pred["novelty"] == -0.42
    assert pred["engine_scores"]["supervised"] == 0.8
    assert pred["attack_type"] == "DoS"
    assert (pred["src_port"], pred["protocol"], pred["start_time"]) == (1234, 6, 100.0)


def test_engine_without_novelty_api_gives_none(monkeypatch):
    rp = _load("pcap_replay")

    class RF:
        is_available = True
        def predict(self, vec, payload=None): return "DoS", 0.7

    monkeypatch.setattr(rp, "supervised", RF())
    _no_other_engines(rp, monkeypatch)
    import numpy as np
    pred = rp.run_detection(_Rec(), np.zeros(76, dtype=np.float32), None, [])
    assert pred["novelty"] is None
    assert pred["engine_scores"]["supervised"] == 0.7


def test_replay_predictions_carry_flow_fields(replay):
    _, result = replay
    p = result.predictions[0]
    for k in ("file", "src_port", "protocol", "start_time", "novelty"):
        assert k in p
    assert "features" not in p                     # only kept when asked


def _pred(label, novelty, rules=(), **kw):
    p = {"file": "x.pcap", "flow_key": "k", "src_ip": "a", "dst_ip": "b", "src_port": 1, "dst_port": 2,
         "protocol": 6, "start_time": 1.0, "true_label": label, "ensemble_score": 0.3,
         "is_anomaly": False, "attack_type": "Benign", "triggered_rules": list(rules),
         "engine_scores": {"supervised": 0.0, "isolation_forest": None, "lstm": None,
                           "baseline": None, "rules": 0.0},
         "novelty": novelty}
    p.update(kw)
    return p


def test_flows_csv_columns_and_features(tmp_path):
    rp = _load("pcap_replay")
    import csv
    preds = [_pred("BENIGN", -0.9, rules=("a", "b"), features=list(range(76))),
             _pred("port_scan", None)]
    out = tmp_path / "f.csv"
    assert rp.write_flows_csv(preds, str(out), with_features=True) == 2
    rows = list(csv.DictReader(open(out)))
    assert list(rows[0])[:len(rp.FLOW_CSV_FIELDS)] == list(rp.FLOW_CSV_FIELDS)
    assert len(rows[0]) == len(rp.FLOW_CSV_FIELDS) + 76
    assert rows[0]["triggered_rules"] == "a;b"
    assert rows[0]["novelty"] == "-0.9" and rows[1]["novelty"] == ""
    assert rows[0][f"f_{rp.FLOW_FEATURE_NAMES[5]}"] == "5"
    assert rows[1][f"f_{rp.FLOW_FEATURE_NAMES[0]}"] == ""   # flow without stored features
    rp.write_flows_csv(preds, str(out))
    assert len(next(csv.reader(open(out)))) == len(rp.FLOW_CSV_FIELDS)


def test_novelty_summary(monkeypatch):
    rp = _load("pcap_replay")
    agg = rp.EvalResult()
    agg.predictions = ([_pred("BENIGN", -1.0 + i / 100) for i in range(100)]
                       + [_pred("port_scan", -0.5), _pred("port_scan", -0.98)])
    s = rp.novelty_summary(agg, current=-0.95)
    assert s["benign_flows"] == 100
    assert s["suggested_threshold"] == pytest.approx(-0.02)       # q0.99 of benign
    assert s["per_label"]["BENIGN"]["above_current"] == pytest.approx(0.95)
    assert s["per_label"]["port_scan"]["above_suggested"] == 0.0
    assert s["per_label"]["port_scan"]["above_current"] == 0.5
    lines = "\n".join(rp.novelty_report_lines(s))
    assert "## Hopfield novelty (shadow mode)" in lines and "| port_scan | 2 |" in lines


def test_novelty_summary_absent_without_scores():
    rp = _load("pcap_replay")
    agg = rp.EvalResult()
    agg.predictions = [_pred("BENIGN", None)]
    assert rp.novelty_summary(agg, current=None) is None


def _replay_packets(tmp_path, pkts):
    from scapy.all import wrpcap
    rp = _load("pcap_replay")
    path = tmp_path / "p.pcap"
    wrpcap(str(path), pkts)
    return rp.replay_pcap(str(path)).predictions


def _tcp_exchange(sport, dport, request, response):
    from scapy.all import IP, TCP, Raw
    c, s = "10.0.0.2", "10.0.0.3"
    pkts = [
        IP(src=c, dst=s) / TCP(sport=sport, dport=dport, flags="S", seq=1),
        IP(src=s, dst=c) / TCP(sport=dport, dport=sport, flags="SA", seq=1, ack=2),
        IP(src=c, dst=s) / TCP(sport=sport, dport=dport, flags="PA", seq=2, ack=2) / Raw(request),
        IP(src=s, dst=c) / TCP(sport=dport, dport=sport, flags="PA", seq=2, ack=40) / Raw(response),
        IP(src=c, dst=s) / TCP(sport=sport, dport=dport, flags="FA", seq=40, ack=200),
    ]
    for i, p in enumerate(pkts):
        p.time = 1000.0 + i * 0.01
    return pkts


def test_server_response_payload_is_not_an_attack(tmp_path):
    """HTML served back to the client (<script>, <img ...>) must not fire payload:xss."""
    pkts = _tcp_exchange(40000, 3128, b"GET http://jenkins/ HTTP/1.1\r\n\r\n",
                         b'HTTP/1.1 200 OK\r\n\r\n<script type="text/javascript"><img src="/x">')
    preds = _replay_packets(tmp_path, pkts)
    assert preds and not any("payload:xss" in p["triggered_rules"] for p in preds)


def test_client_request_payload_still_fires(tmp_path):
    pkts = _tcp_exchange(40001, 80, b"GET /?q=<script>alert(1)</script> HTTP/1.1\r\n\r\n",
                         b"HTTP/1.1 200 OK\r\n\r\nok")
    preds = _replay_packets(tmp_path, pkts)
    assert any("payload:xss" in p["triggered_rules"] for p in preds)


def test_ssh_flow_payload_is_ignored(tmp_path):
    pkts = _tcp_exchange(40002, 22, b"<script>alert(1)</script>", b"SSH-2.0-OpenSSH_9.6\r\n")
    preds = _replay_packets(tmp_path, pkts)
    assert preds and not any(r.startswith("payload:") for p in preds for r in p["triggered_rules"])
