"""Simulator sanity and the opt-in window dump hook of the collector."""

import numpy as np

from src.features.host_extractor import HOST_FEATURE_NAMES
from src.unsupervised import attack_sim
from src.unsupervised.collector import BaselineCollector, CollectedSample

IDX = {n: i for i, n in enumerate(HOST_FEATURE_NAMES)}


def _mean(rows, feat):
    return float(rows[0][:, IDX[feat]].mean())


class TestAttackSim:
    def test_shapes_and_time_order(self):
        for name, fn in attack_sim.ATTACKS.items():
            X, hosts, ts = fn(np.random.default_rng(1), seconds=5)
            assert X.shape[1] == 18 and len(X) == len(hosts) == len(ts) > 0, name
            assert np.all(np.diff(ts) >= 0), name
            assert np.isfinite(X).all(), name

    def test_syn_flood_is_far_faster_than_benign_and_tcp_only(self):
        rng = np.random.default_rng(1)
        flood = attack_sim.syn_flood(rng, seconds=3)
        benign = attack_sim.benign_hosts(rng, n_hosts=6, seconds=120)
        assert _mean(flood, "packets_per_sec") > 20 * _mean(benign, "packets_per_sec")
        assert _mean(flood, "tcp_ratio") == 1.0

    def test_port_scan_touches_many_ports(self):
        X, _, _ = attack_sim.port_scan(np.random.default_rng(1), seconds=10)
        assert X[-1, IDX["unique_ports"]] >= 50

    def test_dns_tunnel_is_udp_with_high_entropy_payload(self):
        X, _, _ = attack_sim.dns_tunnel(np.random.default_rng(1), seconds=20)
        assert X[-1, IDX["udp_ratio"]] == 1.0 and X[-1, IDX["avg_payload_entropy"]] > 6.0

    def test_stationary_host_volume_features_do_not_drift(self):
        """Volume features are windowed (schema 2): once each host's window is full they stay flat.

        They used to grow x8 on stationary traffic. The first minutes are skipped because a host's
        packet window is still filling up.
        """
        X, _, ts = attack_sim.benign_hosts(np.random.default_rng(2), n_hosts=3, seconds=3600)
        mid = (ts > np.percentile(ts, 30)) & (ts < np.percentile(ts, 50))
        late = ts > np.percentile(ts, 80)
        for feat in ("total_packets", "total_bytes", "session_duration"):
            ratio = X[late, IDX[feat]].mean() / X[mid, IDX[feat]].mean()
            assert 0.7 < ratio < 1.4, (feat, ratio)

    def test_deterministic_for_a_seed(self):
        a = attack_sim.port_scan(np.random.default_rng(5), seconds=5)[0]
        b = attack_sim.port_scan(np.random.default_rng(5), seconds=5)[0]
        assert np.array_equal(a, b)


def _samples(n=20):
    return [CollectedSample(host_vec=np.ones(18, dtype=np.float32), src_ip="10.0.0.1", dst_ip="1.1.1.1",
                            dst_port=443, protocol="TCP", ts_epoch=1000.0 + i) for i in range(n)]


class TestDumpHook:
    def test_off_by_default_writes_nothing(self, tmp_path, monkeypatch):
        monkeypatch.setattr("src.config.BASELINE_DUMP_DIR", "")
        BaselineCollector._maybe_dump(_samples(), None)
        assert not list(tmp_path.iterdir())

    def test_on_writes_one_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr("src.config.BASELINE_DUMP_DIR", str(tmp_path))
        BaselineCollector._maybe_dump(_samples(), None)
        assert len(list(tmp_path.glob("window-*.npz"))) == 1

    def test_failure_is_swallowed(self, tmp_path, monkeypatch):
        blocker = tmp_path / "file"
        blocker.write_text("x")                       # a file where a directory is expected
        monkeypatch.setattr("src.config.BASELINE_DUMP_DIR", str(blocker / "sub"))
        BaselineCollector._maybe_dump(_samples(), None)   # must not raise
