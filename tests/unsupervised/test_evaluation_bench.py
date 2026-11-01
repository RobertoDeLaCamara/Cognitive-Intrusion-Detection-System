"""Evaluation bench: metric helpers (numpy), window dump, and parity with the live engine."""

import numpy as np
import pytest

from src.engines.baseline_scoring import combine_scores, iforest_score, lstm_score
from src.unsupervised.dump import dump_window, load_windows
from src.unsupervised.evaluation import auc, feature_drift, quantiles, rate_at


class TestScoringFormulas:
    def test_iforest_boundary_is_half_and_monotone(self):
        assert iforest_score(0.0) == pytest.approx(0.5)
        assert iforest_score(-0.2) > iforest_score(0.0) > iforest_score(0.2)

    def test_lstm_score_clips_at_one_from_the_threshold_up(self):
        assert lstm_score(0.5, 1.0) == pytest.approx(0.5)
        assert lstm_score(1.0, 1.0) == 1.0
        assert lstm_score(50.0, 1.0) == 1.0   # no gradation above the threshold

    def test_array_and_scalar_agree(self):
        raw = np.array([-0.3, 0.0, 0.4])
        assert np.allclose(iforest_score(raw), [iforest_score(r) for r in raw])
        e = np.array([0.1, 1.0, 9.0])
        assert np.allclose(lstm_score(e, 2.0), [lstm_score(v, 2.0) for v in e])
        assert isinstance(iforest_score(0.1), float) and isinstance(combine_scores(0.2, 0.9), float)

    def test_combine_is_the_max(self):
        assert combine_scores(0.3, 0.8) == 0.8


class TestAuc:
    def test_perfect_and_inverted(self):
        assert auc(np.array([0.9, 0.8]), np.array([0.1, 0.2])) == 1.0
        assert auc(np.array([0.1]), np.array([0.9, 0.8])) == 0.0

    def test_ties_count_half(self):
        assert auc(np.array([0.5, 0.5]), np.array([0.5, 0.5])) == pytest.approx(0.5)

    def test_matches_pairwise_definition(self):
        rng = np.random.default_rng(0)
        p, n = rng.normal(1, 1, 60), rng.normal(0, 1, 80)
        brute = np.mean([(a > b) + 0.5 * (a == b) for a in p for b in n])
        assert auc(p, n) == pytest.approx(brute)

    def test_empty_class_is_none(self):
        assert auc(np.array([]), np.array([0.1])) is None


class TestRates:
    def test_rate_at_is_share_at_or_above(self):
        r = rate_at(np.array([0.1, 0.6, 0.7, 1.0]), (0.5, 0.65, 0.99))
        assert r == {"0.5": 0.75, "0.65": 0.5, "0.99": 0.25}

    def test_empty_inputs(self):
        assert quantiles(np.array([])) == {}
        assert np.isnan(rate_at(np.array([]), (0.5,))["0.5"])


class TestFeatureDrift:
    def test_cumulative_counter_is_flagged_and_stationary_is_not(self):
        n = 500
        ts = np.arange(n, dtype=float)
        X = np.column_stack([np.arange(1, n + 1, dtype=float), np.full(n, 5.0)])
        d = feature_drift(X, ts, ["total_packets", "avg_packet_size"])
        assert d["total_packets"]["drifting"] and d["total_packets"]["ratio"] > 2
        assert not d["avg_packet_size"]["drifting"]

    def test_uses_time_not_row_order(self):
        n = 200
        ts = np.arange(n, dtype=float)[::-1]          # rows stored newest first
        X = np.arange(1, n + 1, dtype=float)[::-1].reshape(-1, 1)
        assert feature_drift(X, ts, ["c"])["c"]["ratio"] > 2


class TestDump:
    def _samples(self, n):
        from src.unsupervised.collector import CollectedSample
        return [CollectedSample(host_vec=np.full(18, i, dtype=np.float32), src_ip=f"10.0.0.{i % 3}",
                                dst_ip="1.1.1.1", dst_port=443, protocol="TCP", ts_epoch=1000.0 + i)
                for i in range(n)]

    def test_roundtrip(self, tmp_path):
        dump_window(str(tmp_path), self._samples(50), 1000.0)
        (X, hosts, ts), = load_windows(str(tmp_path))
        assert X.shape == (50, 18) and X[7, 0] == 7 and hosts[4] == "10.0.0.1" and ts[-1] == 1049.0

    def test_keeps_only_newest_files(self, tmp_path):
        import os
        for k in range(4):
            p = dump_window(str(tmp_path), self._samples(10), 1000.0 + k, keep=2)
            os.utime(p, (1000 + k, 1000 + k))
        assert len(list(tmp_path.glob("window-*.npz"))) <= 3  # newest written last, older pruned

    def test_no_tmp_file_left_behind(self, tmp_path):
        dump_window(str(tmp_path), self._samples(10), 1000.0)
        assert not list(tmp_path.glob("*.tmp"))
