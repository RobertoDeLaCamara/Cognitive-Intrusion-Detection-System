"""Training sequences must match inference: seq_len consecutive vectors of ONE host.

The baseline engine keeps one ``seq_len`` buffer per source IP. The trainer used to build
sequences over a randomly shuffled mix of all hosts, so the LSTM never saw the structure
it is scored on. These tests need numpy only (no torch).
"""

import numpy as np
import pytest

from src.unsupervised.window_trainer import _temporal_split, _to_host_sequences


def _rows(n_hosts: int, per_host: int, n_features: int = 3):
    """Rows in arrival order, hosts interleaved. Feature 0 encodes host id, feature 1 the host's
    own running index, so a sequence can be checked for host purity and continuity."""
    X, hosts = [], []
    for k in range(per_host):
        for h in range(n_hosts):
            row = np.zeros(n_features, dtype=np.float32)
            row[0], row[1] = h, k
            X.append(row)
            hosts.append(f"10.0.0.{h}")
    return np.stack(X), hosts


class TestToHostSequences:
    def test_every_sequence_belongs_to_one_host(self):
        X, hosts = _rows(n_hosts=4, per_host=30)
        seqs = _to_host_sequences(X, hosts, seq_len=20)
        assert seqs.shape == (4 * (30 - 20 + 1), 20, 3)
        for seq in seqs:
            assert len(set(seq[:, 0])) == 1

    def test_sequences_are_consecutive_in_host_time(self):
        X, hosts = _rows(n_hosts=3, per_host=25)
        for seq in _to_host_sequences(X, hosts, seq_len=20):
            assert np.all(np.diff(seq[:, 1]) == 1)

    def test_host_with_too_few_rows_contributes_nothing(self):
        X, hosts = _rows(n_hosts=2, per_host=30)
        extra = np.zeros((5, 3), dtype=np.float32)
        extra[:, 0] = 99
        X = np.vstack([X, extra])
        hosts = hosts + ["10.9.9.9"] * 5
        seqs = _to_host_sequences(X, hosts, seq_len=20)
        assert 99 not in set(seqs[:, :, 0].ravel())
        assert seqs.shape[0] == 2 * (30 - 20 + 1)

    def test_no_host_long_enough_gives_empty(self):
        X, hosts = _rows(n_hosts=5, per_host=10)
        seqs = _to_host_sequences(X, hosts, seq_len=20)
        assert seqs.shape == (0, 20, 3)

    def test_length_mismatch_rejected(self):
        X, hosts = _rows(n_hosts=2, per_host=25)
        with pytest.raises(ValueError):
            _to_host_sequences(X, hosts[:-1], seq_len=20)

    def test_result_is_contiguous_float32(self):
        X, hosts = _rows(n_hosts=2, per_host=25)
        seqs = _to_host_sequences(X, hosts, seq_len=20)
        assert seqs.dtype == np.float32 and seqs.flags["C_CONTIGUOUS"]


class TestTemporalSplit:
    def test_validation_is_strictly_newer_than_training(self):
        rng = np.random.default_rng(0)
        n = 1000
        ts = rng.permutation(n).astype(np.float64)  # arrival order differs from time order
        X = np.arange(n, dtype=np.float32).reshape(-1, 1)
        hosts = [f"h{i % 7}" for i in range(n)]
        X_tr, X_va, h_tr, h_va = _temporal_split(X, hosts, ts, 0.2)
        assert len(X_tr) == 800 and len(X_va) == 200
        t_of = {int(x): t for x, t in zip(X[:, 0], ts)}
        assert max(t_of[int(x)] for x in X_tr[:, 0]) < min(t_of[int(x)] for x in X_va[:, 0])
        assert len(h_tr) == 800 and len(h_va) == 200

    def test_hosts_stay_aligned_with_rows(self):
        n = 100
        ts = np.arange(n, dtype=np.float64)[::-1]
        X = np.arange(n, dtype=np.float32).reshape(-1, 1)
        hosts = [f"h{i}" for i in range(n)]
        X_tr, X_va, h_tr, h_va = _temporal_split(X, hosts, ts, 0.25)
        for x, h in list(zip(X_tr[:, 0], h_tr)) + list(zip(X_va[:, 0], h_va)):
            assert h == f"h{int(x)}"

    def test_equal_timestamps_keep_arrival_order(self):
        X = np.arange(10, dtype=np.float32).reshape(-1, 1)
        hosts = ["a"] * 10
        X_tr, X_va, _, _ = _temporal_split(X, hosts, np.zeros(10), 0.2)
        assert list(X_tr[:, 0]) == list(range(8)) and list(X_va[:, 0]) == [8, 9]

    def test_split_does_not_leak_a_row_to_both_sides(self):
        X = np.arange(500, dtype=np.float32).reshape(-1, 1)
        hosts = ["a"] * 500
        X_tr, X_va, _, _ = _temporal_split(X, hosts, np.arange(500, dtype=np.float64), 0.2)
        assert not set(X_tr[:, 0]) & set(X_va[:, 0])
