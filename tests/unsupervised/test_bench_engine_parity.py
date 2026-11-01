"""The offline bench must score a row exactly like the live BaselineEngine (needs torch)."""

import numpy as np
import pytest

pytest.importorskip("torch")


class TestParityWithLiveEngine:
    """The bench must score a row exactly like BaselineEngine.anomaly_score does."""

    def test_row_scores_equal_engine_scores(self):
        from src.engines.baseline_engine import BaselineEngine
        from src.unsupervised import attack_sim
        from src.unsupervised.evaluation import row_scores
        from src.unsupervised.window_trainer import fit_models

        rng = np.random.default_rng(3)
        X, hosts, ts = attack_sim.benign_hosts(rng, n_hosts=6, seconds=900)
        fit = fit_models(X, hosts, ts, epochs=2, seq_len=20)
        assert fit is not None

        eng = BaselineEngine()
        eng._scaler, eng._iforest, eng._lstm = fit.scaler, fit.iforest, fit.model
        eng._threshold, eng._seq_len, eng._n_features = fit.threshold, fit.seq_len, fit.n_features
        eng._buffers = type(eng._buffers)(lambda: __import__("collections").deque(maxlen=fit.seq_len))
        assert eng.is_available

        bench = row_scores(fit, X, hosts)
        live = []
        for vec, h in zip(X, hosts):
            eng.update(h, vec)
            live.append(eng.anomaly_score(h, vec))
        assert np.allclose(bench["score"], np.asarray(live), atol=1e-5)
        assert bench["lstm_valid"].any() and not bench["lstm_valid"].all()
