"""Unit tests for FTTransformerEngine remote NPU offload (FT_NPU_URL).

These tests run without PyTorch or on-disk checkpoints by mocking HTTP calls
to the remote NPU offload endpoint (/health and /v1/cnds/predict).
"""

from unittest.mock import MagicMock, patch

import numpy as np
import pytest
import requests

import src.config as cfg
from src.engines.ft_transformer_engine import FTTransformerEngine


def _health_response(status_code=200, body=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body if body is not None else {
        "status": "ok",
        "loaded_pipelines": {"cnds_ft_transformer": "ok"},
    }
    return resp


def _predict_response(probs):
    resp = MagicMock()
    resp.status_code = 200
    resp.raise_for_status.return_value = None
    resp.json.return_value = {"predictions": [{"probs": list(probs)}]}
    return resp


def _make_npu_engine(url="http://127.0.0.1:8090/"):
    with patch("src.engines.ft_transformer_engine.requests.get", return_value=_health_response()):
        return FTTransformerEngine(
            model_path="__nonexistent__.pt",
            scaler_path="__nonexistent__.pkl",
            npu_url=url,
        )


def test_npu_probe_activates_engine_without_torch():
    eng = _make_npu_engine()
    assert eng.is_available
    assert eng._npu_active is True
    assert eng._device == "npu"
    assert eng._npu_url == "http://127.0.0.1:8090"
    assert eng._n_features == 76
    assert eng._labels[0] == "Benign"
    assert eng.scaler_stats() is None
    assert eng.novelty_scorer is None


def test_npu_predict_anomaly_score_and_novelty():
    eng = _make_npu_engine()
    exploit_probs = [0.02, 0.01, 0.01, 0.01, 0.90, 0.01, 0.01, 0.01, 0.01, 0.01]
    benign_probs = [0.99, 0.001, 0.001, 0.001, 0.001, 0.001, 0.001, 0.001, 0.001, 0.002]

    with patch(
        "src.engines.ft_transformer_engine.requests.post",
        return_value=_predict_response(exploit_probs),
    ) as mock_post:
        label, conf = eng.predict(np.zeros(76, dtype=np.float32))
        assert label == "Exploits"
        assert conf == pytest.approx(0.90, abs=1e-6)

        score = eng.anomaly_score(np.zeros(76, dtype=np.float32))
        assert score == pytest.approx(0.98, abs=1e-6)

        label_n, conf_n, novelty = eng.predict_with_novelty(np.zeros(76, dtype=np.float32))
        assert (label_n, novelty) == ("Exploits", None)
        assert conf_n == pytest.approx(0.90, abs=1e-6)
        assert mock_post.call_args.args[0] == "http://127.0.0.1:8090/v1/cnds/predict"

    with patch(
        "src.engines.ft_transformer_engine.requests.post",
        return_value=_predict_response(benign_probs),
    ):
        label_b, conf_b = eng.predict(np.zeros(76, dtype=np.float32))
        assert label_b == "Benign"
        assert conf_b == pytest.approx(0.99, abs=1e-6)
        assert eng.anomaly_score(np.zeros(76, dtype=np.float32)) == pytest.approx(0.01, abs=1e-6)


def test_npu_sanitizes_nan_and_inf_before_post():
    eng = _make_npu_engine()
    vec = np.zeros(76, dtype=np.float32)
    vec[0] = np.nan
    vec[1] = np.inf
    vec[2] = -np.inf

    probs = [0.95] + [0.005] * 9
    with patch(
        "src.engines.ft_transformer_engine.requests.post",
        return_value=_predict_response(probs),
    ) as mock_post:
        out = eng.predict(vec)
        assert out is not None
        sent = mock_post.call_args.kwargs["json"]["flows"]
        assert len(sent) == 76
        assert np.all(np.isfinite(sent))
        assert sent[0] == 0.0
        assert sent[1] == 1e9
        assert sent[2] == -1e9


def test_npu_rejects_wrong_feature_count():
    eng = _make_npu_engine()
    with pytest.raises(ValueError, match="expects 76 features"):
        eng._forward(np.zeros(75, dtype=np.float32))


def test_npu_probe_failure_falls_back_cleanly():
    with patch(
        "src.engines.ft_transformer_engine.requests.get",
        side_effect=requests.ConnectionError("refused"),
    ):
        eng = FTTransformerEngine(
            model_path="__nonexistent__.pt",
            scaler_path="__nonexistent__.pkl",
            npu_url="http://127.0.0.1:8090",
        )
    assert eng._npu_active is False
    assert eng.is_available is False


def test_npu_probe_rejects_missing_cnds_pipeline():
    resp = _health_response(
        status_code=200,
        body={"status": "ok", "loaded_pipelines": {"embeddings": "ok"}},
    )
    with patch("src.engines.ft_transformer_engine.requests.get", return_value=resp):
        eng = FTTransformerEngine(
            model_path="__nonexistent__.pt",
            scaler_path="__nonexistent__.pkl",
            npu_url="http://127.0.0.1:8090",
        )
    assert eng._npu_active is False
    assert eng.is_available is False


def test_npu_forward_http_error_returns_none_and_zero():
    eng = _make_npu_engine()
    with patch(
        "src.engines.ft_transformer_engine.requests.post",
        side_effect=requests.HTTPError("500 Server Error"),
    ):
        assert eng.predict(np.zeros(76, dtype=np.float32)) is None
        assert eng.anomaly_score(np.zeros(76, dtype=np.float32)) == 0.0
        assert eng.predict_with_novelty(np.zeros(76, dtype=np.float32)) is None


def test_npu_non_finite_probs_handled_safely():
    eng = _make_npu_engine()
    bad_probs = [float("nan")] * 10
    with patch(
        "src.engines.ft_transformer_engine.requests.post",
        return_value=_predict_response(bad_probs),
    ):
        assert eng.predict(np.zeros(76, dtype=np.float32)) is None


def test_config_validates_ft_npu_url_scheme(monkeypatch):
    monkeypatch.setattr(cfg, "FT_NPU_URL", "192.168.1.48:8090")
    with pytest.raises(cfg.ConfigurationError, match="FT_NPU_URL"):
        cfg._validate_config()

    monkeypatch.setattr(cfg, "FT_NPU_URL", "http://127.0.0.1:8090")
    cfg._validate_config()
