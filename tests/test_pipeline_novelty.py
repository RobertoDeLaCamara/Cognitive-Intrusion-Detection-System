"""Hopfield novelty in the capture pipeline: shadow mode only.

The score is logged (on alerts and as [NOVELTY-SHADOW] lines) but must never change
the ensemble result.
"""

import logging
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from src.engines.hopfield_novelty import HopfieldNoveltyScorer
from src.ensemble.scorer import EngineScores, EnsembleResult, EnsembleScorer
from src.features.flow_extractor import FlowRecord


class _Scorer:
    """Stand-in for HopfieldNoveltyScorer with a fixed threshold."""

    threshold = -0.6
    is_novel = HopfieldNoveltyScorer.is_novel


class _FTEngine:
    """Minimal engine exposing the FT-Transformer novelty API (a real class, not a mock)."""

    is_available = True

    def __init__(self, label="Benign", conf=0.97, novelty: "float | None" = -0.4, scorer=True):
        self._out = (label, conf, novelty)
        self.novelty_scorer = _Scorer() if scorer else None
        self.predict = MagicMock(side_effect=AssertionError("predict_with_novelty should be used"))

    def predict_with_novelty(self, flow_features, payload_features=None):
        return self._out


def _flow(src_ip="10.0.0.5"):
    return FlowRecord(key=(src_ip, "1.1.1.1", 40000, 443, 6))


def _result(is_anomaly, score):
    return EnsembleResult(score=score, is_anomaly=is_anomaly, engine_scores=EngineScores(),
                          active_engines=["supervised"], calibrated_score=score)


@pytest.fixture(autouse=True)
def _clean_dedup():
    import src.pipeline as pipeline
    pipeline._dedup_cache.clear()
    yield
    pipeline._dedup_cache.clear()


def _run(engine, ens_result, flow=None):
    import src.pipeline as pipeline
    captured = {}
    ens = MagicMock()

    def _score(scores):
        captured["scores"] = scores
        return ens_result
    ens.score.side_effect = _score
    rules = MagicMock()
    rules.evaluate.return_value = (0.0, [])
    off = MagicMock(is_available=False)
    with patch.object(pipeline, "TRUSTED_OUTBOUND", {}), \
         patch.object(pipeline, "supervised", engine), \
         patch.object(pipeline, "iforest", off), patch.object(pipeline, "lstm", off), \
         patch.object(pipeline, "baseline_engine", off), \
         patch.object(pipeline, "rules", rules), patch.object(pipeline, "ensemble", ens), \
         patch.object(pipeline, "_persist_alert") as persist:
        pipeline.on_flow_complete(flow or _flow(), np.zeros(76, dtype=np.float32), None, [])
    return captured["scores"], persist


def _shadow_lines(caplog):
    return [r for r in caplog.records if r.getMessage().startswith("[NOVELTY-SHADOW]")]


def test_novelty_does_not_change_the_ensemble_score():
    plain = EngineScores(supervised=0.8, rules=0.2, attack_type="DoS")
    with_novelty = EngineScores(supervised=0.8, rules=0.2, attack_type="DoS", novelty=5.0)
    a, b = EnsembleScorer().score(plain), EnsembleScorer().score(with_novelty)
    assert (a.score, a.is_anomaly, a.active_engines) == (b.score, b.is_anomaly, b.active_engines)
    assert "novelty" not in b.active_engines


def test_supervised_scores_come_from_predict_with_novelty():
    scores, _ = _run(_FTEngine(label="DoS", conf=0.9, novelty=-0.7), _result(False, 0.2))
    assert scores.attack_type == "DoS"
    assert scores.supervised == pytest.approx(0.9)
    assert scores.novelty == pytest.approx(-0.7)


def test_shadow_line_when_novel_and_no_alert(caplog):
    caplog.set_level(logging.WARNING, logger="src.pipeline")
    _, persist = _run(_FTEngine(novelty=-0.4), _result(False, 0.2))
    persist.assert_not_called()
    lines = _shadow_lines(caplog)
    assert len(lines) == 1
    assert "novelty=-0.4000" in lines[0].getMessage()
    assert lines[0].novelty_score == pytest.approx(-0.4)


def test_shadow_line_is_deduped_per_source(caplog):
    caplog.set_level(logging.WARNING, logger="src.pipeline")
    for _ in range(3):
        _run(_FTEngine(novelty=-0.4), _result(False, 0.2))
    _run(_FTEngine(novelty=-0.4), _result(False, 0.2), flow=_flow("10.0.0.6"))
    assert len(_shadow_lines(caplog)) == 2


@pytest.mark.parametrize("engine", [
    _FTEngine(novelty=-0.9),               # below threshold: familiar traffic
    _FTEngine(novelty=None),               # scorer off for this flow
    _FTEngine(novelty=-0.4, scorer=False), # engine without a scorer
])
def test_no_shadow_line_otherwise(caplog, engine):
    caplog.set_level(logging.WARNING, logger="src.pipeline")
    _run(engine, _result(False, 0.2))
    assert _shadow_lines(caplog) == []


def test_alert_log_carries_novelty_and_no_shadow_line(caplog):
    caplog.set_level(logging.WARNING, logger="src.pipeline")
    _, persist = _run(_FTEngine(label="DoS", conf=0.95, novelty=-0.4), _result(True, 0.9))
    persist.assert_called_once()
    alerts = [r for r in caplog.records if r.getMessage().startswith("[ALERT]")]
    assert len(alerts) == 1
    assert "novelty=-0.4000" in alerts[0].getMessage()
    assert alerts[0].novelty_score == pytest.approx(-0.4)
    assert _shadow_lines(caplog) == []


def test_engine_without_novelty_api_still_uses_predict():
    class _RF:
        is_available = True

        def predict(self, flow_features, payload_features=None):
            return "DoS", 0.8

    scores, _ = _run(_RF(), _result(False, 0.2))
    assert scores.attack_type == "DoS"
    assert scores.novelty is None
