"""Tests for the ensemble scorer."""

import pytest
from src.ensemble.scorer import EnsembleScorer, EngineScores, EnsembleResult, _calibrate


@pytest.fixture
def scorer():
    return EnsembleScorer()


def test_all_engines_zero(scorer):
    scores = EngineScores(supervised=0.0, isolation_forest=0.0, lstm=0.0, rules=0.0)
    result = scorer.score(scores)
    assert result.score == pytest.approx(0.0)
    assert not result.is_anomaly
    assert len(result.active_engines) == 4


def test_all_engines_one(scorer):
    scores = EngineScores(supervised=1.0, isolation_forest=1.0, lstm=1.0, rules=1.0)
    result = scorer.score(scores)
    assert result.score == pytest.approx(1.0)
    assert result.is_anomaly


def test_no_engines_available(scorer):
    scores = EngineScores()
    result = scorer.score(scores)
    assert result.score == 0.0
    assert not result.is_anomaly
    assert result.active_engines == []


def test_weight_redistribution(scorer):
    """When some engines are None, their weight goes to active ones."""
    scores = EngineScores(rules=1.0)
    result = scorer.score(scores)
    assert result.score == pytest.approx(1.0)
    assert result.is_anomaly
    assert result.active_engines == ["rules"]


def test_partial_engines(scorer):
    scores = EngineScores(supervised=0.9, isolation_forest=0.8)
    result = scorer.score(scores)
    assert 0 < result.score < 1.0
    assert result.is_anomaly


def test_score_clamped(scorer):
    scores = EngineScores(supervised=2.0, isolation_forest=3.0, rules=5.0)
    result = scorer.score(scores)
    assert result.score <= 1.0


def test_below_threshold_not_anomaly(scorer):
    scores = EngineScores(supervised=0.1, isolation_forest=0.1, lstm=0.1, rules=0.0)
    result = scorer.score(scores)
    assert not result.is_anomaly


def test_critical_rule_forces_anomaly_even_if_ml_engines_disagree(scorer):
    """Regression: a confirmed sql_injection signature match must always
    alert at critical severity, even when the statistical engines see
    nothing unusual (score=0.0) and would otherwise dilute rules' weight
    below ENSEMBLE_THRESHOLD."""
    scores = EngineScores(
        supervised=0.0, isolation_forest=0.0, lstm=0.0, rules=1.0,
        triggered_rules=["payload:sql_injection"],
    )
    result = scorer.score(scores)
    assert result.is_anomaly
    assert result.score == pytest.approx(1.0)


def test_non_critical_rule_does_not_force_anomaly(scorer):
    """A rule that isn't in CRITICAL_RULES (e.g. a generic large_payload
    heuristic) still goes through the normal weighted blend."""
    scores = EngineScores(
        supervised=0.0, isolation_forest=0.0, lstm=0.0, rules=1.0,
        triggered_rules=["large_payload"],
    )
    result = scorer.score(scores)
    assert not result.is_anomaly


def test_calibrated_score_present(scorer):
    scores = EngineScores(supervised=0.8, rules=0.5)
    result = scorer.score(scores)
    assert hasattr(result, "calibrated_score")
    assert 0.0 <= result.calibrated_score <= 1.0


def test_calibrate_identity():
    """Temperature=1.0 should return the same score."""
    assert _calibrate(0.7, 1.0) == pytest.approx(0.7)


def test_calibrate_softens():
    """Temperature>1 should push scores toward 0.5."""
    soft = _calibrate(0.9, 3.0)
    assert 0.5 < soft < 0.9


def test_calibrate_sharpens():
    """Temperature<1 should push scores away from 0.5."""
    sharp = _calibrate(0.7, 0.3)
    assert sharp > 0.7


def test_calibrate_edge_cases():
    assert _calibrate(0.0, 2.0) == 0.0
    assert _calibrate(1.0, 2.0) == 1.0


def test_attack_type_weight_override(scorer):
    """Per-attack-type weights should be used when configured."""
    # This tests the _get_weights method — actual override depends on config
    weights = scorer._get_weights(None)
    assert "supervised" in weights
    weights_benign = scorer._get_weights("BENIGN")
    assert weights_benign == weights


def test_calibrated_score_drives_anomaly_decision(scorer):
    """is_anomaly should be based on calibrated_score, not raw score."""
    scores = EngineScores(supervised=0.6, isolation_forest=0.5, lstm=0.5, rules=0.5)
    result = scorer.score(scores)
    # With temperature=1.0, calibrated == raw, so just verify consistency
    assert result.is_anomaly == (result.calibrated_score >= 0.55)
