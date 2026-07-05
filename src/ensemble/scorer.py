"""Multi-engine ensemble confidence scorer.

Combines scores from four engines into a single [0, 1] confidence value.
Engines without data have their weight redistributed to active engines.
Supports per-attack-type weight overrides and confidence calibration (Phase 4).
"""

import logging
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..config import (
    WEIGHT_SUPERVISED, WEIGHT_IFOREST, WEIGHT_LSTM, WEIGHT_RULES, WEIGHT_BASELINE,
    ENSEMBLE_THRESHOLD, ATTACK_TYPE_WEIGHTS, CALIBRATION_TEMPERATURE, CRITICAL_RULES,
)

logger = logging.getLogger(__name__)


@dataclass
class EngineScores:
    supervised: Optional[float] = None   # None = engine unavailable / no data
    isolation_forest: Optional[float] = None
    lstm: Optional[float] = None
    rules: Optional[float] = None

    # Live-trained environment baseline (IsolationForest + LSTM from BaselineEngine)
    baseline: Optional[float] = None

    # Named attack classification from supervised engine
    attack_type: Optional[str] = None
    supervised_confidence: Optional[float] = None

    # Rules that fired
    triggered_rules: List[str] = field(default_factory=list)

    # Threat intelligence (external feeds)
    ti_malicious_ip: bool = False       # src or dst IP matches threat intel
    ti_malicious_ja3: bool = False      # JA3 hash matches threat intel


@dataclass
class EnsembleResult:
    score: float                          # Combined [0, 1]
    is_anomaly: bool
    engine_scores: EngineScores
    active_engines: List[str]
    calibrated_score: float = 0.0         # After temperature scaling


def _calibrate(score: float, temperature: float) -> float:
    """Apply Platt-style temperature scaling to a [0,1] score."""
    if temperature == 1.0 or score <= 0.0 or score >= 1.0:
        return score
    # Convert to logit, scale, convert back
    logit = math.log(score / (1.0 - score))
    scaled = logit / max(temperature, 1e-9)
    return 1.0 / (1.0 + math.exp(-scaled))


class EnsembleScorer:
    """Weighted ensemble with dynamic weight redistribution."""

    _BASE_WEIGHTS: Dict[str, float] = {
        "supervised":      WEIGHT_SUPERVISED,
        "isolation_forest": WEIGHT_IFOREST,
        "lstm":            WEIGHT_LSTM,
        "rules":           WEIGHT_RULES,
        "baseline":        WEIGHT_BASELINE,
    }

    def _get_weights(self, attack_type: Optional[str]) -> Dict[str, float]:
        """Return base weights, overridden by attack-type-specific weights if configured."""
        if attack_type and attack_type != "BENIGN" and attack_type in ATTACK_TYPE_WEIGHTS:
            overrides = ATTACK_TYPE_WEIGHTS[attack_type]
            weights = dict(self._BASE_WEIGHTS)
            weights.update(overrides)
            return weights
        return dict(self._BASE_WEIGHTS)

    def score(self, scores: EngineScores) -> EnsembleResult:
        available: Dict[str, float] = {}

        if scores.supervised is not None:
            available["supervised"] = scores.supervised
        if scores.isolation_forest is not None:
            available["isolation_forest"] = scores.isolation_forest
        if scores.lstm is not None:
            available["lstm"] = scores.lstm
        if scores.rules is not None:
            available["rules"] = scores.rules
        if scores.baseline is not None:
            available["baseline"] = scores.baseline

        if not available:
            return EnsembleResult(
                score=0.0, is_anomaly=False, engine_scores=scores,
                active_engines=[], calibrated_score=0.0,
            )

        # Use attack-type-specific weights if available
        base_weights = self._get_weights(scores.attack_type)

        # Redistribute weights of missing engines
        total_base = sum(base_weights.get(e, 0.0) for e in available)
        if total_base == 0:
            return EnsembleResult(
                score=0.0, is_anomaly=False, engine_scores=scores,
                active_engines=list(available.keys()), calibrated_score=0.0,
            )
        weights = {e: base_weights.get(e, 0.0) / total_base for e in available}

        combined = sum(weights[e] * available[e] for e in available)
        combined = float(max(0.0, min(1.0, combined)))

        # ── Threat intelligence boost ──────────────────────────────────────────
        # If threat intel flags IP or JA3 as malicious, boost score,
        # but don't exceed 1.0
        if scores.ti_malicious_ip or scores.ti_malicious_ja3:
            combined = min(1.0, combined + 0.30)
            if scores.ti_malicious_ip:
                scores.triggered_rules.append("threat_intel_malicious_ip")
            if scores.ti_malicious_ja3:
                scores.triggered_rules.append("threat_intel_malicious_ja3")

        # ── Critical signature override ────────────────────────────────────────
        # A handful of rules are unambiguous matches for a known attack pattern
        # rather than a statistical hint (SQLi, Log4Shell, ...). Those must
        # always alert at critical severity — waiting for the weighted blend
        # to agree would mean a 100%-confidence signature hit can still be
        # diluted below threshold by engines that were never designed to
        # recognise it in the first place.
        critical_hit = any(r in CRITICAL_RULES for r in scores.triggered_rules)
        if critical_hit:
            combined = 1.0

        calibrated = _calibrate(combined, CALIBRATION_TEMPERATURE)

        return EnsembleResult(
            score=combined,
            is_anomaly=critical_hit or calibrated >= ENSEMBLE_THRESHOLD,
            engine_scores=scores,
            active_engines=list(available.keys()),
            calibrated_score=calibrated,
        )


def severity_from_score(score: float, attack_type: str | None = None) -> str:
    """Unified severity classification used by both capture pipeline and API."""
    if attack_type and attack_type not in ("BENIGN", None):
        critical_types = {"DDoS", "DoS", "Infiltration", "Web Attack"}
        if any(t in attack_type for t in critical_types) and score >= 0.70:
            return "critical"
    if score >= 0.85:
        return "critical"
    if score >= 0.70:
        return "high"
    if score >= 0.55:
        return "medium"
    return "low"
