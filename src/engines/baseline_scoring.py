"""Score formulas of the baseline engine, shared with the offline evaluation bench.

Kept free of torch/sklearn so ``BaselineEngine.anomaly_score`` and
``src/unsupervised/evaluation.py`` apply exactly the same mapping. Every function accepts a
scalar (returns ``float``) or an array (returns ``ndarray``).
"""

import numpy as np

# Steepness of the sigmoid that maps the IsolationForest decision function to [0, 1].
IFOREST_SIGMOID_STEEPNESS = 5.0


def _out(a):
    return float(a) if np.ndim(a) == 0 else a


def iforest_score(raw_decision):
    """IsolationForest ``decision_function`` (negative = anomaly) mapped to [0, 1]; 0.5 at the boundary."""
    return _out(1.0 / (1.0 + np.exp(IFOREST_SIGMOID_STEEPNESS * np.asarray(raw_decision, dtype=float))))


def lstm_score(recon_error, threshold: float):
    """Reconstruction error relative to the validation threshold, clipped to 1.0."""
    return _out(np.minimum(np.asarray(recon_error, dtype=float) / max(threshold, 1e-9), 1.0))


def combine_scores(s_iforest, s_lstm):
    """Anomalous by either lens."""
    return _out(np.clip(np.maximum(s_iforest, s_lstm), 0.0, 1.0))
