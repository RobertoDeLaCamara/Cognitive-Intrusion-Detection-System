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
    """Reconstruction error relative to the validation threshold, mapped to [0, 1).

    With ``r = error / threshold`` the score is ``r / (1 + r)``: 0.5 exactly at the threshold (the
    same boundary convention as :func:`iforest_score`), 0.67 at twice the threshold, 0.91 at ten
    times. It is monotone and never saturates, so an error 100x above the threshold still ranks
    above one that only just crossed it. The previous ``min(r, 1)`` gave 1.0 to everything at or
    above the threshold.
    """
    r = np.maximum(np.asarray(recon_error, dtype=float), 0.0) / max(threshold, 1e-9)
    return _out(r / (1.0 + r))


def combine_scores(s_iforest, s_lstm):
    """Anomalous by either lens."""
    return _out(np.clip(np.maximum(s_iforest, s_lstm), 0.0, 1.0))
