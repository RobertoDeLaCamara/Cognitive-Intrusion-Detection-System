"""Offline evaluation of the baseline models (IsolationForest + LSTM autoencoder).

Fits with the same ``fit_models`` the detector uses, scores rows with the engine's own score
formulas (``src/engines/baseline_scoring.py``) and reports:

- false positives on a chronological benign hold-out (what the detector would flag),
- recall / AUC per attack scenario against that hold-out,
- how saturated the score is (share of benign rows at ~1.0),
- features that drift over time (cumulative counters make "the same traffic" look new).

Metric helpers are numpy only; ``row_scores`` and ``evaluate`` need torch.
"""

from typing import Dict, Optional, Sequence, Tuple

import numpy as np

from ..engines.baseline_scoring import combine_scores, iforest_score, lstm_score
from .window_trainer import FitResult, _to_sequences, fit_models

SCORE_THRESHOLDS = (0.5, 0.65, 0.8, 0.99)
SATURATION_AT = 0.999

# (X, hosts, ts) with rows in time order.
Rows = Tuple[np.ndarray, Sequence[str], np.ndarray]


# ── metrics (numpy only) ──────────────────────────────────────────────────────

def auc(pos: np.ndarray, neg: np.ndarray) -> Optional[float]:
    """P(score of a random positive > score of a random negative); ties count half. None if a class is empty."""
    pos, neg = np.asarray(pos, dtype=float), np.asarray(neg, dtype=float)
    if len(pos) == 0 or len(neg) == 0:
        return None
    allv = np.concatenate([pos, neg])
    order = allv.argsort(kind="mergesort")
    ranks = np.empty(len(allv), dtype=float)
    sorted_v = allv[order]
    # average ranks over ties
    i = 0
    while i < len(sorted_v):
        j = i
        while j + 1 < len(sorted_v) and sorted_v[j + 1] == sorted_v[i]:
            j += 1
        ranks[order[i:j + 1]] = (i + j) / 2.0 + 1.0
        i = j + 1
    r_pos = ranks[: len(pos)].sum()
    return float((r_pos - len(pos) * (len(pos) + 1) / 2.0) / (len(pos) * len(neg)))


def rate_at(scores: np.ndarray, thresholds: Sequence[float] = SCORE_THRESHOLDS) -> Dict[str, float]:
    """Share of rows with score >= each threshold (FPR on benign rows, recall on attack rows)."""
    s = np.asarray(scores, dtype=float)
    if len(s) == 0:
        return {f"{t:g}": float("nan") for t in thresholds}
    return {f"{t:g}": float((s >= t).mean()) for t in thresholds}


def quantiles(scores: np.ndarray) -> Dict[str, float]:
    s = np.asarray(scores, dtype=float)
    if len(s) == 0:
        return {}
    return {f"p{q}": float(np.percentile(s, q)) for q in (50, 90, 99)}


def feature_drift(
    X: np.ndarray, ts: np.ndarray, names: Sequence[str], flag_ratio: float = 2.0
) -> Dict[str, dict]:
    """Mean of each feature in the newest 20 % of rows over the mean in the oldest 20 %.

    A stationary feature stays near 1. Cumulative counters (total packets, session duration)
    keep growing, so a model fit on an older window sees newer normal traffic as unusual.
    """
    order = np.argsort(ts, kind="stable")
    n = len(order)
    k = max(n // 5, 1)
    first, last = X[order[:k]], X[order[-k:]]
    out = {}
    for i, name in enumerate(names):
        a, b = float(first[:, i].mean()), float(last[:, i].mean())
        ratio = (b / a) if abs(a) > 1e-9 else (float("inf") if abs(b) > 1e-9 else 1.0)
        out[name] = {
            "first": a,
            "last": b,
            "ratio": ratio,
            "drifting": bool(ratio >= flag_ratio or ratio <= 1.0 / flag_ratio),
        }
    return out


# ── scoring (torch) ───────────────────────────────────────────────────────────

def row_scores(fit: FitResult, X: np.ndarray, hosts: Sequence[str], batch: int = 4096) -> Dict[str, np.ndarray]:
    """Per-row scores exactly as ``BaselineEngine.anomaly_score`` computes them.

    ``X`` must be in time order. The LSTM branch scores the last ``seq_len`` vectors of the
    row's own host, ending at that row; rows before a host's buffer is full get 0.0 (the engine
    does the same) and ``lstm_valid`` False.
    """
    import torch

    n = len(X)
    Xs = fit.scaler.transform(X).astype(np.float32)
    s_if = iforest_score(fit.iforest.decision_function(Xs))
    s_lstm = np.zeros(n, dtype=float)
    valid = np.zeros(n, dtype=bool)

    rows_by_host: Dict[str, list] = {}
    for i, h in enumerate(hosts):
        rows_by_host.setdefault(h, []).append(i)

    device = next(fit.model.parameters()).device
    fit.model.eval()
    with torch.no_grad():
        for idx_list in rows_by_host.values():
            if len(idx_list) < fit.seq_len:
                continue
            idx = np.asarray(idx_list)
            seqs = _to_sequences(Xs[idx], fit.seq_len)
            errs = np.empty(len(seqs), dtype=float)
            for a in range(0, len(seqs), batch):
                x = torch.from_numpy(seqs[a:a + batch]).to(device)
                errs[a:a + batch] = ((fit.model(x) - x) ** 2).mean(dim=(1, 2)).cpu().numpy()
            target = idx[fit.seq_len - 1:]
            s_lstm[target] = lstm_score(errs, fit.threshold)
            valid[target] = True

    return {
        "iforest": s_if,
        "lstm": s_lstm,
        "score": combine_scores(s_if, s_lstm),
        "lstm_valid": valid,
    }


# ── end to end ────────────────────────────────────────────────────────────────

def _summarise(sc: Dict[str, np.ndarray]) -> dict:
    return {
        "n": int(len(sc["score"])),
        "quantiles": quantiles(sc["score"]),
        "rate_at": rate_at(sc["score"]),
        "saturated": float((sc["score"] >= SATURATION_AT).mean()) if len(sc["score"]) else float("nan"),
    }


def evaluate(
    benign: Rows,
    attacks: Dict[str, Rows],
    *,
    feature_names: Optional[Sequence[str]] = None,
    **fit_kwargs,
) -> dict:
    """Fit on the older part of ``benign``, score its newest part and every attack scenario."""
    X, hosts, ts = benign
    fit = fit_models(X, hosts, ts, **fit_kwargs)
    if fit is None:
        return {"error": "window too small to form sequences on both sides of the split"}

    # Same chronological cut as fit_models: the newest rows are the benign hold-out.
    vf = fit_kwargs.get("val_fraction", 0.20)
    order = np.argsort(ts, kind="stable")[int(len(ts) * (1.0 - vf)):]
    X_val, h_val, ts_val = X[order], [hosts[i] for i in order], ts[order]

    benign_sc = row_scores(fit, X_val, h_val)
    report = {
        "fit": {
            "threshold": fit.threshold,
            "n_train_rows": fit.n_train_rows,
            "n_val_rows": fit.n_val_rows,
            "n_train_seq": fit.n_train_seq,
            "n_val_seq": fit.n_val_seq,
        },
        "benign_holdout": {
            **_summarise(benign_sc),
            "lstm_valid_share": float(benign_sc["lstm_valid"].mean()),
            "by_branch_rate_at_0.65": {
                "iforest": float((benign_sc["iforest"] >= 0.65).mean()),
                "lstm": float((benign_sc["lstm"] >= 0.65).mean()),
            },
            "span_hours": float((ts_val.max() - ts_val.min()) / 3600.0) if len(ts_val) else 0.0,
        },
        "attacks": {},
    }
    for name, (Xa, ha, tsa) in attacks.items():
        sc = row_scores(fit, Xa, ha)
        v = sc["lstm_valid"]
        report["attacks"][name] = {
            **_summarise(sc),
            "auc_vs_benign": auc(sc["score"], benign_sc["score"]),
            "auc_iforest": auc(sc["iforest"], benign_sc["iforest"]),
            "auc_lstm_valid_rows": auc(sc["lstm"][v], benign_sc["lstm"][benign_sc["lstm_valid"]]),
        }
    if feature_names is not None:
        report["feature_drift"] = {
            k: d for k, d in feature_drift(X, ts, feature_names).items() if d["drifting"]
        }
    return report
