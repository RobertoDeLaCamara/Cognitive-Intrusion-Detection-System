#!/usr/bin/env python3
"""Train a Random Forest classifier on the CIC-UNSW-NB15 dataset.

Replaces the demo rf_model.joblib with a model trained on real network
intrusion data (447k flows, 76 CICFlowMeter features, 10 classes).

Usage:
    python scripts/train_rf.py [--data-dir PATH] [--output-dir PATH]
                               [--estimators N] [--max-depth D]
                               [--test-size F] [--jobs N]

Defaults:
    --data-dir   /home/roberto/repos/ML-IDS/data/CIC-IDS2017
    --output-dir models/
    --estimators 100
    --max-depth  None (grow full trees)
    --test-size  0.20
    --jobs       -1   (all cores)
"""

import argparse
import logging
import os
import sys
import time
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import joblib

warnings.filterwarnings("ignore", category=UserWarning)

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger(__name__)

sys.path.insert(0, str(Path(__file__).parent.parent))

# ── Label mapping ──────────────────────────────────────────────────────────
LABEL_MAP = {
    0: "Benign",
    1: "Analysis",
    2: "Backdoor",
    3: "DoS",
    4: "Exploits",
    5: "Fuzzers",
    6: "Generic",
    7: "Reconnaissance",
    8: "Shellcode",
    9: "Worms",
}
BENIGN_LABEL = "Benign"

# Feature column order in Data.csv matches FLOW_FEATURE_NAMES in CNDS
# (both follow CICFlowMeter 76-feature layout)


def load_data(data_dir: Path) -> tuple[np.ndarray, np.ndarray]:
    log.info("Loading Data.csv (%s)...", data_dir / "Data.csv")
    X = pd.read_csv(data_dir / "Data.csv", dtype=np.float32)

    log.info("Loading Label.csv...")
    y_raw = pd.read_csv(data_dir / "Label.csv")["Label"].values

    log.info("Loaded %d samples, %d features", len(X), X.shape[1])

    # ── Clean up ──────────────────────────────────────────────────────────
    # Replace inf/-inf with NaN then fill with column median
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    nan_cols = X.isna().any()
    if nan_cols.any():
        log.info("Filling NaN/inf in %d columns with column median",
                 nan_cols.sum())
        X.fillna(X.median(), inplace=True)

    # Clip extreme values to 99.9th percentile per column
    p999 = X.quantile(0.999)
    X = X.clip(upper=p999, axis=1)

    # Map integer labels → string names
    y = np.array([LABEL_MAP[int(lbl)] for lbl in y_raw])

    # ── Class distribution ─────────────────────────────────────────────────
    unique, counts = np.unique(y, return_counts=True)
    log.info("Class distribution:")
    for cls, cnt in sorted(zip(unique, counts), key=lambda x: -x[1]):
        pct = 100 * cnt / len(y)
        log.info("  %-20s  %6d  (%4.1f%%)", cls, cnt, pct)

    return X.values.astype(np.float32), y


def train(X_train, y_train, n_estimators: int, max_depth, n_jobs: int):
    from sklearn.ensemble import RandomForestClassifier

    log.info("Training RandomForest: n_estimators=%d  max_depth=%s  "
             "class_weight=balanced  n_jobs=%d",
             n_estimators, max_depth, n_jobs)
    t0 = time.time()
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight="balanced",   # handles heavy Benign imbalance
        min_samples_leaf=5,        # avoids overfitting on rare classes
        max_features="sqrt",
        n_jobs=n_jobs,
        random_state=42,
        verbose=1,
    )
    model.fit(X_train, y_train)
    log.info("Training done in %.1fs", time.time() - t0)
    return model


def evaluate(model, X_test, y_test, threshold: float = 0.5):
    from sklearn.metrics import classification_report, precision_score, recall_score, f1_score

    log.info("Evaluating on %d test samples...", len(X_test))
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)

    # Multiclass report
    print("\n" + "="*70)
    print("MULTICLASS CLASSIFICATION REPORT")
    print("="*70)
    print(classification_report(y_test, y_pred, zero_division=0))

    # Binary: Benign vs Attack
    benign_idx = list(model.classes_).index(BENIGN_LABEL)
    benign_proba = y_proba[:, benign_idx]
    attack_score = 1.0 - benign_proba  # anomaly score used by SupervisedEngine

    y_true_bin = (y_test != BENIGN_LABEL).astype(int)

    print("="*70)
    print("BINARY (Benign vs Attack) — anomaly_score = 1 - P(Benign)")
    print("="*70)
    print(f"\n{'Threshold':>10}  {'Precision':>10}  {'Recall':>8}  {'F1':>8}  {'FP rate':>10}")
    for t in [0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90]:
        yp = (attack_score >= t).astype(int)
        p = precision_score(y_true_bin, yp, zero_division=0)
        r = recall_score(y_true_bin, yp, zero_division=0)
        f = f1_score(y_true_bin, yp, zero_division=0)
        fp_rate = yp[y_true_bin == 0].mean() if (y_true_bin == 0).any() else 0.0
        print(f"{t:>10.2f}  {p:>10.3f}  {r:>8.3f}  {f:>8.3f}  {fp_rate:>10.3f}")

    # Score overlap
    benign_scores = attack_score[y_test == BENIGN_LABEL]
    attack_scores = attack_score[y_test != BENIGN_LABEL]
    print(f"\nScore distribution:")
    print(f"  Benign traffic  →  mean={benign_scores.mean():.3f}  "
          f"p90={np.percentile(benign_scores, 90):.3f}  "
          f"p99={np.percentile(benign_scores, 99):.3f}  "
          f"max={benign_scores.max():.3f}")
    print(f"  Attack traffic  →  mean={attack_scores.mean():.3f}  "
          f"p10={np.percentile(attack_scores, 10):.3f}  "
          f"min={attack_scores.min():.3f}")

    # Feature importances (top 15)
    importances = pd.Series(model.feature_importances_)
    top15 = importances.nlargest(15)
    print(f"\nTop 15 feature importances:")
    # Load feature names from CNDS
    try:
        from src.features.flow_extractor import FLOW_FEATURE_NAMES
        names = FLOW_FEATURE_NAMES
    except ImportError:
        names = [f"feat_{i}" for i in range(76)]
    for idx, imp in top15.items():
        print(f"  [{idx:2d}] {names[idx]:<35}  {imp:.4f}")


def save_model(model, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "rf_model.joblib"
    joblib.dump(model, path)
    size_kb = path.stat().st_size // 1024
    log.info("Model saved → %s  (%d KB)", path, size_kb)

    # Save label map alongside the model for reference
    import json
    meta = {
        "classes": list(model.classes_),
        "benign_label": BENIGN_LABEL,
        "n_estimators": model.n_estimators,
        "n_features_in": model.n_features_in_,
        "label_map": {str(k): v for k, v in LABEL_MAP.items()},
    }
    meta_path = output_dir / "rf_model_meta.json"
    meta_path.write_text(json.dumps(meta, indent=2))
    log.info("Metadata  → %s", meta_path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir",
                        default="/home/roberto/repos/ML-IDS/data/CIC-IDS2017",
                        type=Path)
    parser.add_argument("--output-dir", default="models", type=Path)
    parser.add_argument("--estimators", default=100, type=int)
    parser.add_argument("--max-depth", default=None, type=lambda x: None if x == "None" else int(x))
    parser.add_argument("--test-size", default=0.20, type=float)
    parser.add_argument("--jobs", default=-1, type=int)
    args = parser.parse_args()

    from sklearn.model_selection import train_test_split

    X, y = load_data(args.data_dir)

    log.info("Splitting: test_size=%.0f%%  stratified", args.test_size * 100)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, stratify=y, random_state=42
    )
    log.info("Train: %d  Test: %d", len(X_train), len(X_test))

    model = train(X_train, y_train,
                  n_estimators=args.estimators,
                  max_depth=args.max_depth,
                  n_jobs=args.jobs)

    evaluate(model, X_test, y_test)
    save_model(model, args.output_dir)

    print("\n" + "="*70)
    print("NEXT STEP")
    print("="*70)
    print("Update supervised.py:  BENIGN_LABEL = 'Benign'")
    print("Then re-run:  python scripts/eval_engines.py")


if __name__ == "__main__":
    main()
