#!/usr/bin/env python3
"""Train a production-grade RF classifier on the CIC-UNSW-NB15 dataset.

Full pipeline from ML-IDS notebooks:
  1. Clip negative values to 0
  2. log1p transform for highly skewed features (|skewness| > 5)
  3. StandardScaler
  4. SMOTE on minority classes (training set only)
  5. RandomForestClassifier (class_weight='balanced')
  6. Evaluation: classification_report + binary precision/recall sweep
  7. MLflow logging + model registration (if MLFLOW_TRACKING_URI is set)

The trained sklearn Pipeline (steps 1-3 + RF) is saved to models/rf_model.joblib
so SupervisedEngine can load it directly — no external scaler needed.

Usage:
    python scripts/train_rf.py [--data-dir PATH] [--output-dir PATH]
                               [--estimators N] [--max-depth D]
                               [--test-size F] [--jobs N] [--no-smote]
                               [--mlflow-uri URI]
"""

import argparse
import logging
import os
import sys
import time
import warnings
import json
from pathlib import Path

# Unset HTTP proxy for local LAN traffic (MinIO artifact store on 192.168.1.x).
# The system-wide proxy at .89 blocks S3/MinIO connections.
for _v in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    os.environ.pop(_v, None)

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

# Minority classes to oversample with SMOTE (< 3000 samples)
SMOTE_TARGET_CLASSES = {"Analysis", "Backdoor", "Worms", "Shellcode"}
SMOTE_MIN_SAMPLES = 2000  # target per minority class after oversampling

# Skewness threshold for log1p transform (matches ML-IDS feature_engineering.ipynb)
SKEW_THRESHOLD = 5.0


# ── Custom sklearn transformers ────────────────────────────────────────────

class ClipNegativeTransformer:
    """Clip negative values to 0 before log1p transform."""
    def fit(self, X, y=None): return self
    def transform(self, X):
        return np.clip(X, 0, None)
    def fit_transform(self, X, y=None): return self.fit(X, y).transform(X)


class SelectiveLog1pTransformer:
    """Apply log1p only to columns identified as highly skewed during fit."""
    def __init__(self, threshold: float = SKEW_THRESHOLD):
        self.threshold = threshold
        self.skewed_cols_ = None

    def fit(self, X, y=None):
        df = pd.DataFrame(X)
        skewness = df.skew().abs()
        self.skewed_cols_ = skewness[skewness > self.threshold].index.tolist()
        log.info("  log1p applied to %d/%d skewed features", len(self.skewed_cols_), X.shape[1])
        return self

    def transform(self, X):
        X = np.array(X, dtype=np.float64)
        if self.skewed_cols_:
            X[:, self.skewed_cols_] = np.log1p(X[:, self.skewed_cols_])
        return X

    def fit_transform(self, X, y=None):
        return self.fit(X, y).transform(X)

    def get_params(self, deep=True):
        return {"threshold": self.threshold}

    def set_params(self, **params):
        for k, v in params.items():
            setattr(self, k, v)
        return self


# ── Data loading ───────────────────────────────────────────────────────────

def load_data(data_dir: Path):
    log.info("Loading Data.csv...")
    X = pd.read_csv(data_dir / "Data.csv", dtype=np.float32)
    log.info("Loading Label.csv...")
    y_raw = pd.read_csv(data_dir / "Label.csv")["Label"].values
    log.info("Loaded %d samples, %d features", len(X), X.shape[1])

    # Replace inf/-inf with NaN, fill with median
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    if X.isna().any().any():
        n_nan_cols = X.isna().any().sum()
        log.info("Filling NaN/inf in %d columns with median", n_nan_cols)
        X.fillna(X.median(), inplace=True)

    y = np.array([LABEL_MAP[int(lbl)] for lbl in y_raw])

    log.info("Class distribution:")
    unique, counts = np.unique(y, return_counts=True)
    for cls, cnt in sorted(zip(unique, counts), key=lambda x: -x[1]):
        log.info("  %-20s  %6d  (%4.1f%%)", cls, cnt, 100 * cnt / len(y))

    return X.values.astype(np.float32), y


# ── Preprocessing + SMOTE ─────────────────────────────────────────────────

def apply_smote(X_train, y_train):
    """Oversample minority classes to SMOTE_MIN_SAMPLES using SMOTE."""
    from imblearn.over_sampling import SMOTE

    unique, counts = np.unique(y_train, return_counts=True)
    class_counts = dict(zip(unique, counts))

    # Build sampling strategy: only oversample classes below target
    sampling_strategy = {}
    for cls in SMOTE_TARGET_CLASSES:
        if cls in class_counts and class_counts[cls] < SMOTE_MIN_SAMPLES:
            sampling_strategy[cls] = SMOTE_MIN_SAMPLES

    if not sampling_strategy:
        log.info("SMOTE: no minority classes below threshold, skipping")
        return X_train, y_train

    log.info("SMOTE: oversampling %s", sampling_strategy)
    t0 = time.time()
    smote = SMOTE(sampling_strategy=sampling_strategy, random_state=42)
    X_res, y_res = smote.fit_resample(X_train, y_train)
    log.info("SMOTE done in %.1fs: %d → %d samples", time.time() - t0,
             len(X_train), len(X_res))
    return X_res, y_res


def build_pipeline(n_estimators: int, max_depth, n_jobs: int):
    """Build sklearn Pipeline: clip → log1p → scaler → RF."""
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.ensemble import RandomForestClassifier

    return Pipeline([
        ("clip",       ClipNegativeTransformer()),
        ("log1p",      SelectiveLog1pTransformer(threshold=SKEW_THRESHOLD)),
        ("scaler",     StandardScaler()),
        ("classifier", RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            class_weight="balanced",
            min_samples_leaf=2,
            min_samples_split=5,
            max_features="sqrt",
            n_jobs=n_jobs,
            random_state=42,
            verbose=1,
        )),
    ])


# ── Evaluation ─────────────────────────────────────────────────────────────

def evaluate(pipeline, X_test, y_test):
    from sklearn.metrics import (classification_report, precision_score,
                                 recall_score, f1_score, accuracy_score)

    log.info("Evaluating on %d test samples...", len(X_test))
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)
    clf = pipeline.named_steps["classifier"]
    classes = list(clf.classes_)
    benign_idx = classes.index(BENIGN_LABEL)
    attack_score = 1.0 - y_proba[:, benign_idx]

    # Multiclass
    print("\n" + "="*70)
    print("MULTICLASS CLASSIFICATION REPORT")
    print("="*70)
    print(classification_report(y_test, y_pred, zero_division=0))

    # Binary sweep
    y_true_bin = (y_test != BENIGN_LABEL).astype(int)
    print("="*70)
    print("BINARY (Benign vs Attack) — anomaly_score = 1 - P(Benign)")
    print("="*70)
    print(f"\n{'Threshold':>10}  {'Precision':>10}  {'Recall':>8}  {'F1':>8}  {'FP rate':>10}")
    metrics_by_threshold = {}
    for t in [0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90]:
        yp = (attack_score >= t).astype(int)
        p = precision_score(y_true_bin, yp, zero_division=0)
        r = recall_score(y_true_bin, yp, zero_division=0)
        f = f1_score(y_true_bin, yp, zero_division=0)
        fp = yp[y_true_bin == 0].mean() if (y_true_bin == 0).any() else 0.0
        print(f"{t:>10.2f}  {p:>10.3f}  {r:>8.3f}  {f:>8.3f}  {fp:>10.3f}")
        metrics_by_threshold[t] = {"precision": p, "recall": r, "f1": f, "fp_rate": fp}

    benign_scores = attack_score[y_test == BENIGN_LABEL]
    attack_scores = attack_score[y_test != BENIGN_LABEL]
    print(f"\nScore distribution:")
    print(f"  Benign  → mean={benign_scores.mean():.3f}  "
          f"p90={np.percentile(benign_scores,90):.3f}  "
          f"p99={np.percentile(benign_scores,99):.3f}  "
          f"max={benign_scores.max():.3f}")
    print(f"  Attack  → mean={attack_scores.mean():.3f}  "
          f"p10={np.percentile(attack_scores,10):.3f}  "
          f"min={attack_scores.min():.3f}")

    # Top features
    importances = pd.Series(clf.feature_importances_)
    top15 = importances.nlargest(15)
    print(f"\nTop 15 feature importances:")
    try:
        from src.features.flow_extractor import FLOW_FEATURE_NAMES
        names = FLOW_FEATURE_NAMES
    except ImportError:
        names = [f"feat_{i}" for i in range(76)]
    for idx, imp in top15.items():
        print(f"  [{idx:2d}] {names[idx]:<35}  {imp:.4f}")

    acc = accuracy_score(y_test, y_pred)
    t90 = metrics_by_threshold[0.90]
    return {
        "accuracy": round(acc, 4),
        "precision_t90": round(t90["precision"], 4),
        "recall_t90": round(t90["recall"], 4),
        "f1_t90": round(t90["f1"], 4),
        "fp_rate_t90": round(t90["fp_rate"], 4),
    }


# ── MLflow logging ─────────────────────────────────────────────────────────

def log_to_mlflow(pipeline, metrics: dict, mlflow_uri: str):
    try:
        import mlflow
        import mlflow.sklearn

        mlflow.set_tracking_uri(mlflow_uri)
        mlflow.set_experiment("cnds-supervised-rf")

        with mlflow.start_run(run_name="rf-pipeline-cicunswb15"):
            # Log params
            clf = pipeline.named_steps["classifier"]
            mlflow.log_params({
                "n_estimators": clf.n_estimators,
                "max_depth": clf.max_depth,
                "class_weight": "balanced",
                "min_samples_leaf": clf.min_samples_leaf,
                "min_samples_split": clf.min_samples_split,
                "dataset": "CIC-UNSW-NB15",
                "pipeline": "clip+log1p+scaler+rf",
            })
            mlflow.log_metrics(metrics)

            model_info = mlflow.sklearn.log_model(
                pipeline,
                artifact_path="rf_pipeline",
                registered_model_name="cnds-supervised",
            )
            log.info("MLflow: model registered → %s", model_info.model_uri)
            return model_info.model_uri
    except Exception as e:
        log.warning("MLflow logging failed (non-fatal): %s", e)
        return None


# ── Save ───────────────────────────────────────────────────────────────────

def save(pipeline, metrics: dict, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "rf_model.joblib"
    joblib.dump(pipeline, path)
    log.info("Pipeline saved → %s  (%d KB)", path, path.stat().st_size // 1024)

    clf = pipeline.named_steps["classifier"]
    meta = {
        "model_type": "sklearn.Pipeline",
        "steps": ["ClipNegativeTransformer", "SelectiveLog1pTransformer",
                  "StandardScaler", "RandomForestClassifier"],
        "classes": list(clf.classes_),
        "benign_label": BENIGN_LABEL,
        "n_estimators": clf.n_estimators,
        "max_depth": clf.max_depth,
        "n_features_in": clf.n_features_in_,
        "label_map": {str(k): v for k, v in LABEL_MAP.items()},
        "metrics": metrics,
    }
    meta_path = output_dir / "rf_model_meta.json"
    meta_path.write_text(json.dumps(meta, indent=2))
    log.info("Metadata  → %s", meta_path)


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir",
                        default="/home/roberto/repos/ML-IDS/data/CIC-IDS2017",
                        type=Path)
    parser.add_argument("--output-dir", default="models", type=Path)
    parser.add_argument("--estimators", default=200, type=int)
    parser.add_argument("--max-depth", default=20,
                        type=lambda x: None if x == "None" else int(x))
    parser.add_argument("--test-size", default=0.20, type=float)
    parser.add_argument("--jobs", default=-1, type=int)
    parser.add_argument("--no-smote", action="store_true",
                        help="Skip SMOTE oversampling")
    parser.add_argument("--mlflow-uri",
                        default=os.getenv("MLFLOW_TRACKING_URI", ""),
                        help="MLflow tracking URI (empty = skip)")
    args = parser.parse_args()

    from sklearn.model_selection import train_test_split

    X, y = load_data(args.data_dir)

    log.info("Splitting: test_size=%.0f%%  stratified", args.test_size * 100)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, stratify=y, random_state=42,
    )
    log.info("Train: %d  Test: %d", len(X_train), len(X_test))

    if not args.no_smote:
        X_train, y_train = apply_smote(X_train, y_train)

    log.info("Building pipeline: clip → log1p → scaler → RF "
             "(n_estimators=%d, max_depth=%s)", args.estimators, args.max_depth)
    pipeline = build_pipeline(args.estimators, args.max_depth, args.jobs)

    t0 = time.time()
    pipeline.fit(X_train, y_train)
    log.info("Training done in %.1fs", time.time() - t0)

    metrics = evaluate(pipeline, X_test, y_test)

    print("\n" + "="*70)
    print("SUMMARY vs BASELINE (v1.0.6 — plain RF, no pipeline)")
    print("="*70)
    print(f"  Accuracy        : {metrics['accuracy']:.3f}  (baseline: 0.930)")
    print(f"  Precision @0.90 : {metrics['precision_t90']:.3f}  (baseline: 0.927)")
    print(f"  Recall    @0.90 : {metrics['recall_t90']:.3f}  (baseline: 0.989)")
    print(f"  FP rate   @0.90 : {metrics['fp_rate_t90']:.3f}  (baseline: 0.019)")

    save(pipeline, metrics, args.output_dir)

    if args.mlflow_uri:
        log.info("Logging to MLflow: %s", args.mlflow_uri)
        uri = log_to_mlflow(pipeline, metrics, args.mlflow_uri)
        if uri:
            print(f"\nMLflow model URI: {uri}")
    else:
        log.info("MLflow skipped (set --mlflow-uri or MLFLOW_TRACKING_URI to enable)")

    print("\n" + "="*70)
    print("NEXT STEP")
    print("="*70)
    print("Model is a Pipeline — SupervisedEngine handles it automatically.")
    print("To use MLflow registry in CNDS: set MLFLOW_TRACKING_URI in .env")


if __name__ == "__main__":
    main()
