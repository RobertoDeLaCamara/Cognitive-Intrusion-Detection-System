"""Smoke test: load the unified FT-Transformer through the engine,
score the held-out test split, and compare to the published metric.

Usage:
    python scripts/smoke_test_ft_unified.py
        [--data-dir /home/roberto/repos/ML-IDS/data/CIC-IDS2017]
        [--per-class-samples 1000]    # subsample for speed
        [--device cpu|cuda]

The published tuned-model metric is test F1 macro = 0.6197 on the full
held-out 15% test split (seed=42 stratified).
"""

import argparse
import logging
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import train_test_split

# Repo path (run from cnds root)
REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from src.engines.ft_transformer_engine import FTTransformerEngine  # noqa: E402
from src.models.ft_transformer import UNIFIED_CLASS_LABELS  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


def predict_batch(engine: FTTransformerEngine, X: np.ndarray, batch_size: int = 4096) -> np.ndarray:
    """Run the engine's model+scaler over a (N, 76) array, return predicted class indices."""
    model = engine._model
    scaler = engine._scaler
    device = engine._device
    use_amp = engine._use_amp
    if model is None or scaler is None:
        raise RuntimeError("Engine not available")

    X = np.nan_to_num(X.astype(np.float32), nan=0.0, posinf=1e9, neginf=-1e9)
    Xs = scaler.transform(X).astype(np.float32)
    preds = np.empty(len(Xs), dtype=np.int64)
    with torch.inference_mode():
        for i in range(0, len(Xs), batch_size):
            tb = torch.from_numpy(Xs[i:i + batch_size]).to(device)
            if use_amp:
                with torch.amp.autocast("cuda", dtype=torch.bfloat16):
                    logits = model(tb)
            else:
                logits = model(tb)
            preds[i:i + batch_size] = logits.argmax(-1).cpu().numpy()
    return preds


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="/home/roberto/repos/ML-IDS/data/CIC-IDS2017")
    ap.add_argument("--per-class-samples", type=int, default=0,
                    help="If >0, subsample test set to N per class (faster).")
    ap.add_argument("--device", default="auto", choices=["auto", "cpu", "cuda"])
    args = ap.parse_args()

    data_dir = Path(args.data_dir)
    if not (data_dir / "Data.csv").exists():
        logger.error("Data.csv not found at %s — cannot run smoke test.", data_dir)
        return 2

    use_gpu = (args.device == "cuda") or (args.device == "auto" and torch.cuda.is_available())
    engine = FTTransformerEngine(use_gpu=use_gpu)
    if not engine.is_available:
        logger.error("FTTransformerEngine not available — aborting.")
        return 2

    logger.info("Loading dataset from %s", data_dir)
    t0 = time.time()
    X_df = pd.read_csv(data_dir / "Data.csv")
    y_df = pd.read_csv(data_dir / "Label.csv")
    logger.info("Loaded in %.1fs.  X=%s  y=%s", time.time() - t0, X_df.shape, y_df.shape)

    if X_df.shape[1] != engine._n_features:
        logger.error("Feature count mismatch: data=%d, model=%d",
                     X_df.shape[1], engine._n_features)
        return 2

    X = X_df.values.astype(np.float32)
    y = y_df.values.ravel().astype(np.int64)

    # Reproduce the original 70/15/15 stratified split with seed=42
    X_trainval, X_test, y_trainval, y_test = train_test_split(
        X, y, test_size=0.15, stratify=y, random_state=42
    )
    logger.info("Test split: %s  classes=%s", X_test.shape, np.unique(y_test, return_counts=True))

    if args.per_class_samples > 0:
        idxs = []
        for c in np.unique(y_test):
            ci = np.where(y_test == c)[0]
            n = min(args.per_class_samples, len(ci))
            idxs.append(np.random.default_rng(42).choice(ci, size=n, replace=False))
        sel = np.concatenate(idxs)
        X_test = X_test[sel]
        y_test = y_test[sel]
        logger.info("Subsampled to %d rows (%d per class)", len(sel), args.per_class_samples)

    t0 = time.time()
    pred = predict_batch(engine, X_test, batch_size=4096)
    logger.info("Inference: %.1fs over %d rows on %s",
                time.time() - t0, len(X_test), engine._device)

    f1m = f1_score(y_test, pred, average="macro")
    f1w = f1_score(y_test, pred, average="weighted")
    print(f"\n=== Smoke test results ===")
    print(f"Test F1 macro    : {f1m:.4f}    (expected ≈ 0.6197 on full test)")
    print(f"Test F1 weighted : {f1w:.4f}")
    print()
    print(classification_report(y_test, pred,
                                labels=list(range(len(UNIFIED_CLASS_LABELS))),
                                target_names=UNIFIED_CLASS_LABELS,
                                digits=4, zero_division=0))

    # Pass-fail: F1 macro must be within 0.02 of expected on the full test split.
    if args.per_class_samples == 0 and abs(f1m - 0.6197) > 0.02:
        logger.error("F1 macro %.4f deviates >0.02 from expected 0.6197", f1m)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
