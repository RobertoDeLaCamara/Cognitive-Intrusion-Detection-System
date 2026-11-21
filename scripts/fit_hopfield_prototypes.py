#!/usr/bin/env python3
"""Fit the Hopfield novelty prototypes (SHE) for the loaded FT-Transformer.

One prototype per class = L2-normalised mean CLS embedding of the class's training
flows. Writes a pickle-free .npz read by src/engines/hopfield_novelty.py:

    prototypes (n_classes x d_token), beta, threshold, fingerprint, class_labels,
    fitted_at, n_train

The split reproduces the unified-model training split (70/15/15 stratified,
seed 42), as in scikit-hopfield examples/cnds_ids_ood_validation/extract.py, and
checks the train class counts against models/unified/unified_metadata.json.
The threshold is a quantile of the validation-split scores, so roughly
(1 - quantile) of known traffic lands above it.

Usage:
    python scripts/fit_hopfield_prototypes.py --data-dir ~/repos/ML-IDS/data/CIC-IDS2017
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import time

import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.config import FT_MODEL_PATH, HOPFIELD_PROTOTYPES_PATH, MODELS_DIR  # noqa: E402
from src.engines.ft_transformer_engine import FTTransformerEngine  # noqa: E402
from src.engines.hopfield_novelty import l2_normalize, she_energy  # noqa: E402


def embed(engine: FTTransformerEngine, X: np.ndarray, batch: int = 4096) -> np.ndarray:
    import torch

    m = engine._model
    X = np.nan_to_num(X, nan=0.0, posinf=1e9, neginf=-1e9)
    out = []
    with torch.inference_mode():
        for i in range(0, len(X), batch):
            t = torch.from_numpy(engine._scaler.transform(X[i:i + batch]).astype(np.float32))
            z = torch.cat([m.cls.expand(t.size(0), -1, -1), t.unsqueeze(-1) * m.tokenizer_w + m.tokenizer_b], dim=1)
            out.append(m.norm(m.encoder(z)[:, 0]).float().numpy())
    return np.vstack(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", required=True, help="dir with Data.csv (76 features) and Label.csv (0..9)")
    ap.add_argument("--metadata", default=os.path.join(MODELS_DIR, "unified", "unified_metadata.json"))
    ap.add_argument("--out", default=HOPFIELD_PROTOTYPES_PATH)
    ap.add_argument("--beta", type=float, default=32.0, help="inverse temperature (validation plateau starts at 32)")
    ap.add_argument("--quantile", type=float, default=0.99, help="threshold quantile on validation scores")
    args = ap.parse_args()

    import pandas as pd
    from sklearn.model_selection import train_test_split

    engine = FTTransformerEngine(model_path=FT_MODEL_PATH, novelty_enabled=False)
    if not engine.is_available or engine.fingerprint is None:
        print("FT-Transformer not available (checkpoint/scaler/torch missing)", file=sys.stderr)
        return 1

    X = pd.read_csv(os.path.join(args.data_dir, "Data.csv")).values.astype(np.float32)
    y = pd.read_csv(os.path.join(args.data_dir, "Label.csv")).values.ravel().astype(np.int64)
    Xtv, _, ytv, _ = train_test_split(X, y, test_size=0.15, stratify=y, random_state=42)
    Xtr, Xva, ytr, yva = train_test_split(Xtv, ytv, test_size=0.15 / 0.85, stratify=ytv, random_state=42)

    meta = json.load(open(args.metadata))
    counts = {str(c): int((ytr == c).sum()) for c in range(len(engine._labels))}
    if meta.get("class_counts_train") and counts != meta["class_counts_train"]:
        print(f"train split does not match the model's training split:\n {counts}\n {meta['class_counts_train']}",
              file=sys.stderr)
        return 1

    t0 = time.time()
    Etr = embed(engine, Xtr)
    Eva = embed(engine, Xva)
    print(f"embedded train {Etr.shape} + val {Eva.shape} in {time.time() - t0:.0f}s")

    En = l2_normalize(Etr)
    prototypes = np.vstack([En[ytr == c].mean(axis=0) for c in range(len(engine._labels))]).astype(np.float32)
    val_scores = she_energy(Eva, l2_normalize(prototypes), args.beta)
    threshold = float(np.quantile(val_scores, args.quantile))

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    np.savez(
        args.out,
        prototypes=prototypes,
        beta=np.float64(args.beta),
        threshold=np.float64(threshold),
        fingerprint=np.str_(engine.fingerprint),
        class_labels=np.array(engine._labels, dtype=np.str_),
        fitted_at=np.str_(dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")),
        n_train=np.int64(len(ytr)),
    )
    print(f"wrote {args.out}  beta={args.beta:g}  threshold(q{args.quantile})={threshold:.4f}")
    print(f"{'class':<16}{'n_val':>8}{'mean':>10}{'>thr':>8}")
    for c, name in enumerate(engine._labels):
        s = val_scores[yva == c]
        print(f"{name:<16}{len(s):>8}{s.mean():>10.4f}{(s >= threshold).mean():>8.2%}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
