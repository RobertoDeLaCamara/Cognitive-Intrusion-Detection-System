#!/usr/bin/env python3
"""Evaluation bench for the baseline models (IsolationForest + LSTM autoencoder).

Fits with the detector's own training routine on a chronological split of benign host vectors,
then reports false positives on the newest benign rows, recall / AUC per simulated attack,
score saturation and features that drift over time.

Benign data, either:
  --dump-dir DIR   windows written by the detector when BASELINE_DUMP_DIR is set (real traffic)
  --simulate       stationary simulated LAN hosts (smoke test of the bench itself)

Attacks are simulated with the real HostExtractor (src/unsupervised/attack_sim.py).

Usage:
    python scripts/eval_baseline.py --dump-dir /data/cnds-windows --output report.json
    python scripts/eval_baseline.py --simulate
"""

import argparse
import json
import logging
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.features.host_extractor import HOST_FEATURE_NAMES  # noqa: E402
from src.unsupervised import attack_sim  # noqa: E402
from src.unsupervised.dump import load_windows  # noqa: E402
from src.unsupervised.evaluation import evaluate  # noqa: E402


def _load_benign(args):
    if args.simulate:
        rng = np.random.default_rng(args.seed)
        return attack_sim.benign_hosts(rng, n_hosts=args.sim_hosts, seconds=args.sim_seconds)
    windows = load_windows(args.dump_dir)
    if not windows:
        sys.exit(f"no window-*.npz files in {args.dump_dir}")
    X = np.vstack([w[0] for w in windows])
    hosts = [h for w in windows for h in w[1]]
    ts = np.concatenate([w[2] for w in windows])
    keep = np.isfinite(X).all(axis=1)
    order = np.argsort(ts[keep], kind="stable")
    X, ts = X[keep][order], ts[keep][order]
    hosts = [h for h, k in zip(hosts, keep) if k]
    hosts = [hosts[i] for i in order]
    return X, hosts, ts


def _print(report: dict) -> None:
    if "error" in report:
        print("ERROR:", report["error"])
        return
    f, b = report["fit"], report["benign_holdout"]
    print(f"\nfit: threshold={f['threshold']:.4g}  train rows/seq={f['n_train_rows']}/{f['n_train_seq']}"
          f"  val rows/seq={f['n_val_rows']}/{f['n_val_seq']}")
    print(f"\nBENIGN HOLD-OUT ({b['n']} rows, {b['span_hours']:.2f} h, LSTM valid on {b['lstm_valid_share']:.0%})")
    print("  score quantiles:", {k: round(v, 3) for k, v in b["quantiles"].items()})
    print("  false-positive rate at score>=", {k: f"{v:.2%}" for k, v in b["rate_at"].items()})
    print(f"  saturated (>=0.999): {b['saturated']:.2%}   by branch @0.65: {b['by_branch_rate_at_0.65']}")
    print("\nATTACKS (recall at score>=t ; AUC vs benign hold-out)")
    ts_ = list(next(iter(report["attacks"].values()))["rate_at"]) if report["attacks"] else []
    print(f"  {'scenario':<16}{'n':>6}  " + "".join(f"{'>='+t:>8}" for t in ts_) + f"{'AUC':>8}{'AUC_if':>8}{'AUC_lstm':>9}")
    fmt = lambda v: "   n/a" if v is None else f"{v:8.3f}"
    for name, a in report["attacks"].items():
        print(f"  {name:<16}{a['n']:>6}  " + "".join(f"{a['rate_at'][t]:>8.0%}" for t in ts_)
              + fmt(a["auc_vs_benign"]) + fmt(a["auc_iforest"]) + fmt(a["auc_lstm_valid_rows"]).rjust(9))
    d = report.get("feature_drift", {})
    print(f"\nDRIFTING FEATURES (newest 20% / oldest 20% of the benign data): {len(d)}")
    for k, v in d.items():
        print(f"  {k:<22} x{v['ratio']:.2f}   ({v['first']:.4g} -> {v['last']:.4g})")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--dump-dir")
    src.add_argument("--simulate", action="store_true")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--sim-hosts", type=int, default=12)
    ap.add_argument("--sim-seconds", type=int, default=3600)
    ap.add_argument("--epochs", type=int, default=20)
    ap.add_argument("--seq-len", type=int, default=20)
    ap.add_argument("--threshold-percentile", type=float, default=99.0)
    ap.add_argument("--output", help="write the full report as JSON")
    args = ap.parse_args()
    logging.basicConfig(level=logging.WARNING)

    benign = _load_benign(args)
    print(f"benign rows: {len(benign[0])}  hosts: {len(set(benign[1]))}")
    report = evaluate(
        benign,
        attack_sim.all_attacks(seed=args.seed, t0=float(benign[2].max()) + 60.0),
        feature_names=HOST_FEATURE_NAMES,
        epochs=args.epochs,
        seq_len=args.seq_len,
        threshold_percentile=args.threshold_percentile,
    )
    _print(report)
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2, default=float))
        print("\nreport written to", args.output)
    return 0 if "error" not in report else 1


if __name__ == "__main__":
    raise SystemExit(main())
