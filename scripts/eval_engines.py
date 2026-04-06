#!/usr/bin/env python3
"""Diagnostic evaluation of CNDS detection engines using synthetic CIC-IDS2017-like traffic.

Generates labelled synthetic flow vectors approximating real attack patterns and runs
them through the supervised (RF) and unsupervised (IF) engines, printing:
  - classification_report per engine
  - confidence score distribution (benign vs attack)
  - false-positive / false-negative breakdown by attack class
  - threshold sensitivity for the RF engine

Usage:
    python scripts/eval_engines.py [--samples N] [--threshold T]
"""

import sys
import os
import argparse
import warnings
import numpy as np

# Suppress sklearn version mismatch warnings for cleaner output
warnings.filterwarnings("ignore", category=UserWarning)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.engines.supervised import SupervisedEngine, BENIGN_LABEL
from src.engines.isolation_forest import IsolationForestEngine
from src.features.flow_extractor import FLOW_FEATURE_NAMES

# ── CIC-IDS2017 feature statistics (μ, σ) per attack class ────────────────
# Approximated from published CIC-IDS2017 dataset statistics.
# Indices match FLOW_FEATURE_NAMES (76 features).

RNG = np.random.RandomState(2024)

# Feature indices for key discriminating features
IDX = {name: i for i, name in enumerate(FLOW_FEATURE_NAMES)}

ATTACK_LABELS = [
    "BENIGN", "DoS Hulk", "PortScan", "DDoS", "DoS GoldenEye",
    "FTP-Patator", "SSH-Patator", "DoS slowloris", "DoS Slowhttptest",
    "Bot", "Web Attack – Brute Force", "Web Attack – XSS",
    "Infiltration", "Web Attack – Sql Injection", "Heartbleed",
]

HOST_FEATURE_DIM = 18


def _base_flow(n: int) -> np.ndarray:
    """Random gaussian baseline for all 76 features, clipped to non-negative."""
    X = np.abs(RNG.randn(n, 76).astype(np.float32))
    return X


def _perturb(X: np.ndarray, idx: int, mean: float, std: float) -> np.ndarray:
    X[:, idx] = np.abs(RNG.normal(mean, std, len(X))).astype(np.float32)
    return X


def generate_samples(n_per_class: int = 200) -> tuple:
    """Generate (X, y) with n_per_class samples per attack type.

    Each class gets characteristic feature perturbations mimicking the
    CIC-IDS2017 traffic profile for that attack.
    """
    X_list, y_list = [], []

    # BENIGN — typical browsing: moderate flow duration, balanced packets
    X = _base_flow(n_per_class)
    _perturb(X, IDX["flow_duration"],    5e6,  2e6)
    _perturb(X, IDX["tot_fwd_pkts"],     25,   15)
    _perturb(X, IDX["tot_bwd_pkts"],     20,   12)
    _perturb(X, IDX["flow_byts_s"],      5000, 3000)
    _perturb(X, IDX["syn_flag_cnt"],     1,    0.5)
    X_list.append(X); y_list.extend(["BENIGN"] * n_per_class)

    # DoS Hulk — very high packet rate, large forward payloads
    X = _base_flow(n_per_class)
    _perturb(X, IDX["flow_pkts_s"],      6000, 2000)
    _perturb(X, IDX["flow_byts_s"],      800000, 200000)
    _perturb(X, IDX["tot_fwd_pkts"],     5000, 1000)
    _perturb(X, IDX["psh_flag_cnt"],     4000, 500)
    _perturb(X, IDX["flow_duration"],    500,  200)
    X_list.append(X); y_list.extend(["DoS Hulk"] * n_per_class)

    # PortScan — many short flows, high SYN, low data
    X = _base_flow(n_per_class)
    _perturb(X, IDX["flow_duration"],    50,   30)
    _perturb(X, IDX["tot_fwd_pkts"],     1,    0.5)
    _perturb(X, IDX["tot_bwd_pkts"],     0,    0.3)
    _perturb(X, IDX["syn_flag_cnt"],     1,    0.1)
    _perturb(X, IDX["rst_flag_cnt"],     1,    0.2)
    _perturb(X, IDX["flow_byts_s"],      200,  100)
    X_list.append(X); y_list.extend(["PortScan"] * n_per_class)

    # DDoS — high packet rate from multiple sources, short flows
    X = _base_flow(n_per_class)
    _perturb(X, IDX["flow_pkts_s"],      10000, 3000)
    _perturb(X, IDX["flow_byts_s"],      500000, 150000)
    _perturb(X, IDX["tot_fwd_pkts"],     1000, 300)
    _perturb(X, IDX["flow_duration"],    1000, 400)
    _perturb(X, IDX["flow_iat_mean"],    100,  50)
    X_list.append(X); y_list.extend(["DDoS"] * n_per_class)

    # DoS GoldenEye — HTTP flood, moderate rate, large headers
    X = _base_flow(n_per_class)
    _perturb(X, IDX["flow_pkts_s"],      300,  100)
    _perturb(X, IDX["fwd_header_len"],   1200, 300)
    _perturb(X, IDX["psh_flag_cnt"],     200,  80)
    _perturb(X, IDX["flow_duration"],    3e6,  1e6)
    X_list.append(X); y_list.extend(["DoS GoldenEye"] * n_per_class)

    # FTP-Patator — many short auth attempts, low bytes
    X = _base_flow(n_per_class)
    _perturb(X, IDX["tot_fwd_pkts"],     8,    3)
    _perturb(X, IDX["tot_bwd_pkts"],     8,    3)
    _perturb(X, IDX["flow_byts_s"],      800,  200)
    _perturb(X, IDX["flow_duration"],    5e5,  2e5)
    _perturb(X, IDX["fin_flag_cnt"],     1,    0.3)
    X_list.append(X); y_list.extend(["FTP-Patator"] * n_per_class)

    # SSH-Patator — similar to FTP-Patator with slightly larger payloads
    X = _base_flow(n_per_class)
    _perturb(X, IDX["tot_fwd_pkts"],     12,   4)
    _perturb(X, IDX["tot_bwd_pkts"],     12,   4)
    _perturb(X, IDX["flow_byts_s"],      1200, 400)
    _perturb(X, IDX["flow_duration"],    6e5,  2e5)
    _perturb(X, IDX["fin_flag_cnt"],     1,    0.3)
    X_list.append(X); y_list.extend(["SSH-Patator"] * n_per_class)

    # DoS slowloris — very long flow, few packets, slow IAT
    X = _base_flow(n_per_class)
    _perturb(X, IDX["flow_duration"],    1e8,  2e7)
    _perturb(X, IDX["tot_fwd_pkts"],     20,   5)
    _perturb(X, IDX["flow_iat_mean"],    5e6,  1e6)
    _perturb(X, IDX["flow_byts_s"],      10,   5)
    X_list.append(X); y_list.extend(["DoS slowloris"] * n_per_class)

    # DoS Slowhttptest — similar to slowloris
    X = _base_flow(n_per_class)
    _perturb(X, IDX["flow_duration"],    9e7,  2e7)
    _perturb(X, IDX["tot_fwd_pkts"],     18,   5)
    _perturb(X, IDX["flow_iat_mean"],    4e6,  1e6)
    _perturb(X, IDX["flow_byts_s"],      12,   5)
    X_list.append(X); y_list.extend(["DoS Slowhttptest"] * n_per_class)

    # Bot — periodic beaconing: regular IAT, moderate traffic
    X = _base_flow(n_per_class)
    _perturb(X, IDX["flow_iat_std"],     50,   20)
    _perturb(X, IDX["flow_iat_mean"],    3e5,  5e4)
    _perturb(X, IDX["tot_fwd_pkts"],     6,    2)
    _perturb(X, IDX["flow_byts_s"],      400,  100)
    X_list.append(X); y_list.extend(["Bot"] * n_per_class)

    # Web Attack – Brute Force — many short HTTP requests
    X = _base_flow(n_per_class)
    _perturb(X, IDX["tot_fwd_pkts"],     4,    1)
    _perturb(X, IDX["tot_bwd_pkts"],     3,    1)
    _perturb(X, IDX["flow_byts_s"],      2000, 500)
    _perturb(X, IDX["flow_duration"],    2e5,  1e5)
    X_list.append(X); y_list.extend(["Web Attack – Brute Force"] * n_per_class)

    # Web Attack – XSS — small payloads, HTTP, similar to brute force
    X = _base_flow(n_per_class)
    _perturb(X, IDX["tot_fwd_pkts"],     4,    1)
    _perturb(X, IDX["tot_bwd_pkts"],     4,    1)
    _perturb(X, IDX["flow_byts_s"],      1800, 500)
    _perturb(X, IDX["flow_duration"],    2e5,  1e5)
    X_list.append(X); y_list.extend(["Web Attack – XSS"] * n_per_class)

    # Infiltration — low-and-slow, resembles normal traffic
    X = _base_flow(n_per_class)
    _perturb(X, IDX["flow_duration"],    6e6,  2e6)
    _perturb(X, IDX["tot_fwd_pkts"],     30,   10)
    _perturb(X, IDX["flow_byts_s"],      3000, 1000)
    X_list.append(X); y_list.extend(["Infiltration"] * n_per_class)

    # Web Attack – Sql Injection
    X = _base_flow(n_per_class)
    _perturb(X, IDX["tot_fwd_pkts"],     5,    1)
    _perturb(X, IDX["tot_bwd_pkts"],     5,    1)
    _perturb(X, IDX["fwd_pkt_len_mean"], 600,  150)
    _perturb(X, IDX["flow_byts_s"],      2500, 600)
    X_list.append(X); y_list.extend(["Web Attack – Sql Injection"] * n_per_class)

    # Heartbleed — very specific: few pkts, high bwd payload
    X = _base_flow(n_per_class)
    _perturb(X, IDX["tot_fwd_pkts"],     3,    1)
    _perturb(X, IDX["bwd_pkt_len_max"],  16000, 1000)
    _perturb(X, IDX["bwd_pkt_len_mean"], 8000,  2000)
    _perturb(X, IDX["flow_byts_s"],      15000, 3000)
    X_list.append(X); y_list.extend(["Heartbleed"] * n_per_class)

    X_all = np.vstack(X_list)
    y_all = np.array(y_list)
    return X_all, y_all


def eval_supervised(engine: SupervisedEngine, X: np.ndarray, y: np.ndarray, threshold: float):
    from sklearn.metrics import classification_report, confusion_matrix

    print("\n" + "="*70)
    print("SUPERVISED ENGINE (Random Forest)")
    print("="*70)
    print(f"  n_estimators : {engine._model.n_estimators}")
    print(f"  n_features   : {engine._model.n_features_in_}")
    print(f"  threshold    : {threshold:.2f}  (anomaly_score >= threshold → attack)")

    y_score = np.array([engine.anomaly_score(x) for x in X])
    y_pred_label = []
    for x in X:
        res = engine.predict(x)
        y_pred_label.append(res[0] if res else "BENIGN")
    y_pred_label = np.array(y_pred_label)

    # Binary classification: BENIGN vs attack
    y_true_bin = (y != "BENIGN").astype(int)
    y_pred_bin = (y_score >= threshold).astype(int)

    print("\n── Binary (BENIGN vs ATTACK) ──")
    from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
    print(f"  Accuracy  : {accuracy_score(y_true_bin, y_pred_bin):.3f}")
    print(f"  Precision : {precision_score(y_true_bin, y_pred_bin, zero_division=0):.3f}  (fewer FP = higher is better for your goal)")
    print(f"  Recall    : {recall_score(y_true_bin, y_pred_bin, zero_division=0):.3f}  (fewer FN = higher is better)")
    print(f"  F1        : {f1_score(y_true_bin, y_pred_bin, zero_division=0):.3f}")

    # Confidence score distribution
    benign_scores = y_score[y == "BENIGN"]
    attack_scores = y_score[y != "BENIGN"]
    print(f"\n── Score distribution ──")
    print(f"  Benign traffic  →  mean={benign_scores.mean():.3f}  std={benign_scores.std():.3f}  "
          f"max={benign_scores.max():.3f}  p90={np.percentile(benign_scores,90):.3f}")
    print(f"  Attack traffic  →  mean={attack_scores.mean():.3f}  std={attack_scores.std():.3f}  "
          f"min={attack_scores.min():.3f}  p10={np.percentile(attack_scores,10):.3f}")

    overlap = (benign_scores > np.percentile(attack_scores, 10)).sum()
    print(f"\n  ⚠  Benign samples scoring above attack p10: {overlap}/{len(benign_scores)} "
          f"({100*overlap/len(benign_scores):.1f}%)  ← false-positive risk zone")

    # Per-class multiclass report
    print("\n── Multiclass report (RF native predict) ──")
    print(classification_report(y, y_pred_label, zero_division=0))

    # Threshold sweep
    print("── Precision / Recall trade-off at different thresholds ──")
    print(f"  {'Threshold':>10}  {'Precision':>10}  {'Recall':>8}  {'F1':>8}  {'FP rate':>10}")
    for t in [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]:
        yp = (y_score >= t).astype(int)
        p = precision_score(y_true_bin, yp, zero_division=0)
        r = recall_score(y_true_bin, yp, zero_division=0)
        f = f1_score(y_true_bin, yp, zero_division=0)
        fp_rate = yp[y_true_bin == 0].mean()
        print(f"  {t:>10.2f}  {p:>10.3f}  {r:>8.3f}  {f:>8.3f}  {fp_rate:>10.3f}")


def eval_iforest(engine: IsolationForestEngine, X: np.ndarray, y: np.ndarray, n_host: int = 18):
    from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score

    print("\n" + "="*70)
    print("ISOLATION FOREST ENGINE (unsupervised — host features only)")
    print("="*70)
    print(f"  NOTE: IF uses {n_host}-dim host features; we project the first {n_host} "
          "flow features as a proxy.\n"
          "  Results are indicative only — real host features differ in semantics.")

    # Use first n_host flow features as proxy for host features
    X_host = X[:, :n_host]
    y_score = np.array([engine.anomaly_score(x) for x in X_host])
    y_true_bin = (y != "BENIGN").astype(int)

    benign_scores = y_score[y == "BENIGN"]
    attack_scores = y_score[y != "BENIGN"]
    print(f"\n── Score distribution ──")
    print(f"  Benign  →  mean={benign_scores.mean():.3f}  std={benign_scores.std():.3f}  "
          f"max={benign_scores.max():.3f}")
    print(f"  Attack  →  mean={attack_scores.mean():.3f}  std={attack_scores.std():.3f}  "
          f"min={attack_scores.min():.3f}")

    print("\n── Threshold sweep ──")
    print(f"  {'Threshold':>10}  {'Precision':>10}  {'Recall':>8}  {'F1':>8}  {'FP rate':>10}")
    for t in [0.3, 0.4, 0.5, 0.6, 0.7, 0.8]:
        yp = (y_score >= t).astype(int)
        p = precision_score(y_true_bin, yp, zero_division=0)
        r = recall_score(y_true_bin, yp, zero_division=0)
        f = f1_score(y_true_bin, yp, zero_division=0)
        fp_rate = yp[y_true_bin == 0].mean() if (y_true_bin == 0).any() else 0.0
        print(f"  {t:>10.2f}  {p:>10.3f}  {r:>8.3f}  {f:>8.3f}  {fp_rate:>10.3f}")


def main():
    parser = argparse.ArgumentParser(description="Evaluate CNDS detection engines")
    parser.add_argument("--samples", type=int, default=200,
                        help="Samples per attack class (default: 200)")
    parser.add_argument("--threshold", type=float, default=0.5,
                        help="RF anomaly score threshold (default: 0.5)")
    args = parser.parse_args()

    print(f"Generating {args.samples} samples × {len(ATTACK_LABELS)} classes "
          f"= {args.samples * len(ATTACK_LABELS)} total samples...")
    X, y = generate_samples(args.samples)

    unique, counts = np.unique(y, return_counts=True)
    print(f"Classes: {dict(zip(unique, counts))}")

    # Load engines
    print("\nLoading engines...")
    rf = SupervisedEngine()
    iforest = IsolationForestEngine()

    if not rf.is_available:
        print("ERROR: RF model not loaded. Run: python scripts/generate_demo_models.py")
        sys.exit(1)

    eval_supervised(rf, X, y, threshold=args.threshold)

    if iforest.is_available:
        eval_iforest(iforest, X, y)
    else:
        print("\nIF engine not available — skipping.")

    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print("Key questions to answer from this output:")
    print("  1. Precision @ your chosen threshold — is the FP rate acceptable?")
    print("  2. Score overlap: how much do benign scores bleed into attack territory?")
    print("  3. Per-class recall: which attack types are being missed?")
    print("  4. Is this a threshold problem (fixable cheaply) or a model problem?")


if __name__ == "__main__":
    main()
