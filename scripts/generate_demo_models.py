#!/usr/bin/env python3
"""Generate lightweight demo models for CNDS out-of-the-box experience.

Creates minimal but functional ML models so all 4 detection engines
activate on `docker compose up`. Models are intentionally small and
trained on synthetic data — they will produce realistic-looking scores
but are NOT suitable for production use.

Usage:
    python scripts/generate_demo_models.py [--output-dir models]
"""

import argparse
import json
import logging
import sys
from pathlib import Path

import numpy as np
import joblib
logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)

# CIC-IDS2017 attack labels used by the supervised engine
ATTACK_LABELS = [
    "BENIGN", "DoS Hulk", "PortScan", "DDoS", "DoS GoldenEye",
    "FTP-Patator", "SSH-Patator", "DoS slowloris", "DoS Slowhttptest",
    "Bot", "Web Attack – Brute Force", "Web Attack – XSS",
    "Infiltration", "Web Attack – Sql Injection", "Heartbleed",
]

N_FLOW_FEATURES = 76   # CICFlowMeter features
N_HOST_FEATURES = 18    # HostExtractor features


def generate_rf_model(out_dir: Path) -> None:
    """Random Forest classifier (76 features, 15 classes)."""
    from sklearn.ensemble import RandomForestClassifier

    rng = np.random.RandomState(42)
    n_samples = 500

    X = rng.randn(n_samples, N_FLOW_FEATURES).astype(np.float32)
    y = rng.choice(ATTACK_LABELS, size=n_samples, p=[0.6] + [0.4 / 14] * 14)

    model = RandomForestClassifier(
        n_estimators=10, max_depth=5, random_state=42, n_jobs=1,
    )
    model.fit(X, y)

    path = out_dir / "rf_model.joblib"
    joblib.dump(model, path)
    log.info("  RF model          → %s  (%d KB)", path.name, path.stat().st_size // 1024)


def generate_if_model(out_dir: Path) -> None:
    """Isolation Forest + StandardScaler (18 features)."""
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    rng = np.random.RandomState(42)
    X = rng.randn(300, N_HOST_FEATURES).astype(np.float32)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=50, contamination=0.05, random_state=42,
    )
    model.fit(X_scaled)

    model_path = out_dir / "isolation_forest.joblib"
    scaler_path = out_dir / "if_scaler.joblib"
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    log.info("  IF model          → %s  (%d KB)", model_path.name, model_path.stat().st_size // 1024)
    log.info("  IF scaler         → %s  (%d KB)", scaler_path.name, scaler_path.stat().st_size // 1024)


def generate_lstm_model(out_dir: Path) -> None:
    """LSTM Autoencoder (18 features, seq_len=20)."""
    import torch
    import torch.nn as nn
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from src.engines.lstm_model import LSTMAutoencoder

    model = LSTMAutoencoder()
    # Quick training on random data so weights are not completely random
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.MSELoss()
    dummy = torch.randn(32, 20, 18)
    model.train()
    for _ in range(50):
        out = model(dummy)
        loss = criterion(out, dummy)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
    model.eval()

    path = out_dir / "lstm_autoencoder.pt"
    torch.save(model.state_dict(), path)
    log.info("  LSTM model        → %s  (%d KB)", path.name, path.stat().st_size // 1024)

    # Update config with reconstruction threshold from training
    config_path = out_dir / "lstm_config.json"
    with torch.no_grad():
        recon = model(dummy)
        threshold = float(torch.mean((dummy - recon) ** 2).item()) * 3.0

    config = {
        "sequence_length": 20,
        "hidden_dim": 64,
        "latent_dim": 32,
        "num_layers": 2,
        "dropout": 0.2,
        "n_features": 18,
        "reconstruction_threshold": threshold,
    }
    config_path.write_text(json.dumps(config, indent=2) + "\n")
    log.info("  LSTM config       → %s", config_path.name)


def main():
    parser = argparse.ArgumentParser(description="Generate CNDS demo models")
    parser.add_argument("--output-dir", default="models", help="Output directory")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    log.info("Generating demo models in %s/", out_dir)
    generate_rf_model(out_dir)
    generate_if_model(out_dir)
    generate_lstm_model(out_dir)
    log.info("Done — all 4 engines will be active on next startup.")


if __name__ == "__main__":
    main()
