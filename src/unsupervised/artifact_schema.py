"""Canonical MLflow artifact layout for unsupervised baseline models."""
ARTIFACT_ROOT = "unsupervised_baseline"
SCALER_FILE = "scaler.joblib"
IFOREST_FILE = "iforest.joblib"
LSTM_FILE = "lstm_autoencoder.pt"          # PyTorch .pt, NOT .keras — weights_only=True on load
THRESHOLD_FILE = "threshold.txt"
PROVENANCE_FILE = "provenance.json"
MODEL_NAME = "cnds-unsupervised-baseline"

# Sequence length used by WindowTrainer._to_sequences() and BaselineEngine ring buffers.
# Both sides MUST use the same value — change here only.
BASELINE_SEQ_LEN: int = 20
