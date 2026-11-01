"""Canonical MLflow artifact layout for unsupervised baseline models."""
ARTIFACT_ROOT = "unsupervised_baseline"
SCALER_FILE = "scaler.joblib"
IFOREST_FILE = "iforest.joblib"
LSTM_FILE = "lstm_autoencoder.pt"          # PyTorch .pt, NOT .keras — weights_only=True on load
THRESHOLD_FILE = "threshold.txt"
PROVENANCE_FILE = "provenance.json"
# Bump when the meaning of a host feature changes; baseline models trained on another schema are
# not loaded. 2: volume/rate/duration over the sliding packet window (1: lifetime totals).
HOST_FEATURE_SCHEMA: int = 2
FEATURE_SCHEMA_FILE = "feature_schema.txt"   # HOST_FEATURE_SCHEMA the models were trained on
MODEL_NAME = "cnds-unsupervised-baseline"

# Sequence length used by WindowTrainer._to_sequences() and BaselineEngine ring buffers.
# Both sides MUST use the same value — change here only.
BASELINE_SEQ_LEN: int = 20
