"""Configuration for the Cognitive Network Defense System (CNDS)."""

import os
import sys
import logging

_logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    """Raised when configuration validation fails."""
    pass


def _validate_config():
    """Validate configuration on module load. Raises ConfigurationError on failure."""
    errors = []

    # Validate engine weights sum to 1.0
    weight_sum = WEIGHT_SUPERVISED + WEIGHT_IFOREST + WEIGHT_LSTM + WEIGHT_RULES
    if not (0.99 <= weight_sum <= 1.01):
        errors.append(f"Engine weights must sum to 1.0, got {weight_sum:.3f}")

    # Validate thresholds are in valid ranges
    if not (0.0 <= ENSEMBLE_THRESHOLD <= 1.0):
        errors.append(f"ENSEMBLE_THRESHOLD must be in [0,1], got {ENSEMBLE_THRESHOLD}")

    if not (0.0 < CALIBRATION_TEMPERATURE <= 10.0):
        errors.append(f"CALIBRATION_TEMPERATURE must be in (0,10], got {CALIBRATION_TEMPERATURE}")

    if FLOW_TIMEOUT <= 0:
        errors.append(f"FLOW_TIMEOUT must be positive, got {FLOW_TIMEOUT}")

    if PACKET_WORKERS < 1:
        errors.append(f"PACKET_WORKERS must be >= 1, got {PACKET_WORKERS}")

    if errors:
        msg = "Configuration validation failed:\n  - " + "\n  - ".join(errors)
        raise ConfigurationError(msg)


# ── Capture ─────────────────────────────────────────────────────────────────
CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", None)   # None = auto
PACKET_WORKERS    = int(os.getenv("PACKET_WORKERS", "4"))
PACKET_QUEUE_SIZE = int(os.getenv("PACKET_QUEUE_SIZE", "20000"))

# ── Flow extractor ──────────────────────────────────────────────────────────
FLOW_TIMEOUT        = float(os.getenv("FLOW_TIMEOUT", "120"))    # seconds
MAX_ACTIVE_FLOWS    = int(os.getenv("MAX_ACTIVE_FLOWS", "50000"))
ACTIVE_IDLE_THRESH  = float(os.getenv("ACTIVE_IDLE_THRESH", "1.0"))  # seconds
MAX_PAYLOAD_SAMPLES = int(os.getenv("MAX_PAYLOAD_SAMPLES", "50"))    # per flow
PAYLOAD_SAMPLE_BYTES = int(os.getenv("PAYLOAD_SAMPLE_BYTES", "4096")) # per packet

# ── Host extractor ───────────────────────────────────────────────────────────
HOST_WINDOW_SIZE    = int(os.getenv("HOST_WINDOW_SIZE", "100"))   # packet history
MAX_TRACKED_IPS     = int(os.getenv("MAX_TRACKED_IPS", "5000"))
MIN_PACKETS_FOR_ML  = int(os.getenv("MIN_PACKETS_FOR_ML", "10"))

COMMON_PORTS = {
    20, 21, 22, 23, 25, 53, 80, 110, 143, 443,
    465, 587, 993, 995, 3306, 5432, 6379, 8080, 8443,
}

# ── Engine weights ────────────────────────────────────────────────────────────
WEIGHT_SUPERVISED   = float(os.getenv("WEIGHT_SUPERVISED", "0.40"))
WEIGHT_IFOREST      = float(os.getenv("WEIGHT_IFOREST", "0.30"))
WEIGHT_LSTM         = float(os.getenv("WEIGHT_LSTM", "0.20"))
WEIGHT_RULES        = float(os.getenv("WEIGHT_RULES", "0.10"))
ENSEMBLE_THRESHOLD  = float(os.getenv("ENSEMBLE_THRESHOLD", "0.55"))
RF_SCORE_THRESHOLD  = float(os.getenv("RF_SCORE_THRESHOLD", "0.90"))  # min confidence for RF to contribute a non-zero score

# ── Per-attack-type weight overrides (Phase 4) ───────────────────────────────
# JSON string mapping attack type → {engine: weight}
# Example: '{"DoS": {"supervised": 0.6, "rules": 0.2}, "PortScan": {"rules": 0.5}}'
import json as _json
ATTACK_TYPE_WEIGHTS = _json.loads(os.getenv("ATTACK_TYPE_WEIGHTS", "{}"))

# Confidence calibration: Platt scaling temperature (>1 = softer, <1 = sharper)
CALIBRATION_TEMPERATURE = float(os.getenv("CALIBRATION_TEMPERATURE", "1.0"))

# ── Rule thresholds ───────────────────────────────────────────────────────────
RATE_SPIKE_MULTIPLIER = float(os.getenv("RATE_SPIKE_MULTIPLIER", "2.0"))
ICMP_FLOOD_THRESHOLD  = int(os.getenv("ICMP_FLOOD_THRESHOLD", "50"))
PORT_SCAN_THRESHOLD   = int(os.getenv("PORT_SCAN_THRESHOLD", "20"))   # unique ports
LARGE_PAYLOAD_BYTES   = int(os.getenv("LARGE_PAYLOAD_BYTES", "10000"))
ALERT_COOLDOWN_SECS   = int(os.getenv("ALERT_COOLDOWN_SECS", "60"))

# ── Model paths ────────────────────────────────────────────────────────────────
MODELS_DIR          = os.getenv("MODELS_DIR", "models")
RF_MODEL_PATH       = os.path.join(MODELS_DIR, os.getenv("RF_MODEL_FILE", "rf_model.joblib"))
RF_LITE_MODEL_PATH  = os.path.join(MODELS_DIR, os.getenv("RF_LITE_MODEL_FILE", "rf_lite_model.joblib"))
IF_MODEL_PATH       = os.path.join(MODELS_DIR, os.getenv("IF_MODEL_FILE", "isolation_forest.joblib"))
IF_SCALER_PATH      = os.path.join(MODELS_DIR, os.getenv("IF_SCALER_FILE", "if_scaler.joblib"))
LSTM_MODEL_PATH     = os.path.join(MODELS_DIR, os.getenv("LSTM_MODEL_FILE", "lstm_autoencoder.pt"))
LSTM_CONFIG_PATH    = os.path.join(MODELS_DIR, os.getenv("LSTM_CONFIG_FILE", "lstm_config.json"))

# ── MLflow (Phase 5) ──────────────────────────────────────────────────────────
MLFLOW_TRACKING_URI = os.getenv("MLFLOW_TRACKING_URI", "http://192.168.1.48:5050")  # homelab MLflow server
MLFLOW_REGISTRY_NAME = os.getenv("MLFLOW_REGISTRY_NAME", "cnds")

# ── Database ────────────────────────────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./cnds.db")

# ── API ────────────────────────────────────────────────────────────────────────
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
API_KEY  = os.getenv("API_KEY", "")   # empty = no auth
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]

# ── JWT Auth (Phase 7) ────────────────────────────────────────────────────────
JWT_SECRET    = os.getenv("JWT_SECRET", "")       # empty = JWT disabled
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

# ── Observability (Phase 7) ───────────────────────────────────────────────────
PROMETHEUS_ENABLED = os.getenv("PROMETHEUS_ENABLED", "false").lower() == "true"
OTEL_EXPORTER_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")

# ── Alerts ─────────────────────────────────────────────────────────────────────
DEDUP_WINDOW_SECS = int(os.getenv("DEDUP_WINDOW_SECS", "300"))

# ── GeoIP (Phase 8) ───────────────────────────────────────────────────────────
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "")  # path to GeoLite2-City.mmdb; empty = disabled

# ── Alert correlation (Phase 8) ───────────────────────────────────────────────
CORRELATION_WINDOW_SECS = int(os.getenv("CORRELATION_WINDOW_SECS", "300"))
CORRELATION_THRESHOLD   = int(os.getenv("CORRELATION_THRESHOLD", "5"))  # alerts before auto-incident

# ── Adaptive weights (Phase 8) ────────────────────────────────────────────────
ADAPTIVE_WEIGHTS_ENABLED = os.getenv("ADAPTIVE_WEIGHTS_ENABLED", "false").lower() == "true"
ADAPTIVE_MIN_SAMPLES     = int(os.getenv("ADAPTIVE_MIN_SAMPLES", "100"))

# ── Notifications (Phase 8) ───────────────────────────────────────────────────
WEBHOOK_URLS       = [u.strip() for u in os.getenv("WEBHOOK_URLS", "").split(",") if u.strip()]
NOTIFY_MIN_SEVERITY = os.getenv("NOTIFY_MIN_SEVERITY", "high")  # minimum severity to notify
TELEGRAM_BOT_TOKEN  = os.getenv("TELEGRAM_BOT_TOKEN", "")       # empty = disabled
TELEGRAM_CHAT_ID    = os.getenv("TELEGRAM_CHAT_ID", "")

# ── Rate limiting (Phase 8) ───────────────────────────────────────────────────
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "60"))   # per window
RATE_LIMIT_WINDOW   = int(os.getenv("RATE_LIMIT_WINDOW", "60"))     # seconds

# ── DNS logging (Phase 8) ─────────────────────────────────────────────────────
DNS_LOGGING_ENABLED = os.getenv("DNS_LOGGING_ENABLED", "false").lower() == "true"

# ── Confidence decay (Phase 9) ────────────────────────────────────────────────
CONFIDENCE_DECAY_FACTOR = float(os.getenv("CONFIDENCE_DECAY_FACTOR", "0.9"))  # per repeat alert
CONFIDENCE_DECAY_WINDOW = int(os.getenv("CONFIDENCE_DECAY_WINDOW", "300"))    # seconds

# ── IP allowlist / blocklist (Phase 9) ────────────────────────────────────────
# Supports individual IPs and CIDR ranges (e.g. 10.0.0.1,192.168.0.0/16)
IP_ALLOWLIST = set(filter(None, os.getenv("IP_ALLOWLIST", "").split(",")))
IP_BLOCKLIST = set(filter(None, os.getenv("IP_BLOCKLIST", "").split(",")))

# ── Device profiles — trusted outbound domains per device IP ──────────────────
# JSON mapping: {"<src_ip>": ["domain.suffix", ...]}
# Flows from a listed src_ip whose dst resolves to one of its trusted suffixes
# are skipped before the detection pipeline runs.
# Example: {"192.168.1.60": ["synology.com", "quickconnect.to", "synology.cn"]}
TRUSTED_OUTBOUND: dict = _json.loads(os.getenv("TRUSTED_OUTBOUND", "{}"))

# ── Logging ────────────────────────────────────────────────────────────────────
LOG_FORMAT = os.getenv("LOG_FORMAT", "text")  # "text" or "json"

# ── JA3 TLS fingerprinting ────────────────────────────────────────────────────
JA3_ENABLED = os.getenv("JA3_ENABLED", "true").lower() == "true"
MALICIOUS_JA3_FILE = os.getenv("MALICIOUS_JA3_FILE", "")  # path to known-bad hashes


def setup_logging():
    """Configure logging. Call once at startup."""
    if LOG_FORMAT == "json":
        try:
            from pythonjsonlogger.json import JsonFormatter
            handler = logging.StreamHandler()
            handler.setFormatter(JsonFormatter(
                fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
                rename_fields={"asctime": "timestamp", "levelname": "level"},
            ))
            logging.root.handlers.clear()
            logging.root.addHandler(handler)
            logging.root.setLevel(logging.INFO)
            return
        except ImportError:
            pass
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        force=True,
    )

# ── Validate configuration on import ──────────────────────────────────────────
_validate_config()
