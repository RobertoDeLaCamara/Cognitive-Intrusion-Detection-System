# Development Guide

## Prerequisites

- Python 3.11+
- Docker 20.10+ and Docker Compose v2
- Root / `CAP_NET_RAW` for live capture
- PyTorch (CPU) for LSTM engine
- MaxMind GeoLite2 database (optional, for GeoIP enrichment)

## Local Setup

```bash
git clone <repo>
cd cnds
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env — set interface, thresholds, DB URL
```

## Training Models

Models are gitignored. You must train them before running the detector.

```bash
# 0. Supervised (FT-Transformer, preferred) — trained in the ML-IDS repo
#    See ML-IDS/notebooks/ft_transformer_optuna_sweep.py.
#    Copy the artifacts into cnds, or load from MLflow.
mkdir -p models/unified
cp /path/to/ML-IDS/models/unified/unified_ft_transformer.pt  models/unified/
cp /path/to/ML-IDS/models/unified/unified_scaler.pkl         models/unified/
cp /path/to/ML-IDS/models/unified/unified_metadata.json      models/unified/

# 1. Supervised (Random Forest, fallback) — requires CIC-UNSW-NB15 dataset
#    Place dataset CSVs in data/CIC-UNSW-NB15/
python scripts/train_rf.py --data-dir /path/to/CIC-UNSW-NB15

# 2. Isolation Forest — requires normal-traffic baseline
sudo python main.py --duration 600        # 10 min capture → data/baseline_host.csv
python scripts/train_isolation_forest.py --input data/baseline_host.csv

# 3. LSTM Autoencoder
python scripts/train_lstm.py --input data/baseline_host.csv

# Verify models exist:
ls models/ models/unified/
# unified/unified_ft_transformer.pt  unified/unified_scaler.pkl  unified/unified_metadata.json
# rf_model.joblib  isolation_forest.joblib  if_scaler.joblib
# lstm_autoencoder.pt  lstm_config.json
```

## Running

```bash
# API only (no capture)
uvicorn src.api.main:app --port 8000 --reload

# Capture + API
sudo python main.py --api

# Docker Compose (full stack: capture + API + dashboard)
docker-compose up

# Specify interface
sudo python main.py --interface eth0

# Duration-limited capture
sudo python main.py --duration 300        # 5 minutes
```

## Testing

```bash
# Full test suite
pytest tests/ -v --cov=src

# Single test
pytest tests/test_flow_extractor.py::TestFlowExtractor::test_basic_flow -v

# API integration tests (no capture required)
pytest tests/test_api.py -v

# Engine unit tests
pytest tests/test_engines.py -v

# MITRE mapping
pytest tests/test_mitre.py -v
```

## Key Environment Variables

| Variable | Default | Notes |
|----------|---------|-------|
| `CAPTURE_INTERFACE` | auto-detect | Network interface for live capture |
| `PACKET_WORKERS` | 4 | Worker threads for packet queue |
| `PACKET_QUEUE_SIZE` | 20000 | Bounded queue capacity |
| `FLOW_TIMEOUT` | 120s | Flow idle expiry |
| `MAX_ACTIVE_FLOWS` | 50000 | Max concurrent flows tracked |
| `HOST_WINDOW_SIZE` | 100 | Packets per IP sliding window |
| `MAX_TRACKED_IPS` | 5000 | Max IPs in host extractor |
| `WEIGHT_SUPERVISED` | 0.40 | RF engine weight |
| `WEIGHT_IF` | 0.30 | IF engine weight |
| `WEIGHT_LSTM` | 0.20 | LSTM engine weight |
| `WEIGHT_RULES` | 0.10 | Rules engine weight |
| `ENSEMBLE_THRESHOLD` | 0.55 | Alert firing threshold |
| `CALIBRATION_TEMPERATURE` | 1.0 | Platt scaling temperature |
| `DEDUP_WINDOW_SECS` | 300 | Duplicate alert suppression window |
| `ALERT_COOLDOWN_SECS` | 60 | Per-IP cooldown after alert |
| `DATABASE_URL` | `sqlite+aiosqlite:///./cnds.db` | Use `postgresql+asyncpg://...` for prod |
| `JWT_SECRET` | (empty) | Enables JWT auth if set |
| `API_KEY` | (empty) | Enables API key auth if set |
| `Monitoring Service_ENABLED` | false | Expose /metrics |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | (empty) | OTLP traces |
| `GEOIP_DB_PATH` | (empty) | MaxMind GeoLite2 .mmdb path |
| `WEBHOOK_URLS` | (empty) | Comma-separated notification URLs |
| `NOTIFY_MIN_SEVERITY` | high | Min severity for webhook notifications |
| `CORRELATION_THRESHOLD` | 5 | Alerts to auto-create incident |
| `ADAPTIVE_WEIGHTS_ENABLED` | false | Feedback-driven weight tuning |
| `IP_ALLOWLIST` | (empty) | Comma-separated IPs or CIDR ranges to skip |
| `IP_BLOCKLIST` | (empty) | Comma-separated IPs to auto-escalate |

## PCAP Replay

Replay a `.pcap` file through the full pipeline without live capture (useful for model evaluation and threat hunting):

```bash
python scripts/pcap_replay.py --pcap captures/attack_sample.pcap
```

## Code Quality

```bash
# Lint
flake8 src/ --max-line-length=120

# Security audit
safety check

# Full CI equivalent
flake8 src/ --max-line-length=120 && safety check && pytest tests/ -v --cov=src
```

## CI/CD Pipeline (CI/CD)

Defined in `CI/CDfile`:

1. **Checkout** — Pull from Git Server
2. **Build Image** — `docker build` with build number + `latest` tags
3. **Code Quality** (parallel):
   - `flake8` lint (max-line-length 120)
   - `safety` dependency audit
4. **Run Tests** — `pytest` with JUnit XML + coverage
5. **Quality Analysis** — Static analysis push
6. **Push** — Docker image to private registry `[REGISTRY_IP]:5000`

## Docker Compose Details

```yaml
services:
  api:
    build: .
    ports: ["8000:8000"]
    volumes:
      - ./models:/app/models:ro
      - cnds_db:/app/data
    environment:
      - DATABASE_URL=sqlite+aiosqlite:////app/data/cnds.db

  detector:
    build: .
    network_mode: host       # required for raw sockets
    command: python main.py
    volumes:
      - ./models:/app/models:ro

  dashboard:
    build: .
    ports: ["8501:8501"]
    command: streamlit run dashboard/app.py
```

## Directory Layout

```
src/
├── config.py                    70+ env vars, fail-fast validation
├── capture/
│   ├── packet_capture.py        Scapy sniff + worker queue
│   └── dispatcher.py            Fan-out to feature extractors
├── features/
│   ├── flow_extractor.py        76-feature bidirectional flows
│   ├── host_extractor.py        18-feature per-IP profiling
│   ├── payload_analyzer.py      Regex + numeric features + ReDoS timeout
│   └── ja3.py                   TLS fingerprinting
├── models/
│   └── ft_transformer.py        FTTransformer class + load helpers + UNIFIED_CLASS_LABELS
├── engines/
│   ├── protocol.py              DetectionEngine structural protocol
│   ├── registry.py              Engine singletons (FT preferred, RF fallback)
│   ├── ft_transformer_engine.py FT-Transformer engine (MLflow → local fallback)
│   ├── supervised.py            Random Forest wrapper (legacy fallback)
│   ├── isolation_forest.py      IF + StandardScaler
│   ├── lstm_autoencoder.py      PyTorch temporal AE
│   └── rules.py                 Heuristic thresholds
├── ensemble/
│   └── scorer.py                Weighted fusion + temperature scaling
├── enrichment/
│   ├── mitre.py                 ATT&CK mapping
│   ├── geoip.py                 MaxMind lookups
│   ├── correlation.py           Auto-incident creation
│   ├── adaptive_weights.py      Feedback-driven tuning
│   ├── suppression.py           Maintenance window rules
│   ├── notifications.py         Webhook/Slack/Telegram
│   ├── confidence_decay.py      Exponential decay for repeat alerts
│   ├── ip_lists.py              Allow/blocklist filtering
│   └── dns_logger.py            DNS query capture
└── api/
    ├── main.py                  FastAPI app + middleware
    ├── models.py                ORM: Alert, Incident, User, SuppressionRule
    ├── schemas.py               Pydantic request/response
    ├── database.py              Async session + auto-migration
    ├── auth.py                  JWT/RBAC
    ├── metrics.py               Monitoring Service + OpenTelemetry
    ├── rate_limit.py            Per-IP token bucket
    └── routers/
        ├── alerts.py
        ├── predict.py
        ├── auth.py
        └── websocket.py
```
