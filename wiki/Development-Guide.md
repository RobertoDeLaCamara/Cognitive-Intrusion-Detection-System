# Development Guide

## Prerequisites

- Python 3.10+ (the code uses `X | None` annotations; the Docker image runs 3.11)
- Docker 20.10+ and Docker Compose v2
- Root / `CAP_NET_RAW` for live capture
- PyTorch (CPU) for the FT-Transformer, LSTM and baseline engines — not in `requirements.txt`; `pip install torch --index-url https://download.pytorch.org/whl/cpu`
- MaxMind GeoLite2 database (optional, for GeoIP enrichment)

## Local Setup

```bash
git clone https://github.com/RobertoDeLaCamara/Cognitive-Intrusion-Detection-System.git
cd Cognitive-Intrusion-Detection-System
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env — set interface, thresholds, DB URL
```

## Training Models

Model weights are gitignored (the lite Random Forest and `lstm_config.json` are committed). The detector runs with whatever subset is present.

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

# 2–3. Isolation Forest + LSTM Autoencoder — no script: trained automatically
#      by the unsupervised baseline subsystem while the detector runs
#      (BASELINE_COLLECTION_ENABLED=true, see doc/unsupervised.md).
#      For a quick local start, generate synthetic demo models instead:
python scripts/generate_demo_models.py --output-dir models

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

# Docker Compose (postgres + api + detector; add --profile dashboard for Streamlit)
docker-compose up

# Specify interface
sudo python main.py --iface eth0

# Duration-limited capture
sudo python main.py --duration 300        # 5 minutes
```

## Testing

```bash
# Full test suite
pytest tests/ -v --cov=src

# Single test
pytest tests/test_api.py::test_list_alerts_hours -v

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
| `WEIGHT_SUPERVISED` | 0.30 | Supervised (FT-T / RF) engine weight |
| `WEIGHT_IFOREST` | 0.20 | Isolation Forest engine weight |
| `WEIGHT_LSTM` | 0.10 | LSTM engine weight |
| `WEIGHT_RULES` | 0.25 | Rules engine weight |
| `WEIGHT_BASELINE` | 0.15 | Baseline engine weight |
| `ENSEMBLE_THRESHOLD` | 0.55 | Alert firing threshold |
| `CALIBRATION_TEMPERATURE` | 1.0 | Platt scaling temperature |
| `DEDUP_WINDOW_SECS` | 300 | Duplicate alert suppression window |
| `ALERT_COOLDOWN_SECS` | 60 | Reserved (not read by the code) |
| `DATABASE_URL` | `sqlite+aiosqlite:///./cnds.db` | Use `postgresql+asyncpg://...` for prod |
| `JWT_SECRET` | (empty) | Enables JWT auth if set |
| `API_KEY` | (empty) | Enables the `X-API-Key` check if set |
| `PROMETHEUS_ENABLED` | false | Expose /metrics |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | (empty) | OTLP traces |
| `GEOIP_DB_PATH` | (empty) | MaxMind GeoLite2 .mmdb path |
| `WEBHOOK_URLS` | (empty) | Comma-separated notification URLs |
| `NOTIFY_MIN_SEVERITY` | high | Min severity for webhook notifications |
| `CORRELATION_THRESHOLD` | 5 | Alerts to auto-create incident |
| `ADAPTIVE_WEIGHTS_ENABLED` | false | Feedback-driven weight tuning |
| `IP_ALLOWLIST` | (empty) | Comma-separated IPs or CIDR ranges to skip |
| `IP_BLOCKLIST` | (empty) | Comma-separated IPs or CIDR ranges to auto-flag as critical (`/api/predict` path) |

## PCAP Replay

Replay a `.pcap` file through the full pipeline without live capture (useful for model evaluation and threat hunting):

```bash
python scripts/pcap_replay.py captures/attack_sample.pcap --output results.json
```

## Code Quality

```bash
# Lint
flake8 src/ --max-line-length=120

# Security audit
safety check -r requirements.txt

# Rough CI equivalent (Jenkins runs flake8 and safety as advisory, `|| true`)
flake8 src/ --max-line-length=120 && safety check -r requirements.txt && pytest tests/ -v --cov=src
```

## CI/CD Pipeline (Jenkins)

Defined in `Jenkinsfile`:

1. **Checkout**
2. **Build Image** — `docker build`, tagged `<build number>` on master or `<branch>-<build>` elsewhere
3. **Code Quality** (parallel, advisory — both end in `|| true`):
   - `flake8` lint (max-line-length 120)
   - `safety` dependency audit
4. **Run Tests** — `pytest tests/` inside the image with JUnit XML + coverage
5. **SonarQube Analysis** — Static analysis push (project key `cnds`)
6. **Claude PR review (advisory)** — pull requests only; posts a review on the Gitea PR, never fails the build
7. **Push to Registry** — `192.168.1.147:5000/cnds:<build>` and `:latest`, only from `master` (or the legacy single-branch job)

The pipeline runs on the Jenkins agent labelled `agent-45`.

## Docker Compose Details

Abridged from `docker-compose.yml` (the file is authoritative):

```yaml
services:
  postgres:
    image: postgres:16-alpine
    ports: ["127.0.0.1:5432:5432"]   # published so the host-network detector can reach it
    # POSTGRES_PASSWORD is mandatory: ${POSTGRES_PASSWORD:?...}

  api:
    build: {context: ., target: base}
    command: uvicorn src.api.main:app --host 0.0.0.0 --port 8000
    ports: ["8000:8000"]
    volumes: ["./models:/app/models"]
    env_file: [{path: .env.example, required: false}, {path: .env, required: false}]
    environment:
      - DATABASE_URL=postgresql+asyncpg://cnds:${POSTGRES_PASSWORD}@postgres:5432/cnds

  detector:
    build: {context: ., target: base}
    user: root
    network_mode: host       # required for raw sockets — can't resolve "postgres"
    command: python main.py
    volumes: ["./models:/app/models:ro"]
    environment:
      # host network mode: use localhost + the published port, not the service name
      - DATABASE_URL=postgresql+asyncpg://cnds:${POSTGRES_PASSWORD}@localhost:5432/cnds

  dashboard:                 # profile: dashboard
    build: {context: ., target: dashboard}
    ports: ["8501:8501"]
    environment: [CNDS_API_URL=http://api:8000]

  demo-seed:                 # profile: demo — one-shot synthetic data
```

Note that the detector runs `python main.py` without `--api`, so `capture_stats` in the `api` container's `/health` stays `null`.

**arm64 / Raspberry Pi:** build with `docker compose build --build-arg TARGETARCH=arm64` — plain `docker build`/`docker compose build` does not auto-populate `ARG TARGETARCH` from a `buildx --platform` flag, so it silently defaults to `amd64` even on an arm64 host.

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
│   ├── payload_analyzer.py      6 regex signatures + 10 numeric features
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
│   ├── baseline_engine.py       Live-trained IF + LSTM (MLflow)
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
│   ├── threat_intel.py          AbuseIPDB / JA3 / MISP feeds
│   └── dns_logger.py            DNS query capture
├── unsupervised/                Baseline collector, trigger, window trainer, drift
├── mcp_server/                  Read-only MCP server (opt-in)
├── triage/                      Advisory triage agent (opt-in)
├── guardian/                    Auto-response module (opt-in, GUARDIAN_ENABLED=false by default)
│   ├── backends.py              MitigationBackend protocol + AdGuardBackend
│   ├── engine.py                guardian_loop / guardian_expiry_loop
│   └── telegram_listener.py     Inline Confirm/Undo via getUpdates long-poll
└── api/
    ├── main.py                  FastAPI app + middleware
    ├── models.py                ORM: Alert, Incident, User, SuppressionRule, MitigationAction, TriageAnnotation
    ├── schemas.py               Pydantic request/response
    ├── database.py              Async session + auto-migration
    ├── auth.py                  JWT/RBAC
    ├── metrics.py               Prometheus + OpenTelemetry
    ├── rate_limit.py            Per-IP sliding-window limiter
    └── routers/
        ├── alerts.py
        ├── predict.py
        ├── auth.py
        ├── baseline.py
        └── websocket.py
```
