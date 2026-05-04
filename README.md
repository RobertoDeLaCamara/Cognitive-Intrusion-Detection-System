# Cognitive Network Defense System

**CNDS** is a real-time network intrusion detection system that fuses four detection engines — supervised ML, unsupervised anomaly detection, temporal sequence modeling, and rule-based heuristics — into a single weighted ensemble. A Scapy capture loop feeds packets into parallel feature pipelines; alerts are exposed over a FastAPI REST interface backed by SQLite (or PostgreSQL).

---

## Architecture

```
[Network Interface]
        │  Scapy packet capture
        ▼
[PacketProcessor]  ── async queue ──►  Worker threads (×4)
        │
        ▼
[Dispatcher]  ── flow expiry ──►  on_flow_complete()
   ├─ FlowExtractor   → 76 CICFlowMeter flow features
   ├─ HostExtractor   → 18 per-IP host features
   ├─ PayloadAnalyzer → regex pattern matches + 10 numeric payload features
   └─ JA3 Extractor   → TLS ClientHello fingerprint (hash + raw string)
        │
        ├─► [Supervised Engine]     FT-Transformer (preferred, 76 flow features, UNSW-NB15 schema)
        │                          ↳ falls back to Random Forest if no checkpoint
        ├─► [Isolation Forest]      Novelty score  (18 host features)
        ├─► [LSTM Autoencoder]      Sequence score (18 host features)
        └─► [Rules Engine]          Threshold + pattern + JA3 rules
                │
                ▼
        [Ensemble Scorer]
         weighted confidence fusion
                │
        ┌───────┴────────┐
        │   Alert fired  │  → MITRE ATT&CK mapping
        └───────┬────────┘    → logger + SQLite  →  FastAPI
                │
                ├─► SIEM (Splunk / Elastic / Syslog-CEF)
                └─► Webhook / Telegram notifications
```

### Detection Engines

| Engine | Input | Model | Detects |
|---|---|---|---|
| **Supervised (preferred)** | 76 CICFlowMeter flow features | FT-Transformer (PyTorch, ~2.4M params) — Optuna-tuned, F1 macro 0.6197 on UNSW-NB15 test split | 10 attack classes: Benign, Analysis, Backdoor, DoS, Exploits, Fuzzers, Generic, Reconnaissance, Shellcode, Worms |
| **Supervised (fallback)** | 76 CICFlowMeter flow features (+ 10 payload features if retrained) | Random Forest (sklearn Pipeline) | Same 10 attack classes; activates only when no FT-T checkpoint is present |
| **Isolation Forest** | 18 per-IP host features | IsolationForest + StandardScaler | Novel / zero-day volumetric anomalies |
| **LSTM Autoencoder** | 18-feature time-series per IP | PyTorch sequence AE | Slow attacks, temporal behaviour drift |
| **Rules** | Flow metadata + payload bytes + JA3 hashes | Threshold rules | ICMP floods, SYN scans, SQLi, XSS, LFI, large payloads, asymmetric upload, malicious TLS fingerprints |

Default ensemble weights: Supervised 40 %, Isolation Forest 30 %, LSTM 20 %, Rules 10 %.
Any missing engine has its weight redistributed proportionally across the active engines.

### Unsupervised Baseline Training

CNDS continuously collects live network feature vectors and autonomously trains baseline anomaly models — no labeled data required. When enough traffic diversity has been observed, a background thread fits a new **IsolationForest** and **LSTM Autoencoder** on the collected window and persists the artifacts to MLflow.

**Trigger conditions** (all four must be satisfied simultaneously):

| Condition | Default |
|---|---|
| Minimum feature vectors collected | 50,000 |
| Minimum distinct source IPs | 20 |
| Minimum elapsed time | 30 minutes |
| Minimum destination-port Shannon entropy | 2.5 bits |

A hard cap of 500,000 vectors overrides the composite trigger regardless of the other conditions.

**Artifact layout** (logged under MLflow experiment `cnds-unsupervised-baseline`, registered as `cnds-unsupervised-baseline`):

```
unsupervised_baseline/
  scaler.joblib          # StandardScaler fitted on training split
  iforest.joblib         # IsolationForest (200 estimators, contamination 0.01)
  lstm_autoencoder.pt    # LSTM Autoencoder weights (PyTorch .pt)
  threshold.txt          # 99th-percentile reconstruction error threshold
  provenance.json        # Window metadata: time range, fire reason, port/protocol histograms
```

If MLflow is not configured, models are still fitted but not persisted; a warning is logged.

**Enable / disable:** set `BASELINE_COLLECTION_ENABLED=false` to disable collection entirely. The default is `true`.

**Drop-counter warning:** while a training run is in progress, incoming samples are silently dropped and counted. When the run completes, a `WARNING` is logged with the total dropped count. A consistently high drop count means training takes longer than one window interval — consider reducing `min_total_vectors` or moving the training workload to a dedicated process.

See [`doc/unsupervised.md`](doc/unsupervised.md) for the full developer reference.

### MITRE ATT&CK Mapping

Every alert is automatically enriched with [MITRE ATT&CK](https://attack.mitre.org/) technique IDs. Mappings cover both supervised model labels (14 attack types) and rule triggers (11 rules including `malicious_ja3`). Techniques are deduplicated when multiple sources map to the same ID.

Example alert payload:
```json
{
  "attack_type": "DoS Hulk",
  "mitre_techniques": [
    {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"}
  ]
}
```

### JA3 TLS Fingerprinting

CNDS extracts [JA3](https://github.com/salesforce/ja3) fingerprints from TLS ClientHello messages in real time. The JA3 hash (MD5 of TLS version, cipher suites, extensions, elliptic curves, and point formats) is:

- Stored on every alert (`ja3_hash`, `ja3_string` columns)
- Checked against a configurable list of known-malicious hashes (`MALICIOUS_JA3_FILE`)
- Flagged by the rules engine as `malicious_ja3` → mapped to MITRE T1071 + T1573

GREASE values (RFC 8701) are filtered before hashing.

### SIEM Integration

Pre-built integration templates live in `siem/`:

| Platform | Files | Method |
|---|---|---|
| **Splunk** | `siem/splunk/inputs.conf`, `props.conf`, `savedsearches.conf` | HEC push via `WEBHOOK_URLS` or HTTP poll |
| **Elastic / OpenSearch** | `siem/elastic/index_template.json`, `logstash_cnds.conf`, `filebeat_cnds.yml` | Logstash poll/webhook, Filebeat log tail |
| **Syslog / CEF** (QRadar, ArcSight, Sentinel) | `siem/syslog/forwarder.py` | Standalone CEF forwarder over UDP/TCP |

Quick start:
```bash
# Push alerts to Splunk HEC
WEBHOOK_URLS=https://splunk.example.com:8088/services/collector/event

# Or run the CEF syslog forwarder
python siem/syslog/forwarder.py --syslog-host 10.0.0.50 --syslog-port 514
```

See `siem/README.md` for full setup instructions.

---

## Quick Start

### 1. Install

```bash
git clone https://github.com/RobertoDeLaCamara/Cognitive-Intrusion-Detection-System.git
cd Cognitive-Intrusion-Detection-System
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

### 2. Add models

The supervised engine selects one of two checkpoints automatically:

1. **Preferred — Unified FT-Transformer** (`models/unified/unified_ft_transformer.pt`, ~6.5 MB, gitignored). Trained on UNSW-NB15 and registered in MLflow as `ml-ids-unified-ft-transformer/1`. Loads from MLflow first, falls back to the local file. See [`doc/UNIFIED_FT_LIVE_RUNBOOK.md`](doc/UNIFIED_FT_LIVE_RUNBOOK.md) for the full setup and live test runbook.
2. **Fallback — Random Forest lite** (`models/rf_lite_model.joblib`, 1.6 MB, committed). Activates automatically if no FT-T checkpoint is present. Provides functional detection (91 % accuracy on CIC-UNSW-NB15) out of the box.

```bash
# Pull the unified FT-Transformer (recommended) — copy from ML-IDS or download from MLflow
mkdir -p models/unified
cp /path/to/ML-IDS/models/unified/unified_ft_transformer.pt  models/unified/
cp /path/to/ML-IDS/models/unified/unified_scaler.pkl         models/unified/
cp /path/to/ML-IDS/models/unified/unified_metadata.json      models/unified/

# OR train the legacy full Random Forest (requires CIC-UNSW-NB15 dataset, ~24s)
python scripts/train_rf.py --data-dir /path/to/CIC-UNSW-NB15

# Isolation Forest + scaler (optional)
cp /path/to/isolation_forest.joblib       models/
cp /path/to/if_scaler.joblib              models/

# LSTM Autoencoder (optional)
cp /path/to/lstm_autoencoder.pt           models/
cp /path/to/lstm_config.json              models/   # tracked in git
```

CNDS works with any subset of models — missing engines are gracefully skipped.

#### What ships in the Docker image

The `Dockerfile` build context includes (via `.dockerignore` allow-rules):

| File | When | Purpose |
|---|---|---|
| `models/rf_lite_model.joblib` | Always (committed) | RF fallback — keeps the supervised slot active even with no MLflow and no FT checkpoint |
| `models/unified/unified_ft_transformer.pt` | If present on the build host | Preferred FT-Transformer; loads ahead of the RF fallback |
| `models/unified/unified_scaler.pkl` | Same | StandardScaler matched to the FT checkpoint |
| `models/unified/unified_metadata.json` | Same | Feature names + class metadata |
| `models/lstm_config.json` | Always (committed) | LSTM architecture config (model weights are pulled at runtime) |

Behaviour matrix at runtime:

| Scenario | Supervised engine |
|---|---|
| No MLflow, no `models/unified/` on the build host | Random Forest lite (bundled) |
| No MLflow, `models/unified/` populated at build | FT-Transformer (loaded from local checkpoint) |
| MLflow reachable from the container | FT-Transformer (loaded from `models:/ml-ids-unified-ft-transformer/<latest>`); local files are still a hot fallback if the registry call fails |

### 3. Run

```bash
# Packet capture + detection (requires root for raw sockets)
sudo venv/bin/python main.py

# Specify network interface
sudo venv/bin/python main.py --iface eth0

# Capture + REST API on :8000
sudo venv/bin/python main.py --api

# API only — no live capture (useful for testing)
uvicorn src.api.main:app --host 0.0.0.0 --port 8000

# Stop automatically after N seconds
sudo venv/bin/python main.py --duration 60

# Docker Compose (API + detector + Streamlit dashboard)
# NOTE: The default SQLite backend does not support concurrent writers.
# In docker-compose, only the API service writes to the DB.
# For production multi-container setups, use PostgreSQL:
#   DATABASE_URL=postgresql+asyncpg://user:pass@db:5432/cnds
docker-compose up -d
# API:       http://localhost:8000
# Dashboard: http://localhost:8501
```

---

## REST API

Base URL: `http://localhost:8000`

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Engine availability + capture stats |
| `/api/predict` | POST | Run all engines on supplied features |
| `/api/alerts` | GET | List alerts (filter: `severity`, `src_ip`, `acknowledged`) |
| `/api/alerts/export` | GET | Export alerts as CSV/JSON (filter: `format`, `severity`, `hours`) |
| `/api/alerts/trends` | GET | Alert counts bucketed by hour/day (filter: `hours`, `bucket`) |
| `/api/alerts/{alert_id}` | GET | Get single alert by ID |
| `/api/alerts/{alert_id}` | PATCH | Acknowledge alert, add notes, link to incident |
| `/api/incidents` | GET / POST | Incident management (POST requires admin/analyst) |
| `/api/stats` | GET | Alert counts grouped by severity |
| `/api/suppression-rules` | GET / POST | List or create suppression rules (POST requires admin/analyst) |
| `/api/suppression-rules/{rule_id}` | DELETE | Remove a suppression rule (requires admin) |
| `/api/adaptive-weights` | GET | Compute adaptive engine weights from feedback |
| `/api/dns-log` | GET | DNS query logs (filter: `src_ip`) |
| `/api/auth/token` | POST | Issue JWT token (when `JWT_SECRET` is set) |
| `/api/auth/users` | GET / POST | User management (requires admin) |
| `/api/auth/users/{user_id}` | DELETE | Delete user (requires admin) |
| `/ws/alerts` | WebSocket | Real-time alert stream (`?token=JWT` when auth enabled) |
| `/metrics` | GET | Monitoring Service metrics (when `Monitoring Service_ENABLED=true`) |
| `/docs` | GET | Swagger UI (auto-generated) |

### Example: manual prediction

```bash
curl -X POST http://localhost:8000/api/predict \
  -H "Content-Type: application/json" \
  -d '{
    "src_ip": "[CLIENT_IP]",
    "dst_ip": "10.0.0.1",
    "dst_port": 80,
    "protocol": 6,
    "host_features": [45.2, 5200.0, 115.0, 800.0, 452, 52000,
                      0.02, 0.005, 12.0, 10.0, 0.9, 0.1, 0.0,
                      3.0, 0.2, 3.5, 80.0, 200.0]
  }'
```

### Example: list high-severity alerts

```bash
curl "http://localhost:8000/api/alerts?severity=high&limit=20"
```

### Example: export alerts as CSV

```bash
curl "http://localhost:8000/api/alerts/export?format=csv&severity=high&hours=24" -o alerts.csv
```

### Example: PCAP replay for model evaluation

```bash
python scripts/pcap_replay.py data/test.pcap --labels data/labels.csv --output results.json
```

---

## Database Migrations

CNDS uses [Alembic](https://alembic.sqlalchemy.org/) for schema versioning. On startup, the API automatically runs pending migrations (falling back to `create_all` for in-memory test databases).

```bash
# Generate a new migration after changing models
alembic revision --autogenerate -m "describe your change"

# Apply all pending migrations
alembic upgrade head

# Downgrade one step
alembic downgrade -1

# View current revision
alembic current
```

Migration files live in `alembic/versions/` and are tracked in git.

---

## Testing

```bash
# Run all tests
pytest tests/ -v

# With coverage report
pytest tests/ --cov=src --cov-report=term-missing

# Single module
pytest tests/test_flow_extractor.py -v
```

---

## Configuration

Copy `.env.example` to `.env` and adjust as needed.

**Note:** Configuration is validated on startup. Invalid settings (e.g., weights not summing to 1.0) will cause a `ConfigurationError`.

| Variable | Default | Description |
|---|---|---|
| `CAPTURE_INTERFACE` | auto | Network interface (e.g. `eth0`) |
| `PACKET_WORKERS` | `4` | Async worker threads |
| `PACKET_QUEUE_SIZE` | `20000` | Internal packet queue size |
| `FLOW_TIMEOUT` | `120` | Seconds before idle flow is flushed |
| `MAX_ACTIVE_FLOWS` | `50000` | Max simultaneous tracked flows |
| `ACTIVE_IDLE_THRESH` | `1.0` | Seconds of inactivity to mark a flow idle |
| `HOST_WINDOW_SIZE` | `100` | Packet history window per IP for host features |
| `MAX_TRACKED_IPS` | `5000` | Max IPs tracked by host extractor / LSTM buffers |
| `MIN_PACKETS_FOR_ML` | `10` | Min packets before ML engines activate |
| `ENSEMBLE_THRESHOLD` | `0.55` | Score above which an alert fires |
| `WEIGHT_SUPERVISED` | `0.40` | Supervised engine weight |
| `WEIGHT_IFOREST` | `0.30` | Isolation Forest weight |
| `WEIGHT_LSTM` | `0.20` | LSTM weight |
| `WEIGHT_RULES` | `0.10` | Rules weight |
| `LARGE_PAYLOAD_BYTES` | `10000` | Forward payload size (bytes) that triggers the large-payload rule |
| `MAX_PAYLOAD_SAMPLES` | `50` | Max payload samples stored per flow for feature extraction |
| `PAYLOAD_SAMPLE_BYTES` | `4096` | Max bytes kept per payload sample |
| `RATE_SPIKE_MULTIPLIER` | `2.0` | Multiplier for rate-spike rule detection |
| `ICMP_FLOOD_THRESHOLD` | `50` | ICMP packet count that triggers flood rule |
| `PORT_SCAN_THRESHOLD` | `20` | SYN count threshold for scan detection |
| `ALERT_COOLDOWN_SECS` | `60` | Seconds before a duplicate alert can fire again |
| `DEDUP_WINDOW_SECS` | `300` | Alert deduplication window (seconds) |
| `MODELS_DIR` | `models` | Directory containing model files |
| `RF_MODEL_FILE` | `rf_model.joblib` | Full RF model (gitignored, fallback only) |
| `RF_LITE_MODEL_FILE` | `rf_lite_model.joblib` | Bundled lite RF model (committed, second-tier fallback) |
| `RF_SCORE_THRESHOLD` | `0.90` | Min RF anomaly score to avoid false positives |
| `FT_MODEL_FILE` | `unified/unified_ft_transformer.pt` | FT-Transformer checkpoint (gitignored, preferred) |
| `FT_SCALER_FILE` | `unified/unified_scaler.pkl` | StandardScaler matched to the FT checkpoint |
| `FT_USE_GPU` | `false` | Run FT-T inference on CUDA when available |
| `FT_SCORE_THRESHOLD` | `0.50` | Min FT anomaly score (1 − P(Benign)) to contribute |
| `MLFLOW_FT_REGISTRY_NAME` | `ml-ids-unified-ft-transformer` | MLflow registered model name to load FT from |
| `MLFLOW_FT_STAGE` | `None` | MLflow stage to pin (default = latest version) |
| `IF_MODEL_FILE` | `isolation_forest.joblib` | Isolation Forest model filename |
| `IF_SCALER_FILE` | `if_scaler.joblib` | IF scaler filename |
| `LSTM_MODEL_FILE` | `lstm_autoencoder.pt` | LSTM model filename |
| `LSTM_CONFIG_FILE` | `lstm_config.json` | LSTM config filename |
| `DATABASE_URL` | `sqlite+aiosqlite:///./cnds.db` | SQLite or PostgreSQL URL |
| `API_HOST` | `0.0.0.0` | API bind address |
| `API_PORT` | `8000` | API listen port |
| `API_KEY` | _(empty)_ | Bearer token; leave empty to disable auth |
| `CORS_ORIGINS` | _(empty)_ | Comma-separated allowed origins; defaults to `http://localhost:3000` |
| `ATTACK_TYPE_WEIGHTS` | `{}` | JSON: per-attack-type engine weight overrides |
| `CALIBRATION_TEMPERATURE` | `1.0` | Platt scaling temperature (>1 softer, <1 sharper) |
| `ML Tracking_TRACKING_URI` | `http://[MAIN_NODE_IP]:5050` | ML Tracking server URL; empty disables ML Tracking |
| `ML Tracking_REGISTRY_NAME` | `cnds` | ML Tracking model registry name |
| `AWS_ACCESS_KEY_ID` | — | S3-compatible storage access key for ML Tracking artifact store |
| `AWS_SECRET_ACCESS_KEY` | — | S3-compatible storage secret key for ML Tracking artifact store |
| `ML Tracking_S3_ENDPOINT_URL` | `http://[BACKUP_SERVER_IP]:9000` | S3-compatible storage S3 endpoint for ML Tracking artifacts |
| `JWT_SECRET` | _(empty)_ | JWT signing secret; empty disables JWT auth |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `JWT_EXPIRE_MINUTES` | `60` | JWT token expiry (minutes) |
| `Monitoring Service_ENABLED` | `false` | Enable Monitoring Service metrics at `/metrics` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | _(empty)_ | OpenTelemetry OTLP endpoint |
| `GEOIP_DB_PATH` | _(empty)_ | Path to GeoLite2-City.mmdb; empty disables GeoIP |
| `CORRELATION_WINDOW_SECS` | `300` | Time window for alert correlation (seconds) |
| `CORRELATION_THRESHOLD` | `5` | Alerts from same IP before auto-incident creation |
| `ADAPTIVE_WEIGHTS_ENABLED` | `false` | Enable adaptive engine weight computation |
| `ADAPTIVE_MIN_SAMPLES` | `100` | Min acknowledged alerts before adapting weights |
| `WEBHOOK_URLS` | _(empty)_ | Comma-separated webhook/Slack notification URLs |
| `NOTIFY_MIN_SEVERITY` | `high` | Minimum severity to trigger webhook notification |
| `TELEGRAM_BOT_TOKEN` | _(empty)_ | Telegram bot token from @BotFather; empty disables |
| `TELEGRAM_CHAT_ID` | _(empty)_ | Telegram chat/group ID to send alerts to |
| `RATE_LIMIT_REQUESTS` | `60` | Max API requests per window per IP |
| `RATE_LIMIT_WINDOW` | `60` | Rate limit window (seconds) |
| `DNS_LOGGING_ENABLED` | `false` | Enable DNS query logging from captured traffic |
| `CONFIDENCE_DECAY_FACTOR` | `0.9` | Score multiplier per repeat alert from same IP |
| `CONFIDENCE_DECAY_WINDOW` | `300` | Seconds to track repeat alerts for decay |
| `IP_ALLOWLIST` | _(empty)_ | Comma-separated IPs or CIDR ranges to skip detection entirely |
| `IP_BLOCKLIST` | _(empty)_ | Comma-separated IPs or CIDR ranges to auto-flag as critical |
| `LOG_FORMAT` | `text` | Log output format: `text` or `json` (structured) |
| `JA3_ENABLED` | `true` | Extract JA3 fingerprints from TLS ClientHello |
| `MALICIOUS_JA3_FILE` | _(empty)_ | Path to known-malicious JA3 hashes (one per line); empty disables |
| `BASELINE_COLLECTION_ENABLED` | `true` | Enable unsupervised baseline collection and training |

---

## Project Structure

```
├── main.py                      # Entry point: capture + CLI
├── docker-compose.yml
├── Dockerfile
├── CI/CDfile                  # CI/CD: build → lint → test → Quality Analysis → push
├── sonar-project.properties
├── requirements.txt
├── .env.example
├── alembic/                     # Database migrations
│   ├── env.py                   # Alembic config wired to CNDS models
│   └── versions/                # Auto-generated migration scripts
├── scripts/
│   ├── retrain_with_payload.py    # Retrain RF with 86 features (76 flow + 10 payload)
│   ├── pcap_replay.py             # PCAP replay for offline threat hunting / model eval
│   └── smoke_test_ft_unified.py   # Reproduce FT-Transformer F1 macro on the held-out test split
├── siem/                        # SIEM integration templates
│   ├── README.md                # Setup guide for all platforms
│   ├── splunk/
│   │   ├── inputs.conf          # HEC input configuration
│   │   ├── props.conf           # Field extraction + CIM mapping
│   │   └── savedsearches.conf   # Pre-built alert searches
│   ├── elastic/
│   │   ├── index_template.json  # Typed mappings (geo_point, nested MITRE)
│   │   ├── logstash_cnds.conf   # Logstash pipeline (poll + webhook)
│   │   └── filebeat_cnds.yml    # Filebeat log tail config
│   └── syslog/
│       └── forwarder.py         # CEF syslog forwarder (QRadar, ArcSight, Sentinel)
├── dashboard/
│   └── app.py                   # Streamlit real-time dashboard
├── models/                       # ML model files
│   ├── unified/
│   │   ├── unified_ft_transformer.pt   # Preferred supervised model (gitignored)
│   │   ├── unified_scaler.pkl          # StandardScaler matched to the FT checkpoint
│   │   └── unified_metadata.json       # Feature names, class counts, training metrics
│   ├── rf_lite_model.joblib      # Bundled lite RF (1.6MB, committed — fallback)
│   ├── rf_model.joblib           # Full RF pipeline (gitignored — fallback only)
│   ├── isolation_forest.joblib   # Isolation Forest (gitignored)
│   ├── if_scaler.joblib          # StandardScaler for IF (gitignored)
│   ├── lstm_autoencoder.pt       # LSTM Autoencoder weights (gitignored)
│   └── lstm_config.json          # LSTM architecture config (committed)
├── src/
│   ├── config.py                # All settings (env-var driven)
│   ├── pipeline.py              # Detection pipeline callback (flow → engines → alert)
│   ├── mlflow_registry.py       # Unified MLflow model registry
│   ├── models/
│   │   └── ft_transformer.py    # FTTransformer class + load/build helpers + UNIFIED_CLASS_LABELS
│   ├── capture/
│   │   ├── packet_capture.py    # Scapy capture + async worker queue
│   │   └── dispatcher.py        # Fan-out to feature pipelines on flow expiry
│   ├── features/
│   │   ├── flow_extractor.py    # 76 CICFlowMeter-compatible features per flow
│   │   ├── host_extractor.py    # 18 per-IP host features
│   │   ├── payload_analyzer.py  # Regex pattern matching + numeric payload features
│   │   ├── ja3.py               # JA3 TLS fingerprint extraction
│   │   └── utils.py             # Shared utilities (byte entropy, etc.)
│   ├── engines/
│   │   ├── protocol.py          # DetectionEngine interface (Protocol)
│   │   ├── registry.py          # Shared engine singletons (FT preferred, RF fallback)
│   │   ├── supervised.py        # Random Forest wrapper (legacy fallback)
│   │   ├── ft_transformer_engine.py  # FT-Transformer engine (MLflow → local fallback)
│   │   ├── isolation_forest.py  # Isolation Forest wrapper
│   │   ├── lstm_autoencoder.py  # LSTM Autoencoder wrapper
│   │   ├── lstm_model.py        # LSTM Autoencoder architecture (nn.Module)
│   │   └── rules.py             # Rule-based engine (incl. JA3 rules)
│   ├── unsupervised/
│   │   ├── collector.py         # Thread-safe ring-capped feature vector buffer
│   │   ├── triggers.py          # CompositeTrigger: four-condition window trigger
│   │   ├── window_trainer.py    # IsolationForest + LSTM Autoencoder training + MLflow logging
│   │   ├── artifact_schema.py   # Canonical MLflow artifact path constants
│   │   └── provenance.py        # ProvenanceMetadata: window statistics snapshot
│   ├── ensemble/
│   │   └── scorer.py            # Weighted confidence fusion → EnsembleResult
│   ├── enrichment/
│   │   ├── mitre.py             # MITRE ATT&CK technique mapping
│   │   ├── geoip.py             # GeoIP enrichment (MaxMind)
│   │   ├── correlation.py       # Auto-group alerts into incidents
│   │   ├── adaptive_weights.py  # Feedback-driven engine weight tuning
│   │   ├── suppression.py       # Temporary alert suppression rules
│   │   ├── notifications.py     # Webhook/Slack alert notifications
│   │   ├── confidence_decay.py  # Exponential score decay for repeat alerts
│   │   ├── ip_lists.py          # IP allowlist / blocklist
│   │   └── dns_logger.py        # DNS query logging from captured traffic
│   └── api/
│       ├── main.py              # FastAPI application
│       ├── models.py            # SQLAlchemy ORM (Alert, Incident)
│       ├── schemas.py           # Pydantic request/response schemas
│       ├── database.py          # Async SQLAlchemy session setup
│       ├── auth.py              # JWT authentication and RBAC
│       ├── metrics.py           # Monitoring Service metrics + OpenTelemetry
│       ├── rate_limit.py        # Per-IP rate limiting middleware
│       └── routers/
│           ├── predict.py       # POST /api/predict
│           ├── alerts.py        # Alert + incident CRUD
│           ├── auth.py          # POST /api/auth/token
│           └── websocket.py     # WebSocket /ws/alerts
└── tests/
    ├── conftest.py              # Shared fixtures (in-memory DB, mock features)
    ├── test_api.py              # API integration tests
    ├── test_auth.py             # JWT authentication and RBAC tests
    ├── test_config.py           # Configuration validation tests
    ├── test_engines.py          # Engine unit tests
    ├── test_enrichment.py       # Enrichment module tests
    ├── test_ensemble.py         # Ensemble scorer tests
    ├── test_flow_extractor.py
    ├── test_host_extractor.py
    ├── test_ja3.py              # JA3 fingerprint extraction tests
    ├── test_mitre.py            # MITRE ATT&CK mapping tests
    ├── test_payload_features.py
    ├── test_rules_engine.py
    ├── test_siem.py             # CEF syslog forwarder tests
    ├── test_ft_transformer_engine.py  # FT-Transformer integration tests (load + predict + dataset checks)
    └── unsupervised/
        └── test_collector.py    # BaselineCollector, CompositeTrigger, ProvenanceMetadata unit tests
```

---

## Roadmap

See the [open issues](https://github.com/RobertoDeLaCamara/Cognitive-Intrusion-Detection-System/issues) for planned features and known bugs. Contributions welcome — check [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
