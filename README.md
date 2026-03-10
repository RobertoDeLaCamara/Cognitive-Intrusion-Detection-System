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
        ├─► [Supervised Engine]     Random Forest (76 flow + 10 payload features)
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
| **Supervised** | 76 CICFlowMeter flow features (+ 10 payload features if retrained) | Random Forest (sklearn Pipeline) | Named attacks: DoS, PortScan, Brute-force, Web attacks, Infiltration |
| **Isolation Forest** | 18 per-IP host features | IsolationForest + StandardScaler | Novel / zero-day volumetric anomalies |
| **LSTM Autoencoder** | 18-feature time-series per IP | PyTorch sequence AE | Slow attacks, temporal behaviour drift |
| **Rules** | Flow metadata + payload bytes + JA3 hashes | Threshold rules | ICMP floods, SYN scans, SQLi, XSS, LFI, large payloads, asymmetric upload, malicious TLS fingerprints |

Default ensemble weights: Supervised 40 %, Isolation Forest 30 %, LSTM 20 %, Rules 10 %.
Any missing engine has its weight redistributed proportionally across the active engines.

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

Copy trained model files to `models/` (binary files are excluded from git):

```bash
# Supervised engine — Random Forest Pipeline (76 features)
cp /path/to/rf_model.joblib               models/

# Isolation Forest + scaler
cp /path/to/isolation_forest.joblib       models/
cp /path/to/if_scaler.joblib              models/

# LSTM Autoencoder
cp /path/to/lstm_autoencoder.pt           models/
cp /path/to/lstm_config.json              models/   # tracked in git
```

CNDS works with any subset of models — missing engines are gracefully skipped.

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
| `/metrics` | GET | Prometheus metrics (when `PROMETHEUS_ENABLED=true`) |
| `/docs` | GET | Swagger UI (auto-generated) |

### Example: manual prediction

```bash
curl -X POST http://localhost:8000/api/predict \
  -H "Content-Type: application/json" \
  -d '{
    "src_ip": "192.168.1.100",
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
| `RF_MODEL_FILE` | `rf_model.joblib` | Random Forest model filename |
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
| `MLFLOW_TRACKING_URI` | _(empty)_ | MLflow server URL; empty disables MLflow |
| `MLFLOW_REGISTRY_NAME` | `cnds` | MLflow model registry name |
| `JWT_SECRET` | _(empty)_ | JWT signing secret; empty disables JWT auth |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `JWT_EXPIRE_MINUTES` | `60` | JWT token expiry (minutes) |
| `PROMETHEUS_ENABLED` | `false` | Enable Prometheus metrics at `/metrics` |
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
| `IP_ALLOWLIST` | _(empty)_ | Comma-separated IPs to skip detection entirely |
| `IP_BLOCKLIST` | _(empty)_ | Comma-separated IPs to auto-flag as critical |
| `LOG_FORMAT` | `text` | Log output format: `text` or `json` (structured) |
| `JA3_ENABLED` | `true` | Extract JA3 fingerprints from TLS ClientHello |
| `MALICIOUS_JA3_FILE` | _(empty)_ | Path to known-malicious JA3 hashes (one per line); empty disables |

---

## Project Structure

```
├── main.py                      # Entry point: capture + detection pipeline
├── docker-compose.yml
├── Dockerfile
├── Jenkinsfile                  # CI/CD: build → lint → test → SonarQube → push
├── sonar-project.properties
├── requirements.txt
├── .env.example
├── alembic/                     # Database migrations
│   ├── env.py                   # Alembic config wired to CNDS models
│   └── versions/                # Auto-generated migration scripts
├── scripts/
│   ├── retrain_with_payload.py  # Retrain RF with 86 features (76 flow + 10 payload)
│   └── pcap_replay.py          # PCAP replay for offline threat hunting / model eval
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
├── models/                      # ML model files (binaries not committed)
│   ├── rf_model.joblib          # Random Forest pipeline (76 features)
│   ├── isolation_forest.joblib  # Isolation Forest
│   ├── if_scaler.joblib         # StandardScaler for IF
│   ├── lstm_autoencoder.pt      # LSTM Autoencoder weights
│   └── lstm_config.json         # LSTM architecture config (tracked)
├── src/
│   ├── config.py                # All settings (env-var driven)
│   ├── mlflow_registry.py       # Unified MLflow model registry
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
│   │   ├── registry.py          # Shared engine singletons
│   │   ├── supervised.py        # Random Forest wrapper
│   │   ├── isolation_forest.py  # Isolation Forest wrapper
│   │   ├── lstm_autoencoder.py  # LSTM Autoencoder wrapper
│   │   └── rules.py             # Rule-based engine (incl. JA3 rules)
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
│       ├── metrics.py           # Prometheus metrics + OpenTelemetry
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
    └── test_siem.py             # CEF syslog forwarder tests
```

---

## CI/CD Pipeline

Jenkins pipeline stages (see `Jenkinsfile`):

1. **Checkout** — pull from Gitea
2. **Build Image** — `docker build` tagged with build number and `latest`
3. **Code Quality** (parallel)
   - *Lint* — flake8 (max line length 120)
   - *Security* — Safety dependency audit
4. **Run Tests** — pytest with JUnit XML + coverage report
5. **SonarQube Analysis** — static analysis pushed to SonarQube (`cnds` project)
6. **Push to Registry** — push to private Docker registry at `192.168.1.86:5000`

---

## Roadmap

### v1.0 (complete)

- [x] Phase 1 — Shared capture layer (single Scapy loop → dual feature extraction)
- [x] Phase 2 — All four engines + ensemble scoring + FastAPI orchestration
- [x] Phase 3 — Payload pattern features fed into supervised feature set
- [x] Phase 4 — Confidence calibration and per-attack-type weight tuning
- [x] Phase 5 — Unified MLflow registry for all three models
- [x] Phase 6 — Real-time dashboard (WebSocket + Streamlit analytics)
- [x] Phase 7 — Auth (JWT/RBAC), Prometheus metrics, OpenTelemetry tracing
- [x] Phase 8 — GeoIP enrichment, alert correlation, adaptive weights, suppression rules, webhook/Telegram notifications, rate limiting, DNS logging
- [x] Phase 9 — Confidence decay, IP allowlist/blocklist, alert trends endpoint, capture stats in /health

### v2.0 (planned)

- [x] PCAP replay mode — offline ingestion of `.pcap` files for threat hunting and model evaluation
- [x] Alembic DB migrations — proper schema versioning for production deployments
- [x] Config validation — fail-fast on startup if weights don't sum to 1.0 or thresholds are out of range
- [x] API integration tests — end-to-end endpoint testing with in-memory SQLite
- [x] RBAC enforcement — wire `require_role()` to sensitive endpoints (suppression rules, incidents)
- [x] Alert export — CSV/JSON bulk export endpoint for analyst reporting
- [x] Dashboard enhancements — top talkers view, attack type breakdown, timeline visualization
- [x] Alert deduplication — suppress duplicate alerts from same (src_ip, attack_type) within configurable window
- [x] WebSocket authentication — JWT token required via `?token=` query parameter when `JWT_SECRET` is set
- [x] MITRE ATT&CK mapping — automatic technique enrichment on every alert (14 attack types + 11 rules)
- [x] JA3 TLS fingerprinting — real-time ClientHello extraction, malicious hash detection, per-alert storage
- [x] SIEM integration templates — Splunk (HEC + CIM), Elastic (index template + Logstash + Filebeat), CEF syslog forwarder
- [ ] Model drift detection — alert when live traffic feature distributions diverge from training data
- [ ] Feedback-driven retraining — analyst TP/FP labels → accumulated dataset → automated retraining via MLflow
- [ ] ONNX Runtime for LSTM — 2-5x inference speedup over raw PyTorch
