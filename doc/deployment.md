# CNDS — Deployment & Operations Guide

## Prerequisites

| Requirement | Details |
|---|---|
| Python | 3.10+ |
| OS | Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+) |
| Privileges | Root or `CAP_NET_RAW` for live capture |
| Network interface | Any interface visible to Scapy (eth0, ens3, wlan0, etc.) |
| RAM | 2 GB minimum; 4 GB recommended (models loaded in memory) |
| Disk | 500 MB for models + logs; more for PostgreSQL history |

For Docker deployments, Docker Engine 20.10+ and Docker Compose v2 are required.

---

## Installation

### Local (Development / Testing)

```bash
# 1. Clone and set up virtualenv
git clone <repo>
cd cnds
python3 -m venv venv
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure
cp .env.example .env
# Edit .env — see Configuration section

# 4. Place model files
# Copy rf_model.joblib, isolation_forest.joblib, lstm_autoencoder.pt to models/
# If models are unavailable, the system runs in rules-only mode

# 5. Run (live capture requires root)
sudo venv/bin/python main.py          # capture only
sudo venv/bin/python main.py --api    # capture + API on :8000

# 6. API only (no capture, no root required)
uvicorn src.api.main:app --host 0.0.0.0 --port 8000
```

### Docker Compose (Full Stack)

```bash
cp .env.example .env
# Edit .env

docker-compose up -d
```

**Services started:**

| Service | Container | Port | Description |
|---|---|---|---|
| `detector` | cnds-detector | — | Packet capture + detection pipeline |
| `api` | cnds-api | 8000 | FastAPI REST + WebSocket |
| `dashboard` | cnds-dashboard | 8501 | Streamlit real-time dashboard |

**Volume mounts:**
- `./models:/app/models` — shared model files (read-only for api/dashboard)
- `./data:/app/data` — SQLite database file (or mount a PostgreSQL socket)
- `./logs:/app/logs` — structured JSON logs

**Required environment in docker-compose.yml:**
```yaml
environment:
  - CAPTURE_INTERFACE=eth0
  - DATABASE_URL=sqlite+aiosqlite:///data/cnds.db
```

For the detector container to capture live traffic, it needs host network access:
```yaml
detector:
  network_mode: host    # required for raw socket access
  cap_add:
    - NET_RAW
    - NET_ADMIN
```

---

## Configuration

All configuration is via environment variables, typically loaded from a `.env` file. `src/config.py` validates all required values on import.

### Core Variables

```bash
# ── Capture ─────────────────────────────────────────────────────────────
CAPTURE_INTERFACE=eth0          # Network interface (auto-detect if empty)
PACKET_WORKERS=4                # Worker threads for packet processing
PACKET_QUEUE_SIZE=10000         # Bounded queue size (packets; drop when full)

# ── Flow Analysis ────────────────────────────────────────────────────────
FLOW_TIMEOUT=120                # Seconds before an inactive flow is flushed
MAX_ACTIVE_FLOWS=50000          # Max concurrent tracked flows
MIN_PACKETS_FOR_ML=5            # Min flow packets before sending to ML engines
ACTIVE_IDLE_THRESH=5.0          # Seconds to split active/idle periods

# ── Host Analysis ────────────────────────────────────────────────────────
HOST_WINDOW_SIZE=100            # Sliding window size (packets) per tracked IP
MAX_TRACKED_IPS=5000            # LRU eviction ceiling for host state

# ── Detection Ensemble ───────────────────────────────────────────────────
WEIGHT_SUPERVISED=0.40
WEIGHT_IFOREST=0.30
WEIGHT_LSTM=0.20
WEIGHT_RULES=0.10
ENSEMBLE_THRESHOLD=0.55         # Score above which is_anomaly=True
CALIBRATION_TEMPERATURE=1.0     # Temperature scaling (1.0 = no-op)

# Per-attack-type weight overrides (JSON)
# ATTACK_TYPE_WEIGHTS={"PortScan": {"rules": 0.4, "supervised": 0.4, "iforest": 0.2, "lstm": 0.0}}

# ── Rules Engine ─────────────────────────────────────────────────────────
ICMP_FLOOD_THRESHOLD=100        # ICMP packets/second threshold
PORT_SCAN_THRESHOLD=50          # SYN count threshold
LARGE_PAYLOAD_BYTES=65000       # Payload size threshold

# ── Models ───────────────────────────────────────────────────────────────
MODELS_DIR=models
RF_MODEL_FILE=rf_model.joblib
IF_MODEL_FILE=isolation_forest.joblib
LSTM_MODEL_FILE=lstm_autoencoder.pt
LSTM_CONFIG_FILE=lstm_config.json

# ── Database ─────────────────────────────────────────────────────────────
DATABASE_URL=sqlite+aiosqlite:///cnds.db
# Production: DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/cnds

# ── API ──────────────────────────────────────────────────────────────────
API_HOST=0.0.0.0
API_PORT=8000
CORS_ORIGINS=http://localhost:3000

# ── Authentication ───────────────────────────────────────────────────────
JWT_SECRET=change-me-in-production
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=60

# ── Enrichment ───────────────────────────────────────────────────────────
GEOIP_DB_PATH=                  # Path to GeoLite2-City.mmdb (empty = disabled)
CORRELATION_WINDOW_SECS=300     # Incident grouping window
CORRELATION_THRESHOLD=5         # Alerts per IP before auto-incident

# ── Notifications ────────────────────────────────────────────────────────
WEBHOOK_URLS=                   # Space-separated list of webhook URLs
NOTIFY_MIN_SEVERITY=medium
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

# ── Observability ────────────────────────────────────────────────────────
PROMETHEUS_ENABLED=true
OTEL_EXPORTER_OTLP_ENDPOINT=    # http://otel-collector:4318 (empty = disabled)
LOG_FORMAT=json                  # json or text

# ── Alert Behavior ───────────────────────────────────────────────────────
DEDUP_WINDOW_SECS=60            # Suppress repeat (src_ip, attack_type) within window
CONFIDENCE_DECAY_FACTOR=0.9     # Score multiplier per repeat alert
ALERT_COOLDOWN_SECS=30          # Min seconds between alerts from same IP

# ── IP Filtering ─────────────────────────────────────────────────────────
IP_ALLOWLIST=                   # IPs or CIDR ranges; skip detection entirely
IP_BLOCKLIST=                   # IPs or CIDR ranges; auto-flag all traffic

# Trusted outbound (JSON): skip detection for specific src→domain pairs
# TRUSTED_OUTBOUND={"192.168.1.60": ["relay.synology.com"]}

# ── JA3 ──────────────────────────────────────────────────────────────────
JA3_ENABLED=true
MALICIOUS_JA3_FILE=             # Path to file with one JA3 hash per line

# ── MLflow ───────────────────────────────────────────────────────────────
MLFLOW_TRACKING_URI=            # Empty = use local model files
MLFLOW_REGISTRY_NAME=cnds

# ── Adaptive Weights ─────────────────────────────────────────────────────
ADAPTIVE_WEIGHTS_ENABLED=false
ADAPTIVE_MIN_SAMPLES=100

# ── Rate Limiting ────────────────────────────────────────────────────────
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60

# ── DNS Logging ──────────────────────────────────────────────────────────
DNS_LOGGING_ENABLED=false
```

---

## Database Setup

### SQLite (Development / Single Node)

```bash
DATABASE_URL=sqlite+aiosqlite:///cnds.db
```

Alembic migrations run automatically at startup. No setup required.

**Limitations:** Single writer only. If the detector and API run in separate processes, SQLite WAL mode handles concurrent reads but not concurrent writes. Use PostgreSQL in production.

### PostgreSQL (Production)

```bash
DATABASE_URL=postgresql+asyncpg://cnds:password@localhost:5432/cnds
```

```sql
-- Create database and user
CREATE USER cnds WITH PASSWORD 'password';
CREATE DATABASE cnds OWNER cnds;
```

Alembic migrations run automatically at startup. To run manually:
```bash
alembic upgrade head
```

---

## Running Database Migrations

```bash
# Apply all pending migrations
alembic upgrade head

# Check current version
alembic current

# Generate a new migration after model changes
alembic revision --autogenerate -m "add_new_column"

# Roll back one step
alembic downgrade -1
```

Migration files are in `alembic/versions/`. The two existing migrations are:
- `72da55e575e8_initial_schema.py` — Core tables (alerts, incidents, suppression_rules, users).
- `a1b2c3d4e5f6_add_mitre_techniques.py` — Adds `mitre_techniques` JSON column to alerts.

---

## Model Files

Binary model files are not distributed with the repository. They must be obtained or trained separately.

| File | Size (approx.) | Training required |
|---|---|---|
| `models/rf_model.joblib` | 50–200 MB | CIC-IDS2017 labeled flow data |
| `models/isolation_forest.joblib` | 10–50 MB | Normal traffic baseline |
| `models/if_scaler.joblib` | < 1 MB | Same baseline as IF model |
| `models/lstm_autoencoder.pt` | 5–50 MB | Normal traffic sequence data |
| `models/lstm_config.json` | < 1 KB | Tracked in git |

If models are absent, CNDS starts in **rules-only mode**. The `/health` endpoint shows which engines are unavailable:
```json
{"engines": {"supervised": false, "isolation_forest": false, "lstm": false, "rules": true}}
```

### Loading models from MLflow

```bash
MLFLOW_TRACKING_URI=http://mlflow-server:5000
MLFLOW_REGISTRY_NAME=cnds
```

CNDS will attempt to load registered model versions from the registry instead of local files. Falls back to local files if registry is unreachable.

---

## GeoIP Setup (Optional)

Download the free MaxMind GeoLite2-City database:

1. Create an account at maxmind.com.
2. Download `GeoLite2-City.mmdb`.
3. Set in `.env`:
```bash
GEOIP_DB_PATH=/path/to/GeoLite2-City.mmdb
```

GeoIP is optional. When the file is absent, `src_geo` is omitted from alerts.

---

## SIEM Integration Setup

### Splunk

1. Enable HEC on your Splunk instance.
2. Copy `siem/splunk/inputs.conf` to your Splunk forwarder.
3. Set in `.env`:
```bash
WEBHOOK_URLS=https://splunk-hec-host:8088/services/collector/event
# Use Authorization header in webhook config for HEC token
```

See `siem/splunk/README.md` for full Splunk setup.

### Elastic

1. Run the Logstash pipeline in `siem/elastic/logstash-pipeline.conf`.
2. Apply the index template: `curl -X PUT http://elastic:9200/_index_template/cnds-alerts -d @siem/elastic/index-template.json`.
3. Stream logs via Filebeat or push via webhook.

### CEF Syslog (QRadar / ArcSight / Sentinel)

```bash
python siem/syslog/forwarder.py --listen-port 5514 --target-host siem-server --target-port 514
```

---

## Production Hardening

### Authentication

1. Set a strong `JWT_SECRET` (32+ random bytes):
   ```bash
   openssl rand -hex 32
   ```
2. Create initial admin user via API on first startup:
   ```bash
   curl -X POST http://localhost:8000/api/auth/users \
     -H "X-API-Key: $INITIAL_API_KEY" \
     -d '{"username": "admin", "password": "strong-password", "role": "admin"}'
   ```
3. Disable legacy API key by removing `API_KEY` from `.env`.

### TLS

Run CNDS behind an nginx reverse proxy with TLS termination:

```nginx
server {
    listen 443 ssl;
    server_name cnds.internal;

    ssl_certificate /etc/ssl/cnds.crt;
    ssl_certificate_key /etc/ssl/cnds.key;

    location / {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

The `Upgrade` and `Connection` headers are required for WebSocket proxying.

### Resource Limits

For high-traffic networks, tune these values:
```bash
PACKET_WORKERS=8             # More workers for higher packet rates
PACKET_QUEUE_SIZE=50000      # Larger buffer for bursty traffic
MAX_ACTIVE_FLOWS=200000      # More flows for large networks
MAX_TRACKED_IPS=20000        # More host state for large networks
FLOW_TIMEOUT=60              # Shorter timeout to free state faster
```

Monitor the `/health` endpoint. If `dropped` count increases, add workers or increase queue size.

### Log Rotation

When `LOG_FORMAT=json`, logs go to stdout/stderr. In Docker:
```yaml
logging:
  driver: "json-file"
  options:
    max-size: "100m"
    max-file: "10"
```

For systemd deployments, logs go to journald by default.

---

## Periodic Cleanup

The API server runs a periodic cleanup task (configurable interval) that:
1. Removes alerts older than `ALERT_RETENTION_DAYS` (default: 90 days).
2. Deletes expired suppression rules.
3. Prunes DNS log entries beyond retention window.
4. Rebuilds SQLite WAL checkpoint (SQLite only).

This task runs in the background and requires no external cron setup.

---

## Systemd Service (Non-Docker)

```ini
# /etc/systemd/system/cnds.service
[Unit]
Description=Cognitive Network Defense System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/cnds
EnvironmentFile=/opt/cnds/.env
ExecStart=/opt/cnds/venv/bin/python main.py --api
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable cnds
sudo systemctl start cnds
sudo journalctl -u cnds -f
```

---

## Testing

```bash
# Full test suite
pytest tests/ -v --cov=src

# Single test
pytest tests/test_flow_extractor.py::TestFlowExtractor::test_basic_flow -v

# Specific modules
pytest tests/test_engines.py tests/test_ensemble.py -v

# With coverage report
pytest tests/ --cov=src --cov-report=html
# → Open htmlcov/index.html
```

**Test categories:**

| Module | Coverage |
|---|---|
| `test_flow_extractor.py` | FlowRecord lifecycle, 76-feature extraction |
| `test_host_extractor.py` | HostHistory sliding window, 18-feature computation |
| `test_engines.py` | Engine scoring, unavailability, mock models |
| `test_ensemble.py` | Weighted fusion, weight redistribution, calibration |
| `test_rules_engine.py` | All 6 rule types, threshold edge cases |
| `test_mitre.py` | Attack type → technique ID mapping |
| `test_ja3.py` | TLS ClientHello parsing, GREASE filtering |
| `test_payload_features.py` | Pattern matching, timeout protection |
| `test_enrichment.py` | Suppression, correlation, decay |
| `test_auth.py` | JWT issuance, role enforcement |
| `test_api.py` | REST endpoint behavior, pagination |
| `test_config.py` | Env var parsing, validation failures |
| `test_siem.py` | SIEM forwarder output format |

---

## Monitoring

### Key Metrics to Watch

| Metric | Normal Range | Action if Exceeded |
|---|---|---|
| `cnds_packets_dropped_total` | 0 | Increase `PACKET_WORKERS` or `PACKET_QUEUE_SIZE` |
| `cnds_active_flows` | < `MAX_ACTIVE_FLOWS` | Reduce `FLOW_TIMEOUT` or increase limit |
| `cnds_engine_latency_seconds{engine="lstm"}` | < 10ms | Check GPU availability; reduce `LSTM_SEQ_LEN` |
| `http_request_duration_seconds{endpoint="/api/alerts"}` | < 200ms | Add DB indexes; switch to PostgreSQL |
| `cnds_alerts_total{severity="critical"}` | Baseline-dependent | Investigate immediately |

### Health Check

```bash
curl http://localhost:8000/health
```

For load balancer / uptime monitoring, this endpoint returns HTTP 200 while the system is functional and HTTP 503 if all ML engines are unavailable and the rules engine is also failing.

### Dashboard

The Streamlit dashboard at `:8501` provides:
- Real-time alert feed (WebSocket-backed).
- Alert volume chart by hour/day.
- Severity distribution pie chart.
- Top attacking source IPs.
- MITRE technique frequency heatmap.
- Engine score distribution histograms.
- Active incident list.

---

## Upgrading

1. Pull new code.
2. Update dependencies: `pip install -r requirements.txt --upgrade`.
3. Run Alembic migrations: `alembic upgrade head`.
4. Restart the service.

Check `CHANGELOG.md` for breaking changes before upgrading major versions.
