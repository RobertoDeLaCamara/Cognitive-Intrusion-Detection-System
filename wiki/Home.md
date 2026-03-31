# CNDS — Cognitive Network Defense System

Real-time network intrusion detection system using a four-engine weighted ensemble: Random Forest (40%), Isolation Forest (30%), LSTM Autoencoder (20%), and rule-based heuristics (10%). Live Scapy packet capture → async worker queue → flow dispatcher → feature extractors → ensemble → MITRE ATT&CK enrichment → alert.

## Quick Start

```bash
cp .env.example .env
# Edit .env — set DATABASE_URL, interface, thresholds as needed

# Option A: Docker Compose (recommended)
docker-compose up

# Option B: local
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
sudo python main.py                    # live capture
sudo python main.py --api              # capture + API on :8000
uvicorn src.api.main:app --port 8000   # API only

# Train models first (model files are gitignored)
# See Development Guide
```

## Stack

| Component | Technology | Port |
|-----------|-----------|------|
| Packet capture | Scapy (raw sockets, root required) | — |
| API | FastAPI + Uvicorn | 8000 |
| Dashboard | Streamlit | 8501 |
| Database | SQLite (default) / PostgreSQL | — |
| Metrics | Prometheus | /metrics |
| Tracing | OpenTelemetry (optional) | — |

## Wiki Pages

1. [Architecture and Data Flow](Architecture-and-Data-Flow.md)
2. [ML Pipeline](ML-Pipeline.md)
3. [API Reference](API-Reference.md)
4. [Enrichment and SIEM Integration](Enrichment-and-SIEM.md)
5. [Development Guide](Development-Guide.md)

## Key Layout

```
main.py                          entry point — capture + CLI
src/config.py                    70+ env vars with fail-fast validation
src/pipeline.py                  detection pipeline callback (flow → engines → alert)
src/capture/                     Scapy + async worker queue
src/features/                    flow (76), host (18), payload (10), JA3
src/engines/                     RF, IF, LSTM, rules
src/ensemble/scorer.py           weighted fusion + temperature scaling
src/enrichment/                  MITRE, GeoIP, correlation, notifications
src/api/                         FastAPI + JWT/RBAC + Prometheus + WebSocket
siem/                            Splunk, Elastic, Syslog-CEF templates
models/                          gitignored — must train separately
```

## Non-Obvious Facts

- Model files (`rf_model.joblib`, `isolation_forest.joblib`, `lstm_autoencoder.pt`) are gitignored and must be provided or trained separately.
- SQLite does not support concurrent writers — use `DATABASE_URL=postgresql+asyncpg://...` in production.
- Live capture requires `root` or `CAP_NET_RAW`.
- Engine weights must sum to 1.0 ± 0.01; validation fails at import if misconfigured.
- Trusted-outbound filtering skips detection for configured device→domain pairs entirely (DNS reverse lookup, 1h TTL cache).
