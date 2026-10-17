# CNDS — Cognitive Network Defense System

Real-time network intrusion detection system using a five-engine weighted ensemble (defaults from `src/config.py`): Supervised classifier (30 % — FT-Transformer when its checkpoint is present, Random Forest fallback otherwise), Isolation Forest (20 %), LSTM Autoencoder (10 %), rule-based heuristics (25 %) and the live-trained unsupervised Baseline engine (15 %), plus external threat-intel boosts and a `CRITICAL_RULES` override. Live Scapy packet capture → async worker queue → flow dispatcher → feature extractors → ensemble → MITRE ATT&CK enrichment → alert.

## Quick Start

```bash
cp .env.example .env
# Edit .env — set DATABASE_URL, interface, thresholds as needed

# Option A: Docker Compose (recommended; POSTGRES_PASSWORD must be set in .env)
docker-compose up

# Option B: local
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
sudo python main.py                    # live capture
sudo python main.py --api              # capture + API on :8000
uvicorn src.api.main:app --port 8000   # API only

# Model files are gitignored except the bundled lite Random Forest;
# see Getting Started and the Development Guide for the rest
```

## Stack

| Component | Technology | Port |
|-----------|-----------|------|
| Packet capture | Scapy (raw sockets, root required) | — |
| API | FastAPI + Uvicorn | 8000 |
| Dashboard | Streamlit (compose profile `dashboard`) | 8501 |
| Database | SQLite (default) / PostgreSQL (compose stack) | 5432 (compose, localhost only) |
| Metrics | Prometheus | /metrics |
| Tracing | OpenTelemetry (optional) | — |

## Wiki Pages

1. [Getting Started](Getting-Started.md), [Configuration](Configuration.md), [Deployment](Deployment.md)
2. [Architecture](Architecture.md) and [Architecture and Data Flow](Architecture-and-Data-Flow.md)
3. [Detection Engines](Detection-Engines.md), [Ensemble Scoring](Ensemble-Scoring.md), [Feature Extraction](Feature-Extraction.md), [ML Pipeline](ML-Pipeline.md)
4. [API Reference](API-Reference.md) and [REST API](REST-API.md)
5. [Alert Enrichment](Alert-Enrichment.md), [Enrichment and SIEM Integration](Enrichment-and-SIEM.md), [SIEM Integration](SIEM-Integration.md), [MITRE ATT&CK Mapping](MITRE-ATT&CK-Mapping.md)
6. [Development Guide](Development-Guide.md), [Testing](Testing.md), [CI/CD Pipeline](CI-CD-Pipeline.md), [Contributing](Contributing.md), [Changelog](Changelog.md)

## Key Layout

```
main.py                          entry point — capture + CLI
src/config.py                    100+ env vars with fail-fast validation
src/pipeline.py                  detection pipeline callback (flow → engines → alert)
src/capture/                     Scapy + async worker queue
src/features/                    flow (76), host (18), payload (10), JA3
src/engines/                     FT-Transformer / RF, IF, LSTM, rules, baseline
src/ensemble/scorer.py           weighted fusion + temperature scaling
src/enrichment/                  MITRE, GeoIP, correlation, notifications
src/guardian/                    optional auto-response: whitelist, circuit breaker, AdGuard block, rollback
src/api/                         FastAPI + JWT/RBAC + Prometheus + WebSocket
src/unsupervised/                live baseline collector + window trainer
src/mcp_server/, src/triage/     read-only MCP server and advisory triage agent (optional, out of process)
siem/                            Splunk, Elastic, Syslog-CEF templates
models/                          weights gitignored (bundled: rf_lite_model.joblib, lstm_config.json)
```

## Non-Obvious Facts

- Model files (`unified/unified_ft_transformer.pt`, `rf_model.joblib`, `isolation_forest.joblib`, `lstm_autoencoder.pt`) are gitignored and must be provided or trained separately; the bundled `rf_lite_model.joblib` keeps the supervised slot working out of the box. `torch` is not in `requirements.txt` (the Docker image installs the CPU build), so FT-Transformer, LSTM and baseline need it installed. The FT-Transformer also loads from the MLflow registry `ml-ids-unified-ft-transformer` when configured.
- SQLite does not support concurrent writers — use `DATABASE_URL=postgresql+asyncpg://...` in production.
- Live capture requires `root` or `CAP_NET_RAW`.
- Engine weights (all five, including `WEIGHT_BASELINE`) must sum to 1.0 ± 0.01; validation fails at import if misconfigured.
- The API refuses to start without `API_KEY`, `JWT_SECRET` or `AUTH_DISABLED=true`. `JWT_SECRET` protects only the routes that declare a role; see [API Reference](API-Reference.md#authentication).
- Trusted-outbound filtering skips detection for configured device→domain pairs entirely (DNS reverse lookup, 1h TTL cache).
- The optional Guardian module (`src/guardian/`, `GUARDIAN_ENABLED=false` by default) can auto-block critical alerts — but never put a broad LAN CIDR in `GUARDIAN_WHITELIST`, since that's exactly the range the detector monitors and would silently disable every auto-block.
