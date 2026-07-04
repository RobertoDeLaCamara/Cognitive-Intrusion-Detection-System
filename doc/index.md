# CNDS Documentation Index

**Cognitive Network Defense System** — Real-time multi-engine network intrusion detection.

---

**New to CNDS? Start with the [Reading Guide](READING-GUIDE.md).**

---

## Documents

| File | Audience | Description |
|---|---|---|
| [concepts.md](concepts.md) | All audiences | MITRE ATT&CK, JA3, flows, ML algorithms, SIEM, JWT, Monitoring Service, attack types |
| [product.md](product.md) | Executives, PM, sales | Commercial purpose, value proposition, competitive positioning |
| [architecture.md](architecture.md) | Engineers, architects | System design, data flow, component responsibilities |
| [engines.md](engines.md) | ML engineers, security engineers | Detection engine overview, model specs, tuning |
| [ml-models.md](ml-models.md) | ML engineers, data scientists | Deep dive: feature engineering, training, retraining, calibration, ML Tracking |
| [api-reference.md](api-reference.md) | Integrators, developers | Complete REST + WebSocket API reference |
| [use-cases.md](use-cases.md) | SOC analysts, security architects | Operational use cases, attack scenarios, analyst workflows |
| [digital-twin-sandbox.md](digital-twin-sandbox.md) | Engineers, demo operators | Local network digital twin, offline demo, sandbox testing |
| [deployment.md](deployment.md) | DevOps, platform engineers | Installation, configuration, production operations |
| [ft_transformer_architecture.md](ft_transformer_architecture.md) | ML engineers | FT-Transformer internals: tokenizer, encoder blocks, forward pass diagram, hyperparameters, temperature scaling |
| [UNIFIED_FT_LIVE_RUNBOOK.md](UNIFIED_FT_LIVE_RUNBOOK.md) | Engineers, QA | Manual end-to-end test of the FT-Transformer engine on live traffic |

---

## System at a Glance

```
Raw Packets (Scapy)
       │
       ▼
 PacketProcessor (async queue, 4 workers)
       │
       ▼
   Dispatcher ──────────────────────────────────┐
       │                                         │
       ├── FlowExtractor (76 features)           │
       ├── HostExtractor (18 features)           │
       ├── PayloadAnalyzer (10 features)         │
       └── JA3 Fingerprinter                     │
                                                 │
       ▼                                         │
  Detection Engines                              │
  ├── Supervised (40%) ← 76 flow features       │
  │   ├── FT-Transformer (preferred, ~2.4M params)
  │   └── Random Forest (fallback when no FT ckpt)
  ├── Isolation Forest (30%) ← 18 host features │
  ├── LSTM Autoencoder (20%) ← temporal seq.    │
  └── Rules Engine (10%) ← all signals          │
                                                 │
       ▼                                         │
  Ensemble Scorer (weighted fusion)             │
       │                                         │
       ▼                                         │
  Enrichment Pipeline                            │
  ├── MITRE ATT&CK mapping                      │
  ├── GeoIP lookup                              │
  ├── Incident correlation                      │
  ├── Alert suppression / deduplication         │
  └── Confidence decay                          │
                                                 │
       ▼                                         │
  Alert Storage (SQLite / PostgreSQL)            │
       │                                         │
       ├── REST API (FastAPI :8000)              │
       ├── WebSocket stream (/ws/alerts)         │
       ├── Streamlit dashboard (:8501)           │
       ├── SIEM push (Splunk / Elastic / CEF)   │
       └── Guardian auto-response (optional)     │
           block src_ip → AdGuard DNS → rollback │
```

---

## Quick Start

```bash
# 1. Install dependencies
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Configure
cp .env.example .env
# Edit .env — set CAPTURE_INTERFACE, DATABASE_URL, model paths

# 3. Run (live capture requires root)
sudo python main.py --api      # capture + API on :8000

# 4. Run demo (no root, no models needed)
cd demo && python run_demo.py

# 5. Full stack with Docker
docker-compose up
```

## Version History

| Version | Notes |
|---|---|
| 1.2.0 | Guardian auto-response module (opt-in auto-block + whitelist + circuit breaker + timed rollback), PostgreSQL in default `docker-compose.yml`, per-service resource limits |
| 1.1.1 | `FT_TEMPERATURE` env var (default 2.0), ARM64 Docker support, scikit-learn<2.0 pin |
| 1.1.0 | Unified FT-Transformer supervised engine (F1 macro 0.6197), MLflow registry load, smoke test |
| 1.0.9 | Bundled RF lite model (1.6 MB), 3-tier model load chain |
| 1.0.3 | TRUSTED_OUTBOUND device profiles, periodic cleanup |
| 1.0.2 | MITRE ATT&CK mapping, JA3 TLS fingerprinting, SIEM integration |
| 1.0.1 | GeoIP pipeline, structured logging, API deduplication, engine protocol |
| 1.0.0 | Initial release — 4-engine ensemble, FastAPI, SQLite/PostgreSQL |
