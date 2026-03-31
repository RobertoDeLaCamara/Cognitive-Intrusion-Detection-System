# Architecture

## High-Level Data Flow

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

## Key Design Decisions

- **Single capture loop** — one Scapy sniff loop feeds all four feature extractors, avoiding duplicate packet processing.
- **Async worker queue** — packets are dispatched to a configurable number of worker threads (`PACKET_WORKERS`, default 4) via a bounded queue (`PACKET_QUEUE_SIZE`, default 20,000).
- **Flow-based detection** — the dispatcher tracks bidirectional flows. When a flow expires (`FLOW_TIMEOUT` seconds of inactivity), all accumulated features are sent to the engines.
- **Graceful degradation** — any engine can be missing (no model file). Its weight is redistributed proportionally across the remaining active engines.
- **Dedicated DB writer** — alert persistence uses a separate writer thread with a bounded queue so packet workers are never blocked on I/O.

## Component Map

```
src/
├── config.py                 # Env-var driven settings, validated on startup
├── pipeline.py               # Detection pipeline callback (flow → engines → alert)
├── capture/
│   ├── packet_capture.py     # Scapy sniff + async worker queue
│   └── dispatcher.py         # Flow tracking, expiry, fan-out to extractors
├── features/
│   ├── flow_extractor.py     # 76 CICFlowMeter features per flow
│   ├── host_extractor.py     # 18 per-IP host features
│   ├── payload_analyzer.py   # Regex patterns + 10 numeric payload features
│   ├── ja3.py                # JA3 TLS fingerprint extraction
│   └── utils.py              # Shared helpers (byte_entropy, etc.)
├── engines/
│   ├── protocol.py           # DetectionEngine Protocol interface
│   ├── registry.py           # Shared engine singletons
│   ├── supervised.py         # Random Forest wrapper
│   ├── isolation_forest.py   # Isolation Forest wrapper
│   ├── lstm_autoencoder.py   # LSTM Autoencoder wrapper
│   ├── lstm_model.py        # LSTM Autoencoder architecture (nn.Module)
│   └── rules.py              # Rule-based engine (incl. JA3 rules)
├── ensemble/
│   └── scorer.py             # Weighted fusion → EnsembleResult
├── enrichment/               # Post-scoring enrichment modules
│   ├── mitre.py              # MITRE ATT&CK technique mapping
│   ├── geoip.py              # MaxMind GeoIP lookup
│   ├── correlation.py        # Auto-group alerts into incidents
│   ├── adaptive_weights.py   # Feedback-driven weight tuning
│   ├── suppression.py        # Temporary alert suppression rules
│   ├── notifications.py      # Webhook / Slack / Telegram
│   ├── confidence_decay.py   # Exponential score decay for repeat alerts
│   ├── ip_lists.py           # IP allowlist / blocklist
│   └── dns_logger.py         # DNS query logging
├── api/                      # FastAPI application
│   ├── main.py               # App factory, startup hooks, middleware
│   ├── models.py             # SQLAlchemy ORM (Alert, Incident, etc.)
│   ├── schemas.py            # Pydantic request/response models
│   ├── database.py           # Async session + Alembic migration
│   ├── auth.py               # JWT + RBAC
│   ├── metrics.py            # Prometheus + OpenTelemetry
│   ├── rate_limit.py         # Per-IP rate limiting
│   └── routers/              # Route modules (predict, alerts, auth, ws)
└── mlflow_registry.py        # Unified MLflow model registry
```
