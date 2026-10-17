# Architecture & Data Flow

## Stack Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  Network Interface (Scapy raw sockets — requires root/CAP_NET_RAW)  │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PacketCapture + PacketProcessor                                     │
│  Bounded queue: 20 000 packets    Workers: 4 (configurable)          │
│  Non-blocking enqueue; dropped packets tracked                       │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Dispatcher  (src/capture/dispatcher.py)                             │
│  Fan-out per packet to all extractors simultaneously:                │
│  ├─ FlowExtractor    → 76 CICFlowMeter features (5-tuple flows)      │
│  ├─ HostExtractor    → 18 per-IP features (sliding window 100 pkts)  │
│  ├─ PayloadAnalyzer  → regex patterns + 10 numeric features          │
│  └─ JA3              → TLS ClientHello MD5 fingerprint               │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
               [flow idle > 120s — expiry callback]
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  on_flow_complete()  (src/pipeline.py)                                │
│  0. trusted-outbound filter; threat-intel IP / JA3 lookup           │
│  1. supervised.predict(flow_vec)           → (attack_type, conf)    │
│  2. isolation_forest.anomaly_score(host)   → [0,1]                  │
│  3. lstm.update(ip, host); .anomaly_score(ip) → [0,1]               │
│  4. baseline.update/anomaly_score(ip, host) → [0,1]                 │
│  5. rules.evaluate(record, flow_vec, payload, ja3) → (score, rules) │
│  6. ensemble.score(EngineScores)           → EnsembleResult          │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
              [score ≥ ENSEMBLE_THRESHOLD (0.55)]
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Deduplication check: (src_ip, attack_type) within 300s window      │
│  → if duplicate: drop silently                                       │
│  → if new: enqueue to async alert writer thread (capacity 1000)     │
│                                                                      │
│  Alert writer thread:                                                │
│  + GeoIP enrichment (MaxMind GeoLite2)                              │
│  + MITRE ATT&CK technique mapping                                    │
│  + Structured JSON logging                                           │
│  + SQLite / PostgreSQL persistence                                   │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
                ┌─────────────┬──────────────┐
                ▼              ▼              ▼
    FastAPI REST API :8000  SIEM Integrations  Guardian (optional)
    + WebSocket /ws/alerts  (Splunk HEC,       polls alerts table →
    + Streamlit Dashboard    Elastic,          block src_ip (AdGuard) →
      :8501                  Syslog-CEF :514)   auto-rollback timer
```

## Detection Cycle — Step by Step

Every time a flow expires (idle > `FLOW_TIMEOUT` seconds, default 120s):

```
1. FlowExtractor.flush_expired()
      └─ collect flow record (5-tuple + accumulated stats)
      └─ compute 76 CICFlowMeter features → np.ndarray[76]

2. HostExtractor.extract_features(src_ip)
      └─ sliding window last 100 packets for that IP
      └─ returns np.ndarray[18], or None if the IP has seen fewer than 3 packets

3. PayloadAnalyzer (per packet: analyze_payload; per flow: extract_payload_features)
      └─ 6 regex patterns (sql_injection, xss, command_injection, path_traversal,
         log4j, shellshock) matched directly on the first 4 KB, after a cheap pre-screen
      └─ analyze_payload → List[str] of pattern names; extract_payload_features → np.ndarray[10]

4. JA3.extract_ja3(tls_packet)
      └─ binary TLS ClientHello parse; GREASE values filtered (RFC 8701)
      └─ returns (ja3_hash, ja3_string), or None if not a ClientHello; the malicious flag comes from the known-bad hash list

5. Engine scoring (parallel conceptually, sequential in practice):
   supervised.predict(flow_vec ++ payload_features)
      → (attack_type: str, confidence: float [0,1])
   isolation_forest.anomaly_score(host_vec)
      → float [0,1]; None if model unavailable
   lstm.update(src_ip, host_vec); lstm.anomaly_score(src_ip)
      → float [0,1]; 0.0 until the per-IP buffer holds seq_len (20) vectors
   baseline.update(src_ip, host_vec); baseline.anomaly_score(src_ip, host_vec)
      → float [0,1]; engine unavailable until a baseline window has been trained
   rules.evaluate(record, flow_vec, payload_matches, ja3_info)
      → (score: float, triggered: List[str])

6. EnsembleScorer.score(EngineScores)
      └─ weighted sum: 0.30*Supervised + 0.20*IF + 0.10*LSTM + 0.25*Rules + 0.15*Baseline
         (defaults; WEIGHT_* env vars, must sum to 1.0)
      └─ if engine unavailable → redistribute weight proportionally
      └─ threat-intel hit → score + 0.30 (capped at 1.0)
      └─ any CRITICAL_RULES hit → score forced to 1.0 and is_anomaly
      └─ Platt temperature scaling: calibrated_score = sigmoid(logit/T)
      └─ returns EnsembleResult(score, is_anomaly, engine_scores, calibrated_score)

7. if is_anomaly (calibrated score ≥ ENSEMBLE_THRESHOLD 0.55, or a critical rule fired):
      └─ dedup check (src_ip, attack_type) within 300s
      └─ if new: enqueue to background writer
```

## Docker Compose Services

| Service | Network | Port | Notes |
|---------|---------|------|-------|
| api | bridge | 8000 | FastAPI + async DB writes |
| detector | host | — | Raw sockets (root required) |
| dashboard | bridge | 8501 | Streamlit; polls API. Opt-in: `--profile dashboard` |
| postgres | bridge | 127.0.0.1:5432 | Required — `api` and `detector` write concurrently, and SQLite has no concurrent-writer support. Needs `POSTGRES_PASSWORD` |
| demo-seed | bridge | — | One-shot synthetic data seeder. Opt-in: `--profile demo` |

`detector` uses `network_mode: host` for raw packet access. It writes alerts to the database **directly** via its own `DATABASE_URL` — not through the API's HTTP interface — because host networking means it can't resolve other containers' service names. Both `api` and `detector` must therefore point at the same PostgreSQL instance.

## Service Startup Order

```
PostgreSQL (healthy)
    ↓
API (healthy — /health returns 200)
    ↓
Detector (also waits for PostgreSQL) + Dashboard (profile `dashboard`)
```

## Network & Ports

| Service | Internal | External | Purpose |
|---------|----------|----------|---------|
| API | 8000 | 8000 | REST + WebSocket |
| Dashboard | 8501 | 8501 | Streamlit UI |
| Prometheus | — | /metrics | Scrape endpoint on API (`PROMETHEUS_ENABLED=true`) |
| Syslog-CEF | — | 514 UDP/TCP | SIEM forwarding (optional) |

## Async Alert Writer

Alerts are never written synchronously during detection:

```
Detection callback
    ↓ enqueue (non-blocking, drops if queue > 1000)
Bounded queue (capacity 1000)
    ↓
Background writer thread
    ↓ GeoIP lookup
    ↓ MITRE mapping
    ↓ SQLite/PostgreSQL INSERT (synchronous SQLAlchemy engine in the writer thread)
```

This ensures packet processing is never blocked by slow DB writes.

## Guardian Auto-Response (Optional)

```
Alerts table
    │
    ▼ poll every GUARDIAN_POLL_INTERVAL_SECS (default 15s)
guardian_loop()  (src/guardian/engine.py, runs inside the api container)
    ├─ severity < GUARDIAN_MIN_SEVERITY?           → skip
    ├─ src_ip matches GUARDIAN_WHITELIST?          → skip
    ├─ src_ip already has a PENDING action?        → skip
    ├─ circuit breaker tripped?                    → skip whole batch + notify once
    └─ else: MitigationBackend.block(src_ip)
             └─ AdGuardBackend: GET/POST AdGuard /control/access/{list,set}
             insert mitigation_actions row (status=PENDING, expires_at=+GUARDIAN_BLOCK_MINUTES)
             notify (Telegram inline buttons if TELEGRAM_BOT_TOKEN set, else plain notify_alert)

guardian_expiry_loop()  (same interval)
    └─ PENDING rows past expires_at → MitigationBackend.unblock() → status=EXPIRED
```

Off by default (`GUARDIAN_ENABLED=false`). Never hooks into the capture pipeline above — it only reads the `alerts` table. See [Configuration](Configuration.md) for env vars and [Deployment](Deployment.md) for the setup/safety checklist (especially: never put a broad LAN CIDR in `GUARDIAN_WHITELIST`).
