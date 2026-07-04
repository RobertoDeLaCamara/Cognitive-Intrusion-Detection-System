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
│  1. supervised.predict(flow_vec)           → (attack_type, conf)    │
│  2. isolation_forest.anomaly_score(host)   → [0,1]                  │
│  3. lstm.update(ip, host); .score(ip)      → [0,1]                  │
│  4. rules.evaluate(record, payload, ja3)   → (score, rules_fired)   │
│  5. ensemble.score(EngineScores)           → EnsembleResult          │
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
      └─ returns np.ndarray[18] or None if < 10 packets

3. PayloadAnalyzer.analyze(payloads)
      └─ 30+ regex patterns (SQLi, XSS, cmd injection, shells, dir traversal)
      └─ each pattern runs in daemon thread with 1s timeout (ReDoS protection)
      └─ returns (triggered_rules: List[str], features: np.ndarray[10])

4. JA3.extract(tls_packet)
      └─ binary TLS ClientHello parse; GREASE values filtered (RFC 8701)
      └─ returns (hash: str, is_malicious: bool)

5. Engine scoring (parallel conceptually, sequential in practice):
   supervised.predict(flow_vec ++ payload_features)
      → (attack_type: str, confidence: float [0,1])
   isolation_forest.anomaly_score(host_vec)
      → float [0,1]; None if model unavailable
   lstm.update(src_ip, host_vec); lstm.anomaly_score(src_ip)
      → float [0,1]; None if buffer < seq_len
   rules.evaluate(record, payload_matches, ja3_info)
      → (score: float, triggered: List[str])

6. EnsembleScorer.score(EngineScores)
      └─ weighted sum: 0.40*RF + 0.30*IF + 0.20*LSTM + 0.10*Rules
      └─ if engine unavailable → redistribute weight proportionally
      └─ Platt temperature scaling: calibrated_score = sigmoid(logit/T)
      └─ returns EnsembleResult(score, is_anomaly, engine_scores, calibrated_score)

7. if is_anomaly (score ≥ 0.55):
      └─ dedup check (src_ip, attack_type) within 300s
      └─ if new: enqueue to background writer
```

## Docker Compose Services

| Service | Network | Port | Notes |
|---------|---------|------|-------|
| api | bridge | 8000 | FastAPI + async DB writes |
| detector | host | — | Raw sockets (root required) |
| dashboard | bridge | 8501 | Streamlit; polls API |
| postgres | bridge | 5432 (internal) | Required — `api` and `detector` write concurrently, and SQLite has no concurrent-writer support |

`detector` uses `network_mode: host` for raw packet access. It writes alerts to the database **directly** via its own `DATABASE_URL` — not through the API's HTTP interface — because host networking means it can't resolve other containers' service names. Both `api` and `detector` must therefore point at the same PostgreSQL instance.

## Service Startup Order

```
PostgreSQL (healthy)
    ↓
API (healthy — /health returns 200)
    ↓
Detector + Dashboard
```

## Network & Ports

| Service | Internal | External | Purpose |
|---------|----------|----------|---------|
| API | 8000 | 8000 | REST + WebSocket |
| Dashboard | 8501 | 8501 | Streamlit UI |
| Monitoring Service | — | /metrics | Scrape endpoint on API |
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
    ↓ SQLite/PostgreSQL INSERT
    ↓ JSON log append
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

Off by default (`GUARDIAN_ENABLED=false`). Never hooks into the capture pipeline above — it only reads the `alerts` table. See [Configuration](Configuration) for env vars and [Deployment](Deployment) for the setup/safety checklist (especially: never put a broad LAN CIDR in `GUARDIAN_WHITELIST`).
