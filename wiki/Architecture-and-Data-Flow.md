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
                ┌─────────────┴──────────────┐
                ▼                            ▼
    FastAPI REST API :8000         SIEM Integrations
    + WebSocket /ws/alerts         (Splunk HEC, Elastic,
    + Streamlit Dashboard :8501     Syslog-CEF :514)
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

`detector` uses host networking for direct packet access; communicates with `api` via `http://api:8000`.

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
| Prometheus | — | /metrics | Scrape endpoint on API |
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
