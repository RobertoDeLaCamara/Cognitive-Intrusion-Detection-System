# CNDS — System Architecture

## Overview

CNDS is structured as a linear pipeline: capture → feature extraction → detection → enrichment → storage/delivery, with an optional auto-response stage (Guardian) layered on top. Each stage is independently modular, communicates through well-defined interfaces, and can be replaced or extended without touching adjacent stages.

---

## High-Level Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Network Interface                           │
│                    (Scapy raw socket / PCAP)                        │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ raw packets
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    PacketCapture (daemon thread)                    │
│          Scapy sniff() → bounded async queue (FIFO)                 │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│              PacketProcessor (4 worker threads, default)            │
│           Dequeue → Dispatcher.process_packet()                     │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              │                           │
              ▼                           ▼
  ┌───────────────────────┐   ┌──────────────────────────┐
  │  FlowExtractor        │   │  HostExtractor           │
  │  76 CICFlowMeter      │   │  18 per-IP aggregate     │
  │  features per flow    │   │  features (sliding win)  │
  └──────────┬────────────┘   └───────────┬──────────────┘
             │                            │
             ▼                            ▼
  ┌───────────────────────┐   ┌──────────────────────────┐
  │  PayloadAnalyzer      │   │  JA3 Fingerprinter       │
  │  6 pattern flags +    │   │  TLS ClientHello → MD5   │
  │  10 numeric features  │   │  hash + string           │
  └──────────┬────────────┘   └───────────┬──────────────┘
             │                            │
             └──────────┬─────────────────┘
                        │ feature vectors
                        ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        Detection Engines                            │
│                                                                     │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │ Supervised       │  │ Isolation Forest │  │ LSTM Autoencoder │  │
│  │ weight: 40%      │  │ weight: 30%      │  │ weight: 20%      │  │
│  │ 76 flow features │  │ 18 host features │  │ 20-step seq/IP   │  │
│  │ 10 attack types  │  │ anomaly score    │  │ reconstruction   │  │
│  │ FT-T preferred / │  │                  │  │                  │  │
│  │ RF fallback      │  │                  │  │                  │  │
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘  │
│           │                     │                     │            │
│           │            ┌────────┘                     │            │
│           │            │            ┌─────────────────┘            │
│           │            │            │  ┌──────────────────┐        │
│           │            │            │  │ Rules Engine     │        │
│           │            │            │  │ weight: 10%      │        │
│           │            │            │  │ 6 heuristic rules│        │
│           │            │            │  └────────┬─────────┘        │
└───────────┼────────────┼────────────┼───────────┼──────────────────┘
            │            │            │           │
            └────────────┴──────┬─────┘───────────┘
                                │ EngineScores
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       EnsembleScorer                                │
│                                                                     │
│  • Weighted average with dynamic weight redistribution              │
│  • Per-attack-type weight overrides (JSON config)                   │
│  • Temperature scaling (Platt-style confidence calibration)         │
│  • Threshold: ENSEMBLE_THRESHOLD (default 0.55)                     │
│  • Severity mapping: low / medium / high / critical                 │
└────────────────────────────┬────────────────────────────────────────┘
                             │ EnsembleResult (if score ≥ threshold)
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Enrichment Pipeline                            │
│                                                                     │
│  ┌─────────────┐  ┌──────────┐  ┌────────────────┐  ┌───────────┐  │
│  │ MITRE       │  │ GeoIP    │  │ Deduplication  │  │ Suppres-  │  │
│  │ ATT&CK map  │  │ lookup   │  │ + decay        │  │ sion rules│  │
│  └─────────────┘  └──────────┘  └────────────────┘  └───────────┘  │
│  ┌─────────────┐  ┌──────────┐  ┌────────────────┐                 │
│  │ Incident    │  │ Adaptive │  │ Notifications  │                 │
│  │ correlation │  │ weights  │  │ webhook/TG     │                 │
│  └─────────────┘  └──────────┘  └────────────────┘                 │
└────────────────────────────┬────────────────────────────────────────┘
                             │
               ┌─────────────┼──────────────────┐
               ▼             ▼                  ▼
    ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐
    │  SQLite /    │  │  WebSocket   │  │  SIEM Push      │
    │  PostgreSQL  │  │  /ws/alerts  │  │  Splunk / ELK   │
    │  (async)     │  │  (JWT auth)  │  │  / CEF Syslog   │
    └──────────────┘  └──────────────┘  └─────────────────┘
               │
               ▼
    ┌──────────────────┐  ┌─────────────────────┐
    │  FastAPI REST    │  │  Streamlit Dashboard │
    │  :8000           │  │  :8501               │
    └──────────────────┘  └─────────────────────┘
               │
               ▼ (polls alerts table, opt-in)
    ┌────────────────────────────────────────────┐
    │  Guardian (src/guardian/) — optional        │
    │  whitelist → circuit breaker → block via    │
    │  MitigationBackend (AdGuard DNS) → timer    │
    │  auto-rollback → mitigation_actions table   │
    └────────────────────────────────────────────┘
```

---

## Component Reference

### Capture Layer (`src/capture/`)

#### `PacketCapture`
- Wraps Scapy `sniff()` in a daemon thread.
- Writes raw `scapy.Packet` objects to a bounded FIFO queue.
- Queue size configurable via `PACKET_QUEUE_SIZE` (default: 10,000).
- Dropped-packet counter exposed for monitoring.

#### `PacketProcessor`
- Spins up `PACKET_WORKERS` (default: 4) threads, each pulling from the queue.
- Non-blocking dequeue with 0.5 s timeout to allow clean shutdown.
- Calls `Dispatcher.process_packet()` synchronously per packet.
- Tracks active worker count and total processed/dropped packets.

#### `Dispatcher`
- Per-packet fan-out to FlowExtractor, HostExtractor, PayloadAnalyzer, JA3.
- Maintains per-(src_ip, dst_ip, sport, dport, protocol) flow state.
- Flushes flows older than `FLOW_TIMEOUT` seconds (default: 120) periodically.
- LRU eviction for payload matches and JA3 cache when ceilings are hit.
- Passes completed feature vectors to the engine pipeline.

---

### Feature Extraction Layer (`src/features/`)

#### `FlowExtractor` — 76 CICFlowMeter Features
The authoritative feature set for supervised classification, mirroring the CIC-IDS2017 dataset schema.

**Tracked per bidirectional flow:**

| Category | Features |
|---|---|
| Duration | `flow_duration` |
| Forward (client→server) | `tot_fwd_pkts`, `tot_len_fwd_pkts`, `fwd_pkt_len_max/min/mean/std` |
| Backward (server→client) | `tot_bwd_pkts`, `tot_len_bwd_pkts`, `bwd_pkt_len_max/min/mean/std` |
| Flow-level rates | `flow_byts_s`, `flow_pkts_s` |
| Inter-arrival times | `flow_iat_mean/std/max/min`, `fwd_iat_tot/mean/std/max/min`, `bwd_iat_*` |
| TCP flags | `fwd_psh_flags`, `bwd_psh_flags`, `fwd_urg_flags`, `bwd_urg_flags`, `fin/syn/rst/pst/ack/urg/cwe/ece_flag_cnt` |
| Header lengths | `fwd_header_len`, `bwd_header_len` |
| Subflow | `subflow_fwd_pkts`, `subflow_fwd_byts`, `subflow_bwd_pkts`, `subflow_bwd_byts` |
| Bulk transfer | `fwd/bwd_blk_rate_avg`, `fwd/bwd_seg_size_avg` |
| Init window | `init_fwd_win_byts`, `init_bwd_win_byts` |
| Active/Idle | `active_mean/std/max/min`, `idle_mean/std/max/min` |
| Misc | `fwd_act_data_pkts`, `fwd_seg_size_min`, `pkt_size_avg`, `down_up_ratio` |

Flow key: `(src_ip, dst_ip, src_port, dst_port, protocol)`. Forward/backward direction determined by first-seen packet.

#### `HostExtractor` — 18 Per-IP Features
Aggregated behavioral fingerprint per source IP using a sliding window of the last `HOST_WINDOW_SIZE` (default: 100) packets.

| # | Feature | Description |
|---|---|---|
| 0 | `packet_rate` | Packets per second |
| 1 | `byte_rate` | Bytes per second |
| 2 | `avg_packet_size` | Mean packet size |
| 3 | `packet_size_variance` | Size variance |
| 4 | `total_packets` | Window packet count |
| 5 | `total_bytes` | Window byte count |
| 6 | `iat_mean` | Inter-arrival time mean |
| 7 | `iat_std` | Inter-arrival time std |
| 8 | `burst_rate` | Packet bursts per second |
| 9 | `session_duration` | Time since first packet |
| 10 | `tcp_ratio` | Fraction of TCP packets |
| 11 | `udp_ratio` | Fraction of UDP packets |
| 12 | `icmp_ratio` | Fraction of ICMP packets |
| 13 | `unique_ports` | Distinct destination ports |
| 14 | `uncommon_port_ratio` | Ports > 1024 / total |
| 15 | `avg_entropy` | Mean payload byte entropy |
| 16 | `avg_payload_size` | Mean payload length |
| 17 | `payload_size_variance` | Payload size variance |

#### `PayloadAnalyzer` — 10 Numeric Features + 6 Pattern Flags
Examines raw packet payload bytes for injection signatures and statistical indicators.

**Pattern flags (indices 0–5):**

| Index | Pattern | Target Attack |
|---|---|---|
| 0 | SQL injection regex | SQLi |
| 1 | XSS payload regex | Cross-site scripting |
| 2 | Command injection regex | OS command injection |
| 3 | Path traversal regex | Directory traversal |
| 4 | Log4J JNDI regex | CVE-2021-44228 |
| 5 | Shellshock regex | CVE-2014-6271 |

**Numeric features (indices 6–9):**
- Index 6: Distinct pattern types matched
- Index 7: Maximum payload entropy across samples
- Index 8: Mean payload length
- Index 9: Suspicious character ratio

Pattern matching is timeout-protected (1 s per pattern via threading) to prevent regex catastrophic backtracking from stalling the capture pipeline. A cheap pre-screen regex runs before the full pattern set.

#### `JA3` — TLS ClientHello Fingerprinting
Parses TLS record layer (type 22, handshake type 1) to extract:
- TLS version
- Cipher suite list (GREASE filtered per RFC 8701)
- Extension type list
- Elliptic curve groups
- EC point formats

MD5 hash of the canonical string becomes the JA3 fingerprint. Optionally compared against a malicious-hash file. Stored on every alert as `ja3_hash` + `ja3_string` columns.

---

### Detection Engine Layer (`src/engines/`)

See [engines.md](engines.md) for full engine documentation.

**Interface contract** (`src/engines/protocol.py`):

```python
class DetectionEngine(Protocol):
    @property
    def is_available(self) -> bool: ...

    def score(self, features: np.ndarray) -> tuple[float, str | None]: ...
```

Every engine exposes `is_available` (graceful degradation when model files are absent) and `score()` returning `(confidence: float [0,1], attack_type: str | None)`.

**Engine singletons** (`src/engines/registry.py`): Engines are loaded once at startup and shared across all worker threads. The registry checks availability flags to skip absent models rather than crashing.

---

### Ensemble Layer (`src/ensemble/scorer.py`)

#### `EngineScores` (dataclass)
```
supervised_score: float
iforest_score: float
lstm_score: float
rules_score: float
attack_type: str | None      # from supervised engine
triggered_rules: list[str]   # from rules engine
```

#### Scoring Algorithm

1. **Collect available scores**: Engines that return `is_available=False` are excluded.
2. **Dynamic weight redistribution**: Base weights `{supervised: 0.40, iforest: 0.30, lstm: 0.20, rules: 0.10}` are re-normalized across available engines only.
3. **Per-attack-type overrides**: If `ATTACK_TYPE_WEIGHTS` env var contains a JSON mapping for the detected attack type, those weights replace the base weights.
4. **Weighted average**: `raw_score = Σ(weight_i × score_i) / Σ(weight_i)`.
5. **Temperature scaling**: `calibrated = sigmoid(logit(raw_score) / CALIBRATION_TEMPERATURE)`. Default temperature = 1.0 (no-op).
6. **Threshold gate**: If `calibrated_score >= ENSEMBLE_THRESHOLD` (default 0.55), `is_anomaly = True`.
7. **Severity mapping**:
   - `< 0.55` → not an alert
   - `0.55 – 0.70` → `low`
   - `0.70 – 0.80` → `medium`
   - `0.80 – 0.90` → `high`
   - `≥ 0.90` → `critical`

---

### Enrichment Layer (`src/enrichment/`)

#### MITRE ATT&CK Mapping (`mitre.py`)
- 14 supervised attack types → technique IDs
- 11 rule triggers → technique IDs
- Technique list deduplicated and stored as JSON on the alert

| Attack Type | MITRE Technique |
|---|---|
| DoS Hulk | T1498 — Network Denial of Service |
| DoS GoldenEye | T1498 |
| DoS Slowloris | T1499 — Endpoint Denial of Service |
| DoS Slowhttptest | T1499 |
| PortScan | T1046 — Network Service Scanning |
| FTP-Patator | T1110 — Brute Force |
| SSH-Patator | T1110 |
| Bot | T1071 — Application Layer Protocol |
| Infiltration | T1190 — Exploit Public-Facing Application |
| Web Attack – Brute Force | T1110.001 |
| Web Attack – XSS | T1059.007 |
| Web Attack – SQL Injection | T1190 |
| Heartbleed | T1203 — Exploitation for Client Execution |

#### Alert Deduplication (`src/pipeline.py`)
- In-memory LRU cache keyed by `(src_ip, attack_type)`.
- TTL: `DEDUP_WINDOW_SECS` (default: 60 s).
- Prevents alert storms from high-frequency attacks.

#### Confidence Decay (`confidence_decay.py`)
- Exponential score reduction for repeat alerts from the same source.
- Factor: `CONFIDENCE_DECAY_FACTOR` (default: 0.9 per repeat within window).
- Decayed alerts may fall below threshold and not fire.

#### Alert Suppression (`suppression.py`)
- Suppression rules stored in database, cached in memory with 10-second TTL.
- Cache invalidated on rule create/delete.
- Match criteria: `src_ip`, `dst_ip`, `attack_type`, `min_severity`, optional expiry.
- Rules checked before DB insertion; matching alerts are silently dropped.

#### Incident Correlation (`correlation.py`)
- When a source IP generates `CORRELATION_THRESHOLD` (default: 5) alerts within `CORRELATION_WINDOW_SECS` (default: 300 s), a new incident is auto-created and subsequent alerts are linked to it.

#### Adaptive Weights (`adaptive_weights.py`)
- Analysts label alerts as true positive or false positive via `PATCH /api/alerts/{id}`.
- When `ADAPTIVE_WEIGHTS_ENABLED=true` and `ADAPTIVE_MIN_SAMPLES` is reached, the system computes new engine weights from TP/FP rates.
- New weights applied to `EnsembleScorer` until next recomputation.

#### GeoIP (`geoip.py`)
- MaxMind GeoLite2-City database.
- Caches `src_ip → {country, city, latitude, longitude}`.
- Stored in `src_geo` JSON column on alert.
- Optional: disabled when `GEOIP_DB_PATH` is empty.

#### Notifications (`notifications.py`)
- Webhook push: POST JSON alert to all `WEBHOOK_URLS` (space-separated list).
- Telegram: Send message to `TELEGRAM_CHAT_ID` via `TELEGRAM_BOT_TOKEN`.
- Minimum severity gate: `NOTIFY_MIN_SEVERITY` (default: `medium`).

---

### API Layer (`src/api/`)

#### `FastAPI` Application (`src/api/main.py`)
- Lifespan context manager: initializes DB, starts periodic cleanup task.
- CORS middleware (configured via `CORS_ORIGINS`).
- Optional legacy API-key auth via `X-API-Key` header.
- Monitoring Service exporter at `/metrics`.
- OpenTelemetry tracing via `OTEL_EXPORTER_OTLP_ENDPOINT`.
- Per-IP rate limiting: `RATE_LIMIT_REQUESTS` per `RATE_LIMIT_WINDOW` seconds.

#### Authentication (`auth.py`)
- JWT tokens issued at `POST /api/auth/token`.
- Three roles: `admin`, `analyst`, `viewer`.
- Role requirements per endpoint are enforced as FastAPI dependency functions.
- Passwords stored as bcrypt hashes.

#### Database (`database.py`)
- Async SQLAlchemy sessions for non-blocking DB I/O.
- Supports both `sqlite+aiosqlite://` (dev) and `postgresql+asyncpg://` (prod).
- Alembic migrations in `alembic/versions/`.

See [api-reference.md](api-reference.md) for full endpoint documentation.

---

### Guardian Auto-Response Layer (`src/guardian/`)

Opt-in (`GUARDIAN_ENABLED=false` by default), off-hot-path consumer of the alerts table — it never touches `src/pipeline.py` or the capture worker threads, only reads what they already wrote.

#### `guardian_loop()` (`engine.py`)
- Runs as a background asyncio task started from `src/api/main.py`'s `lifespan()`, polling every `GUARDIAN_POLL_INTERVAL_SECS` (default 15 s) for alerts with `id > last_seen_id`.
- Skips alerts below `GUARDIAN_MIN_SEVERITY` (default `critical`), alerts whose `src_ip` is absent, and alerts whose `src_ip` matches `GUARDIAN_WHITELIST` (reuses the CIDR/exact-IP matcher from `src/enrichment/ip_lists.py`).
- Skips a `src_ip` that already has an active (`PENDING`) `MitigationAction` — no duplicate blocks.
- **Circuit breaker:** if `GUARDIAN_CIRCUIT_MAX_ACTIONS` actions were created in the last `GUARDIAN_CIRCUIT_WINDOW_SECS`, the whole batch is skipped (and never replayed later) and a single "guardian paused" notification fires via the existing `notify_alert()` path.
- On a qualifying alert: calls `MitigationBackend.block(src_ip, reason)`, then records a `MitigationAction` row (`status=PENDING`, `expires_at=now+GUARDIAN_BLOCK_MINUTES`). If the block call itself raises, no row is written — a failed block must never be recorded as if it succeeded.
- Sends a Telegram message with inline Confirm/Undo buttons if `TELEGRAM_BOT_TOKEN` is set; otherwise falls back to the standard `notify_alert()` webhook/Telegram-plain path.

#### `guardian_expiry_loop()` (`engine.py`)
- Same poll interval; finds every `PENDING` action past `expires_at`, calls `MitigationBackend.unblock()`, and marks it `EXPIRED`. This is the automatic rollback — a false positive locks a device out for at most `GUARDIAN_BLOCK_MINUTES`, never permanently, unless a human confirms it first.

#### `MitigationBackend` (`backends.py`)
A two-method `Protocol` (`block(ip, reason)` / `unblock(ip)`) so enforcement points are swappable without touching the decision logic in `engine.py`.

- **`AdGuardBackend`** (only implementation currently): DNS-level blocking via AdGuard Home. AdGuard's `/control/access/set` endpoint has no incremental add/remove — it always replaces the full `{allowed_clients, disallowed_clients, blocked_hosts}` payload, so `block()`/`unblock()` do a read (`/control/access/list`) → modify → write.
- A router/firewall backend is a natural future addition, but most consumer/ISP routers have no API for this — see [deployment.md](deployment.md#guardian-auto-response-setup) for the caveat.

#### Telegram inline buttons (`telegram_listener.py`)
- `send_action_notice()` posts a message with an `inline_keyboard` (`confirm:<id>` / `undo:<id>` callback data) whenever a new action is created.
- `telegram_listener_loop()` long-polls Telegram's `getUpdates` endpoint — deliberately **not** a webhook, since most deployments of this module (homelab, small office) have no public HTTPS endpoint reachable from Telegram's servers, while outbound HTTPS to `api.telegram.org` is essentially always available.
- `confirm:<id>` → `status=CONFIRMED`, `expires_at=NULL` (block becomes permanent, no longer subject to auto-rollback).
- `undo:<id>` → calls `unblock()` immediately, `status=UNDONE`.
- The whole listener task is only started if `TELEGRAM_BOT_TOKEN` is set; without it, the guardian still blocks and auto-rolls-back on schedule, just without interactive confirm/undo.

#### Timezone handling
Every `DateTime` column touched by the guardian (`created_at`, `expires_at`, `resolved_at`) is naive, matching the rest of `models.py` (`Alert.timestamp`, etc.) — but unlike the sync `psycopg2` path used by `pipeline.py`, asyncpg (used by the guardian's async session) rejects binding a timezone-aware `datetime` against a naive column outright. `src/guardian/engine.py` and `telegram_listener.py` each define a small `_utcnow()` helper (`datetime.now(timezone.utc).replace(tzinfo=None)`) rather than calling `datetime.now(timezone.utc)` directly.

---

### Storage Schema

```
alerts
├── id (PK)
├── timestamp
├── src_ip, dst_ip
├── src_port, dst_port
├── protocol
├── attack_type
├── severity {low, medium, high, critical}
├── ensemble_score (float)
├── engine_scores (JSON: {supervised, iforest, lstm, rules})
├── triggered_rules (JSON: list[str])
├── src_geo (JSON: {country, city, lat, lon})
├── mitre_techniques (JSON: list[{id, name, tactic}])
├── ja3_hash, ja3_string
├── acknowledged (bool)
├── notes (text)
└── incident_id (FK → incidents)

incidents
├── id (PK)
├── title, description
├── status {open, investigating, resolved, closed}
├── severity
├── assigned_to
├── created_at, updated_at, resolved_at
├── notes
└── alerts (relationship → alerts)

suppression_rules
├── id (PK)
├── src_ip (nullable)
├── dst_ip (nullable)
├── attack_type (nullable)
├── min_severity (nullable)
├── reason
├── created_at
└── expires_at (nullable)

users
├── id (PK)
├── username (unique)
├── password_hash
├── role {admin, analyst, viewer}
├── is_active
└── created_at

mitigation_actions
├── id (PK)
├── src_ip
├── action_type (e.g. "dns_block")
├── backend (e.g. "adguard")
├── status {pending, confirmed, undone, expired}
├── reason
├── alert_id (FK → alerts, nullable)
├── created_at
├── expires_at (nullable — null once confirmed permanent)
└── resolved_at (nullable)
```

---

### SIEM Integration (`siem/`)

#### Splunk
- `inputs.conf`: HEC input definition.
- `props.conf`: Field extraction transforms.
- `savedsearches.conf`: Pre-built correlation searches.
- CIM (Common Information Model) field mapping for Splunk ES.

#### Elastic / OpenSearch
- `index-template.json`: Typed field mappings (keyword, float, geo_point for lat/lon).
- `logstash-pipeline.conf`: Parse CNDS JSON logs → Elastic documents.
- `filebeat.yml`: Tail CNDS log file, tag with `cnds` index.

#### CEF Syslog (`forwarder.py`)
- Reads CNDS alert JSON from stdin or webhook.
- Emits RFC 3164 syslog messages in ArcSight CEF format.
- Compatible with QRadar, ArcSight Logger, Microsoft Sentinel.

---

## Concurrency Model

```
Main Thread
├── PacketCapture thread (Scapy sniff, daemon)
├── Worker Thread 0  ──┐
├── Worker Thread 1  ──┤─── Dispatcher (CPU-bound feature extraction)
├── Worker Thread 2  ──┤
├── Worker Thread 3  ──┘
├── DB Writer Thread (async queue → SQLAlchemy)
├── FastAPI server (uvicorn, separate process or same process)
└── Guardian background asyncio tasks (opt-in, run inside the API process)
    ├── guardian_loop           — poll + block
    ├── guardian_expiry_loop    — poll + auto-rollback
    └── telegram_listener_loop  — only if TELEGRAM_BOT_TOKEN is set
```

The bounded queue between PacketCapture and the workers prevents unbounded memory growth. If workers fall behind, packets are dropped and the drop counter increments (visible at `/health`).

ML inference (RF, IF, LSTM) runs synchronously inside worker threads. For high-throughput environments, the worker count can be increased via `PACKET_WORKERS`.

---

## Configuration Hierarchy

```
Environment variables (.env file)
    ↓ loaded by
src/config.py (50+ variables, validation on import)
    ↓ imported by
All modules that need configuration
```

Key configuration categories:

| Category | Key Variables |
|---|---|
| Capture | `CAPTURE_INTERFACE`, `PACKET_WORKERS`, `PACKET_QUEUE_SIZE` |
| Flow analysis | `FLOW_TIMEOUT`, `MAX_ACTIVE_FLOWS`, `MIN_PACKETS_FOR_ML` |
| Host analysis | `HOST_WINDOW_SIZE`, `MAX_TRACKED_IPS` |
| Ensemble | `WEIGHT_*`, `ENSEMBLE_THRESHOLD`, `ATTACK_TYPE_WEIGHTS` |
| Calibration | `CALIBRATION_TEMPERATURE`, `FT_TEMPERATURE` |
| Rules | `ICMP_FLOOD_THRESHOLD`, `PORT_SCAN_THRESHOLD`, `LARGE_PAYLOAD_BYTES` |
| Models | `MODELS_DIR`, `FT_MODEL_FILE`, `FT_SCALER_FILE`, `RF_MODEL_FILE`, `IF_MODEL_FILE`, `LSTM_MODEL_FILE` |
| Database | `DATABASE_URL` |
| Auth | `JWT_SECRET`, `JWT_ALGORITHM`, `JWT_EXPIRE_MINUTES` |
| Enrichment | `GEOIP_DB_PATH`, `CORRELATION_*`, `ADAPTIVE_WEIGHTS_ENABLED` |
| Notifications | `WEBHOOK_URLS`, `NOTIFY_MIN_SEVERITY`, `TELEGRAM_*` |
| Observability | `Monitoring Service_ENABLED`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `LOG_FORMAT` |
| IP filtering | `IP_ALLOWLIST`, `IP_BLOCKLIST`, `TRUSTED_OUTBOUND` |
| Guardian auto-response | `GUARDIAN_ENABLED`, `GUARDIAN_MIN_SEVERITY`, `GUARDIAN_WHITELIST`, `GUARDIAN_BLOCK_MINUTES`, `GUARDIAN_CIRCUIT_*`, `ADGUARD_*` |

---

## Failure Modes and Graceful Degradation

| Scenario | Behavior |
|---|---|
| FT-T checkpoint missing AND `rf_*.joblib` missing | Supervised engine `is_available=False`; weight redistributed to other engines |
| FT-T checkpoint missing only | Registry falls back to `SupervisedEngine` (Random Forest); supervised slot stays active |
| `lstm_autoencoder.pt` missing | LSTM engine unavailable; remaining engines continue |
| All ML models missing | Rules engine runs at 100% weight; detections still fire |
| PostgreSQL unreachable | Alert persisted to in-memory queue; retried on reconnect |
| GeoIP database absent | `src_geo` field omitted from alert; pipeline continues |
| JA3 hash file missing | JA3 matching disabled; fingerprint still computed and stored |
| Packet queue full | Packets dropped; `dropped_count` incremented at `/health` |
| Worker thread crash | Remaining workers continue; crash logged with stack trace |
| Guardian's `MitigationBackend.block()`/`unblock()` fails | Exception is caught and logged; no `mitigation_actions` row is written/updated for a failed `block()`, so the audit trail never claims a block that didn't happen |
| Guardian circuit breaker trips | Auto-blocking pauses for the batch (not replayed later); one notification fires; detection and manual response are unaffected |
