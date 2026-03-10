# Changelog

All notable changes to this project will be documented in this file.

## [1.0.2] - 2026-03-10

### Added

- **Alembic DB migrations** — schema versioning with auto-migration on API startup; falls back to `create_all` for in-memory test databases. Initial migration captures all existing tables (alerts, incidents, suppression_rules, users)
- **Alert deduplication in capture pipeline** — duplicate alerts from the same `(src_ip, attack_type)` pair are suppressed within the `DEDUP_WINDOW_SECS` window (default 300s), reducing alert fatigue from persistent scanners
- **WebSocket authentication** — `/ws/alerts` now requires a `?token=<JWT>` query parameter when `JWT_SECRET` is configured; unauthenticated connections are rejected with close code 4001/4003

### Changed

- `alembic` added to `requirements.txt`
- `src/api/database.py` — `init_db()` runs Alembic `upgrade head` instead of `create_all`

## [1.0.1] - 2026-03-10

### Fixed

- **Suppression logic inverted** — `min_severity` filter now correctly suppresses alerts at or below the specified severity level, not above it
- **Unbounded memory growth** — `confidence_decay` and `dns_logger` in-memory dicts are now bounded with LRU eviction (capped at `MAX_TRACKED_IPS`)
- **Race condition in rate limiter** — `RateLimitMiddleware` now uses `asyncio.Lock` to protect the shared hits dict
- **Hardcoded ensemble threshold** — the predict endpoint now uses `ENSEMBLE_THRESHOLD` from config instead of a hardcoded `0.55` after confidence decay
- **Severity logic divergence** — unified severity classification into a single `severity_from_score()` function in `ensemble/scorer.py`, used by both the capture pipeline and the API
- **Incorrect bulk transfer features** — the 6 CICFlowMeter bulk features now track actual consecutive-packet transfer segments instead of duplicating total byte/packet counts
- **UDP payloads not captured** — `FlowRecord.add_packet` now stores UDP payload samples alongside TCP, enabling payload feature extraction for DNS tunneling and UDP-based attacks
- **Sync DB writes blocking packet workers** — alert persistence in the capture pipeline now uses a dedicated writer thread with a bounded queue instead of blocking worker threads
- **FIFO eviction in dispatcher** — `Dispatcher._payload_hits` now uses `OrderedDict` with LRU eviction instead of FIFO
- **Host extractor evicts low-volume IPs** — eviction now targets the IP with the oldest last-seen timestamp, preserving low-and-slow attack patterns like C2 beacons
- **O(n) flow expiry scan** — `FlowExtractor.collect_expired` now uses a min-heap for O(k) expiry (k = expired flows) instead of scanning all active flows

### Security

- **IP address validation** — `PredictRequest` now validates `src_ip` and `dst_ip` fields using `ipaddress.ip_address()`, preventing injection via malformed IPs in logs, DB, and webhook payloads
- **Webhook payload data leak** — webhook notifications now send only safe summary fields (IP, severity, score, attack type, timestamp) instead of the full internal alert dict
- **Pinned torch version** — Dockerfile now pins `torch==2.5.1+cpu` instead of using an unpinned `>=2.0.0`

### Improved

- **Payload pre-screening** — `analyze_payload` now runs a cheap regex pre-screen before spawning per-pattern timeout threads, reducing thread churn on benign traffic
- **Shared utility module** — extracted duplicate `_entropy` implementations from `host_extractor.py` and `payload_analyzer.py` into `src/features/utils.py`
- **Docker Compose safety** — detector service no longer shares the SQLite DB volume with the API service, preventing concurrent-writer corruption; comments guide users toward PostgreSQL for production

### Changed

- **Dockerfile** — added default `CMD` so `docker run` without arguments starts the API server
- **requirements.txt** — added explanatory comment for the `anyio<4.0.0` pin
