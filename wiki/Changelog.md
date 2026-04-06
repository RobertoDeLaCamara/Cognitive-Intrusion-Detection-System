# Changelog

## [1.0.4] - 2026-03-31

### Changed
- Pipeline extraction — detection callback moved from `main.py` to `src/pipeline.py`
- CIDR support — `IP_ALLOWLIST` and `IP_BLOCKLIST` accept CIDR ranges (e.g. `10.0.0.0/8`)
- Suppression rule caching — in-memory cache with 10s TTL, invalidated on create/delete
- Payload analyzer — direct regex matching on bounded 4KB input (removed thread-per-pattern)
- WebSocket connection limit — max 100 concurrent `/ws/alerts` clients
- Alembic runs in thread executor to avoid blocking async loop
- Flow heap compaction on eviction prevents unbounded memory growth
- SQLite warning when using `--api` mode
- Pydantic v2 `ConfigDict` migration (eliminates deprecation warnings)

### Fixed
- docker-compose detector: removed unreachable `CNDS_API_URL` env var

## [1.0.3] - 2026-03-10

### Added
- Periodic cleanup task — background asyncio task purges expired suppression rules and prunes inactive IPs from the rate limiter every 5 minutes
- GeoIP in capture pipeline — alerts from `main.py` now include `src_geo` enrichment
- Structured JSON logging — `LOG_FORMAT=json` for machine-parseable logs (ELK/Loki/CloudWatch compatible)
- API predict deduplication — `/api/predict` suppresses duplicate alerts within `DEDUP_WINDOW_SECS`
- Engine interface protocol — `DetectionEngine` Protocol with runtime `isinstance` checks

## [1.0.2] - 2026-03-10

### Added
- Alembic DB migrations with auto-migration on API startup
- Alert deduplication in capture pipeline (`DEDUP_WINDOW_SECS`, default 300s)
- WebSocket authentication (`?token=<JWT>` when `JWT_SECRET` is configured)

### Changed
- `init_db()` runs Alembic `upgrade head` instead of `create_all`

## [1.0.1] - 2026-03-10

### Fixed
- Suppression `min_severity` filter logic corrected
- Unbounded memory growth in `confidence_decay` and `dns_logger` (now LRU-bounded)
- Race condition in rate limiter (added `asyncio.Lock`)
- Hardcoded ensemble threshold replaced with `ENSEMBLE_THRESHOLD` from config
- Severity classification unified into `severity_from_score()` function
- Bulk transfer features now track actual consecutive-packet segments
- UDP payloads now captured alongside TCP
- Sync DB writes no longer block packet workers (dedicated writer thread)
- FIFO eviction in dispatcher replaced with LRU
- Host extractor evicts by oldest last-seen timestamp
- Flow expiry uses min-heap for O(k) performance

### Security
- IP address validation on `PredictRequest` (prevents injection)
- Webhook payloads limited to safe summary fields
- Pinned `torch==2.5.1+cpu` in Dockerfile

### Improved
- Payload pre-screening reduces thread churn on benign traffic
- Shared `byte_entropy` utility extracted to `src/features/utils.py`
- Docker Compose safety: detector no longer shares SQLite DB volume with API

## Roadmap

### Planned
- Model drift detection — alert when live traffic features diverge from training data
- Feedback-driven retraining — analyst TP/FP labels → automated retraining via ML Tracking
- ONNX Runtime for LSTM — 2-5x inference speedup over raw PyTorch
