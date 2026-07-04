# Changelog

## [1.2.0] - 2026-07-04

### Added
- Guardian auto-response module (`src/guardian/`) — opt-in, off by default. Auto-blocks critical-severity alerts' `src_ip` via an AdGuard Home DNS backend, with a device whitelist, a circuit breaker against alert storms, and automatic timer-based rollback
- `mitigation_actions` table tracking every guardian action (pending/confirmed/undone/expired)
- Telegram inline Confirm/Undo buttons for guardian actions, via `getUpdates` long-polling (no webhook required)
- `postgres` service added to the default `docker-compose.yml` — required now that `api`/`detector` run as separate containers

### Fixed
- Missing `requests` and `psycopg2-binary` dependencies that only surfaced against a real production boot, not the test suite
- `docker-compose.yml` `env_file` order bug where `.env.example`'s blank defaults silently overrode real `.env` values
- Timezone-aware vs naive `DateTime` bug in the new guardian code (asyncpg rejects it; SQLite in tests does not)
- Dashboard `ZeroDivisionError` when there are zero alerts (`dict.get(key, default)` only applies `default` when the key is absent, not when it's `0`)

> This wiki page is a manually maintained excerpt — see the repository root [`CHANGELOG.md`](https://github.com/RobertoDeLaCamara/Cognitive-Intrusion-Detection-System/blob/master/CHANGELOG.md) for the complete, continuously updated history (1.1.2–1.1.1 and earlier are not mirrored here).

## [1.0.5] - 2026-04-19

### Security
- `GET /api/alerts/export` now requires `admin` or `analyst` role in JWT-only deployments (was unauthenticated)
- `GET /api/baseline/status` and `/api/baseline/windows` now require `viewer` role minimum (was unauthenticated)

### Fixed
- `asyncio.Lock` in `/api/predict` dedup cache created eagerly at module load (was lazy, causing race condition under concurrent requests)
- `StandardScaler` / LSTM no longer silently poisoned by NaN/Inf host vectors — bad rows are dropped with a WARNING before training
- `mlflow.register_model()` moved outside `with mlflow.start_run()` context so the run is FINISHED before the registry entry is created
- `last_time=0.0` in `BaselineCollector.observe()` no longer falls back to `time.time()` (sentinel pattern, fixes pcap replay timestamps)
- Suppression cache refresh now holds an `asyncio.Lock` to prevent redundant concurrent DB queries
- ETA estimate in `/api/baseline/status` capped at 7 days (prevents unbounded int from tiny `min_ratio` values)
- `cnds_baseline_windows_trained` Prometheus metric is now a true monotone counter (previously capped at 20 by deque maxlen); renamed from `cnds_baseline_windows_trained_total` to match Prometheus naming convention
- `siem/syslog/forwarder.py` persists `last_id` to `~/.cnds_forwarder_state.json` to avoid replaying alerts on restart
- Threshold artifact written as JSON `{"threshold": ..., "percentile": ...}` (was raw float string); `BaselineEngine` reads both formats for backward compatibility
- `geoip.is_enabled()` now correctly returns `False` when no database is configured (was always `True`)

### Changed
- `WindowTrainer` exposes `get_windows_trained_total()` — monotone counter of trained windows since process start
- `start_baseline_scrape()` accepts optional `windows_total_getter` parameter to use the new counter

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
