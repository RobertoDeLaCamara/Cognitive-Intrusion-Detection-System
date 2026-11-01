# Changelog

> This wiki page is a manually maintained excerpt — see the repository root [`CHANGELOG.md`](https://github.com/RobertoDeLaCamara/Cognitive-Intrusion-Detection-System/blob/master/CHANGELOG.md) for the complete, continuously updated history. Releases 1.1.0, 1.1.1, 1.0.5–1.0.9 (as numbered in the root file) are not mirrored here.

## [Unreleased]

### Security
- `/api/auth/users` was open in API-key-only mode: the key middleware skipped every `/api/auth*` path and `require_role` does nothing without `JWT_SECRET`. Only `/api/auth/token` is exempt now; `/api/auth/users*` needs `X-API-Key` unless JWT is on (then the admin role check guards it). Deployments with `API_KEY` alone were affected: check `GET /api/auth/users` for unknown accounts.

### Added
- `geoip2` is installed in the image (hashed locks regenerated with every other pin held). GeoIP enrichment stays off until `GEOIP_DB_PATH` points at a `.mmdb` City database (GeoLite2 or DB-IP Lite).
- Baseline evaluation bench (`scripts/eval_baseline.py`): fits with the detector's own `fit_models()` on a chronological split of benign host vectors and reports false positives on the newest benign rows, recall and AUC for six simulated attacks (built with the real `HostExtractor`), score saturation and features that drift over time. `BASELINE_DUMP_DIR` (off by default) makes the collector write each window to disk so the bench can run on real traffic. `src/engines/baseline_scoring.py` now holds the score formulas shared by `BaselineEngine` and the bench (no behaviour change).
- Suppression rules can be limited to a destination port (`dst_port`, Alembic `a8b9c0d1e2f3`). A narrow rule (`src_ip` or `dst_ip` plus `dst_port`) may last up to 365 days instead of 7. The API applies the migration at startup: recreate `api` before the detector.
- **Baseline stability gate**: a retrained window is no longer promoted when its LSTM threshold is more than `BASELINE_THRESHOLD_MAX_RATIO` (3.0) times above/below the median of the last accepted windows; after `BASELINE_MAX_CONSECUTIVE_REJECTS` (3) rejections in a row the new level is accepted as a regime change. Seen on raspi-189 with 3000-vector windows: p99 thresholds of 0.32 and 8.93 for consecutive windows of the same network. Larger windows (`BASELINE_MIN_VECTORS`) also steady it.

- **Suppressed detector alerts are logged as `[SUPPRESSED]`** (`src=… | dst=… | dport=… | score=… | type=… | rule=#N`). The `[ALERT]` line is written at detection time, before suppression is evaluated, so it also covers alerts that are then suppressed; count `[SUPPRESSED]` to separate them.
- Triage agent (`src/triage/`, `python -m src.triage`) — out-of-process advisory verdicts written only to the append-only `triage_annotations` table (migration `c3d8e1f4a7b2`); `scripts/eval_triage.py`
- `start` / `end` / `hours` date-range filters on `GET /api/alerts` (#5)
- Baseline training trigger thresholds configurable via `BASELINE_MIN_VECTORS`, `BASELINE_MIN_SRC_IPS`, `BASELINE_MIN_ELAPSED_SECS`, `BASELINE_MIN_PORT_ENTROPY` (#65)
- logwatch: log-based detection (`src/logwatch/`, Gitea rules, replay CLI; no live tailer yet) (#53, #55, #60, #61)
- ntfy notification channel: `NTFY_URL`, `NTFY_TOPIC`, `NTFY_USER`, `NTFY_PASSWORD`, `NTFY_TOKEN` (#62)
- `baseline_progress` log lines and baseline metrics are emitted when the detector runs without `--api` (#67)

### Changed
- Host volume features are windowed instead of cumulative (host-feature schema 2). `total_packets`, `total_bytes`, `session_duration`, `packets_per_sec` and `bytes_per_sec` were totals since a host was first seen, so on stationary traffic they grew x8.5 in about an hour and the baseline LSTM, trained on one hour, scored the next as unusual (16 % of benign rows above 0.65 on the first raspi-189 window, all from the LSTM). They are now computed over the host's last `HOST_WINDOW_SIZE` packets. Models carry `feature_schema.txt`; `BaselineEngine` ignores any model trained on another schema, so after deploying it stays off until one new window is trained (about an hour at the current thresholds). The legacy demo IsolationForest/LSTM read the same 18 features and see the new values too.
- Baseline LSTM trains on per-host sequences with a chronological split. `WindowTrainer` used to shuffle all rows and slide a window over the mix of hosts, while the engine scores one `seq_len` buffer per source IP, so the LSTM never saw the structure it is scored on and a random split leaked neighbouring rows into validation. Sequences are now built inside each host (`_to_host_sequences`) and the oldest 80 % of the window trains, the newest 20 % validates (`_temporal_split`). Hosts with fewer than `seq_len` vectors in a split contribute no sequence. The IsolationForest is unchanged apart from the split.
- `hours` is bounded to 1–87600 (10 years) on `GET /api/alerts` and `GET /api/alerts/export`; larger values return 422 instead of 500 (#16)
- Jenkinsfile pushes images only from `master`; PR builds get an advisory Claude review stage
- `syn_scan` condition fixed (#49) and added to the default `CRITICAL_RULES` (#50)
- Suppression rules apply to alerts written by the capture pipeline (#66)
- Payload regex rules are skipped on encrypted or high-entropy payloads (#68)
- Docker dependencies install in three layers (`requirements-lock-{torch,sci,rest}-<arch>.txt`, `scripts/split_lock.py`); Jenkinsfile registry push uses `retry(4)` with `sleep 90` (#69)
- Baseline registered with `MlflowClient.create_model_version`, compatible with a 3.x client against a 2.x MLflow server (#70)

### Fixed
- Payload-pattern hits and JA3 fingerprints are attributed to their own flow; `payload_matches`, ports and protocol are persisted on capture-pipeline alerts; `sql_injection` / `command_injection` regexes no longer match binary noise

## [1.3.0] - 2026-09-14

### Added
- Read-only MCP server (`src/mcp_server/`, nine tools, enforced read-only at the DB engine, no enforcement tools)

## [1.2.1] - 2026-07-05

### Security
- Removed the insecure default `POSTGRES_PASSWORD` fallback; `docker-compose.yml` now refuses to start without it

### Fixed
- `/api/predict` alert persistence against Postgres and the wider timezone-aware vs naive `DateTime` bug, fixed with the shared `src/timeutils.utcnow()` helper and a regression test

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

## 2026-04-19 — hardening release (no version number; not recorded in the root `CHANGELOG.md`, whose `[1.0.5]` is the 2026-04-06 Prometheus-metrics release)

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
- Feedback-driven retraining — analyst TP/FP labels → automated retraining via MLflow
- ONNX Runtime for LSTM — 2-5x inference speedup over raw PyTorch
