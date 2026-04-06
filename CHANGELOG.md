# Changelog

All notable changes to this project will be documented in this file.

## [1.0.9] - 2026-04-06

### Added
- **Bundled lite supervised model** — `models/rf_lite_model.joblib` (1.6MB) committed to the repo; trained on 50k stratified sample of CIC-UNSW-NB15 (91% accuracy, 2.4% FP rate at threshold 0.90). Users get functional intrusion detection on `git clone` with no setup required.
- **3-tier model load chain** — `SupervisedEngine` now tries: (1) ML Tracking registry, (2) full local `rf_model.joblib`, (3) bundled `rf_lite_model.joblib`.
- **`--lite` flag in `train_rf.py`** — generates the bundled lite model in ~0.3s (50k sample, 25 estimators, max_depth=10, no SMOTE).
- **`RF_LITE_MODEL_PATH` config** — env var `RF_LITE_MODEL_FILE` overrides the lite model path.

## [1.0.8] - 2026-04-06

### Added
- **ML Tracking artifact store** — model artifacts registered to S3-compatible storage on `[BACKUP_SERVER_IP]:9000`; model `cnds-supervised` available in registry at `[MAIN_NODE_IP]:5050`.
- **Proxy bypass in ML Tracking init** — `ML Tracking_registry.init()` and `train_rf.py` unset `HTTP_PROXY`/`HTTPS_PROXY` so boto3 reaches the S3-compatible storage LAN endpoint directly.
- **`.env.example`** — documents `ML Tracking_TRACKING_URI`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `ML Tracking_S3_ENDPOINT_URL` for homelab setup.

## [1.0.7] - 2026-04-06

### Changed
- **Full Pipeline in `train_rf.py`** — training now wraps preprocessing (clip → log1p on 48 skewed features → StandardScaler) + RF into a single sklearn `Pipeline`; no separate scaler needed at inference time.
- **Pipeline-aware `SupervisedEngine`** — `_get_classifier()`, `_get_n_features()`, `_get_classes()` helpers unwrap `Pipeline` objects; supports both Pipeline and plain estimator formats transparently.
- **`ML Tracking_TRACKING_URI` default** — points to homelab server (`[MAIN_NODE_IP]:5050`); set to empty to disable.

## [1.0.6] - 2026-04-06

### Added
- **`RF_SCORE_THRESHOLD`** (default `0.90`) — RF anomaly scores below this are zeroed to suppress low-confidence false positives. Env var: `RF_SCORE_THRESHOLD`.
- **`eval_engines.py`** — diagnostic script evaluating RF and IF engines with synthetic CIC-UNSW-NB15-like traffic; outputs classification report, binary precision/recall sweep, and score distributions.

### Changed
- **Real RF model** — replaced random demo model with one trained on full CIC-UNSW-NB15 (447k flows, 100 estimators, class_weight=balanced); accuracy 93%, FP rate 1.9% at threshold 0.90.
- **`BENIGN_LABEL`** updated to `"Benign"` to match CIC-UNSW-NB15 taxonomy (was `"BENIGN"` for the demo model).
- **`anomaly_score()`** now uses `1 - P(Benign)` instead of confidence of the predicted class for better calibration.

## [1.0.5] - 2026-04-06

### Added
- **Extended Monitoring Service metrics** — `cnds_alerts_suppressed_total` counter (labels: `reason=dedup|suppression_rule`) and `cnds_ensemble_score` histogram (fine-grained buckets, label: `is_anomaly`).
- **Engine label on alert counter** — `cnds_alerts_total` now includes `engine` label (primary engine by score contribution).
- **`observe_ensemble_score()`** — called on every `/api/predict` request regardless of whether an alert fires.
- **`inc_suppressed()`** — incremented on both dedup hits and suppression rule matches.
- **Test suites** — `test_predict.py`, `test_pipeline.py`, `test_suppression.py`, `test_correlation.py` (67 tests).

## [1.0.4] - 2026-03-31

### Changed

- **Pipeline extraction** — detection pipeline callback (`on_flow_complete`, alert persistence, dedup, trusted-outbound filtering) extracted from `main.py` into `src/pipeline.py` for cleaner separation of concerns
- **CIDR support for IP lists** — `IP_ALLOWLIST` and `IP_BLOCKLIST` now accept CIDR ranges (e.g. `10.0.0.0/8,[CLIENT_IP]`) in addition to individual IPs
- **Suppression rule caching** — suppression rules are now cached in memory with a 10-second TTL, avoiding a DB query per alert; cache is invalidated on rule create/delete
- **Payload analyzer simplification** — removed thread-per-regex pattern matching; uses direct `re.search()` on bounded 4KB input instead (pre-screen regex still filters benign payloads)
- **WebSocket connection limit** — `/ws/alerts` now rejects connections beyond 100 concurrent clients (close code 4029)
- **Alembic in thread executor** — `init_db()` runs Alembic migrations via `run_in_executor` to avoid blocking the async event loop
- **Lazy asyncio.Lock** — predict router's dedup lock is now lazily initialized to avoid creating it outside an event loop
- **Flow heap compaction** — `FlowExtractor._evict_oldest()` now compacts the expiry heap to prevent unbounded growth from stale references
- **SQLite concurrent-writer warning** — `main.py --api` now logs a warning when using SQLite, recommending PostgreSQL for production
- **Pydantic v2 migration** — replaced deprecated `class Config` with `model_config = ConfigDict(from_attributes=True)` in all Pydantic schemas (eliminates 4 deprecation warnings)
- **JWT test secrets** — test suite uses 32+ byte HMAC secrets (eliminates `InsecureKeyLengthWarning`)

### Fixed

- **docker-compose detector** — removed misleading `CNDS_API_URL` env var from detector service (uses `network_mode: host`, cannot resolve service names)

## [1.0.3] - 2026-03-10

### Added

- **Periodic cleanup task** — background asyncio task runs every 5 minutes to purge expired suppression rules from the DB and prune inactive IPs from the rate limiter
- **GeoIP in capture pipeline** — alerts persisted from `main.py` now include `src_geo` enrichment (previously only the API predict endpoint did this)
- **Structured JSON logging** — set `LOG_FORMAT=json` for machine-parseable logs compatible with ELK/Loki/CloudWatch; alert logs include structured `extra` fields (`src_ip`, `ensemble_score`, `attack_type`, etc.)
- **API predict deduplication** — `/api/predict` now suppresses duplicate alerts from the same `(src_ip, attack_type)` within `DEDUP_WINDOW_SECS`, matching the capture pipeline behaviour
- **Engine interface protocol** — `src/engines/protocol.py` defines a `DetectionEngine` Protocol; ML engines are verified at import time via `isinstance` checks in the registry

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
