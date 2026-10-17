# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Security
- **BREAKING: the API refuses to start without authentication** — if neither `API_KEY` nor `JWT_SECRET` is set, importing `src.api.main` exits non-zero unless `AUTH_DISABLED=true` (only the literal `true`; logs a warning). The sandbox opts in explicitly; set `JWT_SECRET` or `API_KEY` in `.env` before redeploying (cnds#20).

- **Role checks on every alerts, incidents and predict route when JWT auth is enabled** (cnds#21, #1). Before, `GET /api/alerts`, `/alerts/trends`, `/alerts/{id}`, `/incidents`, `/stats`, `/suppression-rules`, `/adaptive-weights`, `/dns-log`, **`PATCH /api/alerts/{id}`** and **`POST /api/predict`** accepted any caller. Now reads need `viewer`, `analyst` or `admin`; `PATCH /alerts/{id}` and `POST /predict` need `analyst` or `admin`. **BREAKING for JWT deployments:** every client must send a token. The dashboard and `scripts/demo_seed.py` now authenticate (`CNDS_API_KEY`, or `CNDS_API_USER` + `CNDS_API_PASSWORD`; `API_KEY` / `CNDS_API_TOKEN` for the seed). Without `JWT_SECRET` nothing changes: API-key and `AUTH_DISABLED=true` deployments stay as before, and the API key still grants full access.

### Added
- **Triage agent — MCP roadmap phase 2 (`src/triage/`, `python -m src.triage`)** — an out-of-process consumer that annotates unacknowledged alerts at or above `TRIAGE_MIN_SEVERITY` with an advisory verdict (`likely_malicious`/`likely_benign`/`needs_human`), confidence, evidence tagged by source, an analyst recommendation and optional ATT&CK ids. Two modes: `workflow` (CNDS assembles context through the sanitising MCP query layer; the model makes one call with no tools — the default) and `agent` (the model gets only the read-only `cnds` MCP tools). Backend is `claude -p` with `--json-schema`, `--tools ""`, `--permission-mode dontAsk`, `--max-turns`, `--max-budget-usd`, `--no-session-persistence`, and `--strict-mcp-config --allowedTools mcp__cnds` in agent mode; it runs in an empty temp directory.
- **`triage_annotations` table** (Alembic `c3d8e1f4a7b2`) — append-only; the runner writes nothing else. Failed or schema-invalid answers are stored as `backend_error`/`invalid_output` with verdict `needs_human`, so failures are visible and not retried in a loop.
- **Deterministic guards over the model** (`src/triage/policy.py`) — confidence floor → `needs_human`; no `confirm_block`/`undo_block` without a Guardian action on the alert; no `confirm_block` on a Guardian-whitelisted source; benign+block contradiction → escalate. `model_verdict` and `policy_notes` keep the raw opinion and what changed. Model text is scrubbed like attacker-influenced fields before it is stored.
- **Spend control** — per-call `TRIAGE_MAX_USD_PER_ALERT`, rolling 24 h `TRIAGE_DAILY_BUDGET_USD`, `TRIAGE_BATCH_SIZE` per run.
- **`get_alert` returns `agent_triage`** — the latest annotation, labelled advisory. The runner reads alerts with `include_triage=False` so a re-triage is not anchored on the previous model opinion.
- **`scripts/eval_triage.py`** — agreement with analyst labels (`[tp]`/`[fp]` at the start of acknowledgement notes): coverage, deferral rate, precision/recall of `likely_malicious`, guard hit rate, mean cost and latency.
- **`tests/test_triage.py`** — schema, guards, prompt wrapping, least-privilege CLI argv, CLI output parsing, runner selection/idempotence, failure recording, daily budget, MCP exposure, and an AST check that no triage module imports the Guardian, creates mitigation rows or assigns alert workflow fields.
- **Date-range filters on `GET /api/alerts`** (#5, [ADR 0001](docs/adr/0001-date-range-filter-get-api-alerts.md)) — optional `start` / `end` (inclusive ISO 8601; naive values are read as UTC; `start` after `end` returns 422) and `hours` (last N hours). All filters combine with `severity`, `acknowledged`, `src_ip` and with each other (AND). Backward compatible.

### Changed
- **`hours` is bounded on `GET /api/alerts` and `GET /api/alerts/export`** (#16, [ADR 0002](docs/adr/0002-bound-hours-get-api-alerts-api-alerts.md)) — `1 <= hours <= 87600` (10 years, `MAX_HOURS` in `src/api/routers/alerts.py`). Larger values now return 422 instead of an `OverflowError` 500.
- **Jenkinsfile** — images are pushed to the registry only from `master` (or the legacy single-branch job); other branches build and test only. A new advisory "Claude PR review" stage posts a review on the Gitea PR and never fails the build.

### Fixed
- **Payload and JA3 attribution** — payload pattern hits and the TLS ClientHello JA3 fingerprint are now attached to their own flow instead of whichever flow from the same host expired next; `payload_matches`, ports and protocol are persisted on alerts written by the capture pipeline.
- **`sql_injection` and `command_injection` payload regexes** no longer match binary noise.

## [1.3.0] - 2026-09-14

### Added
- **Read-only MCP server (`src/mcp_server/`)** — exposes the alert store to [Model Context Protocol](https://modelcontextprotocol.io) clients (Claude Code, Claude Desktop, any MCP-compatible agent) over stdio, so an analyst can triage conversationally instead of paging through alert JSON. Opt-in and out of process: the protocol SDK lives in a separate `requirements-mcp.txt` and nothing in the detector, API or dashboard imports it. Nine tools: `list_alerts`, `get_alert`, `get_ip_profile`, `alert_trends`, `get_stats`, `list_incidents`, `list_mitigation_actions`, `list_suppression_rules`, `get_detection_config`.
- **Read-only enforced at the database engine, not by convention** (`src/mcp_server/db.py`) — a dedicated engine applies `PRAGMA query_only=ON` per connection on SQLite and the `postgresql_readonly` execution option (→ `SET TRANSACTION READ ONLY`) on PostgreSQL. A future editing mistake in a query function cannot corrupt the alert store; a test asserts a raw `INSERT` raises, and a second greps `queries.py` for write calls.
- **No enforcement tools, deliberately** — there is no `block_ip`/`unblock_ip`/`acknowledge_alert`. The Guardian stays the sole actuator for mitigation because it is deterministic, circuit-broken and auditable; substituting a non-deterministic LLM would be a security regression. `test_catalogue_exposes_only_read_verbs` fails the build if a mutating tool is ever added.
- **Attacker-influenced field sanitisation** (`src/mcp_server/sanitize.py`) — once alert data reaches an LLM the network becomes an input channel to the agent, so `src_ip`/`dst_ip` are parsed with `ipaddress`, `ja3_string`/`ja3_hash` are checked against canonical syntax, and free text is length-bounded, stripped of control characters and de-delimited (code fences, angle brackets). Payloads carry `_untrusted_fields` plus an advisory. It intentionally does **not** pattern-match for malicious intent — that is trivially bypassed and manufactures false confidence; the real control is that no tool can actuate anything. Audit of the schema confirmed the surface is narrow by construction: `triggered_rules`/`payload_matches` hold closed pattern names from `features/payload_analyzer.py`, and raw payload bytes are never persisted.
- **`get_ip_profile` tool** — the triage primitive the REST API lacked: aggregates one source IP's alert totals, first/last seen, severity and attack-type breakdown, most frequent triggered rules, targeted ports, distinct JA3 fingerprints, score max/mean, how many of its past alerts were acknowledged (the best available proxy for prior human verdicts), its Guardian mitigation history, and the policy in force for it (Guardian whitelist, detection allowlist/blocklist) — the last of which explains why a critical alert produced no block without the analyst reading `.env`.
- **`get_detection_config` tool** — thresholds, engine weights, `CRITICAL_RULES`, rule thresholds, dedup/cooldown windows, correlation settings, Guardian policy and IP lists. An `ensemble_score` is uninterpretable without its threshold, and a `payload:sql_injection` hit fires an alert through `CRITICAL_RULES` regardless of the weighted blend; without this an agent mis-ranks alerts confidently. A test asserts no `password`/`token`/`secret`/`api_key` substring can appear in its output.
- **`tests/test_mcp_server.py`** — 102 tests covering every query function, sanitisation, the tool catalogue/dispatch contract (including that schema properties match handler signatures, which would otherwise only surface as a runtime `TypeError`), the read-only guarantees, and protocol error semantics through a real in-process client/server pair. Coverage: `sanitize.py` 100%, `queries.py` 99%, `tools.py` 97%.

### Fixed
- **Stale ensemble weights in `README.md` and `doc/index.md`** — both documented weights that no longer matched `src/config.py`. The README claimed Supervised 35% / IF 25% / LSTM 15% / Rules 5% / Baseline 20%, and `doc/index.md`'s diagram claimed 40/30/20/10 while omitting the Baseline engine entirely. Actual defaults are 30/20/10/25/15; `WEIGHT_RULES` was deliberately raised from 0.05 to 0.25 (a certain signature match previously could not clear `ENSEMBLE_THRESHOLD` on its own) and the documentation was never updated to match.
- **Missing 1.2.1 row in `doc/index.md`'s version history** — the table stopped at 1.2.0 although CHANGELOG had a 1.2.1 entry.

### Notes
- **Known limitations, all consequences of running out of process** — the DNS query log (`enrichment/dns_logger.py`) and the threat-intel indicator sets live in in-memory structures inside the detector process, so no MCP tool can reach them; likewise `/health` engine availability and live capture stats. None requires a schema change to lift, but each would need either persistence or an HTTP call into the running API.
- **No authentication, by design** — the MCP client spawns the server as a subprocess over stdio and it inherits the OS user's privileges. It is an operator-local tool; the DB file's permissions are the access-control boundary. Do not expose it over a network transport. For PostgreSQL, give it a role with only `CONNECT` and `SELECT`.
- Phases 2 (an async triage agent that annotates alerts with a suggested verdict, finally feeding `adaptive_weights` the acknowledged samples it waits for) and 3 (agent-proposed mitigations routed through the existing Telegram Confirm/Undo handshake) are documented in `doc/mcp-server.md` but **not implemented**.

## [1.2.1] - 2026-07-05

### Security
- **Removed insecure default `POSTGRES_PASSWORD` fallback** — `docker-compose.yml` fell back to the guessable literal `cnds` whenever `POSTGRES_PASSWORD` was unset. Compose now refuses to start (`${POSTGRES_PASSWORD:?...}`) instead of silently using a weak password. Documented the now-mandatory var in `.env.example` and `doc/deployment.md`.

### Fixed
- **`/api/predict` alert persistence broken against Postgres** — same root cause as the guardian timezone bug below: `Alert(timestamp=datetime.now(timezone.utc), ...)` bound a tz-aware datetime into a naive `DateTime` column via the async session, so asyncpg silently rejected every insert (`alert_id` came back `None`, no visible error in `docker logs`). Confirmed live against raspi-62 while testing the guardian with a simulated attack through this exact endpoint.
- **Timezone bug was systemic, not guardian-only** — every async code path that touches a `DateTime` column (`src/api/routers/alerts.py`, `src/api/routers/predict.py`, `src/enrichment/correlation.py`, `src/enrichment/suppression.py`, in addition to the guardian) used `datetime.now(timezone.utc)` (aware) against naive columns. This broke `is_suppressed()`/`cleanup_expired()`, `correlate_alert()`, and the periodic cleanup task, in addition to `/api/predict` and the guardian actions above. Fixed by introducing `src/timeutils.utcnow()` as the single naive-UTC helper used everywhere, replacing the guardian module's duplicate `_utcnow()` helpers. Added `tests/test_timeutils.py` as a regression guard that introspects every model's `DateTime` column defaults and asserts they're naive.

## [1.2.0] - 2026-07-04

### Added
- **Guardian auto-response module (`src/guardian/`)** — opt-in (`GUARDIAN_ENABLED=false` by default) background asyncio consumer of the alerts table that automatically mitigates `GUARDIAN_MIN_SEVERITY`-and-above alerts. Ships with an `AdGuardBackend` (DNS-level blocking via AdGuard Home's `/control/access/list` + `/control/access/set`) behind a small `MitigationBackend` protocol so other enforcement points can be added later. Includes a device whitelist (`GUARDIAN_WHITELIST`), a circuit breaker against alert storms (`GUARDIAN_CIRCUIT_MAX_ACTIONS`/`_WINDOW_SECS`), and automatic timer-based rollback (`GUARDIAN_BLOCK_MINUTES`). Deliberately reads from the alerts table rather than hooking into `src/pipeline.py`'s capture path.
- **`mitigation_actions` table** (`src/api/models.py` `MitigationAction`/`MitigationStatus`, migration `f7c9a2b4e1d3`) — audit trail of every guardian action: `src_ip`, `status` (`pending`/`confirmed`/`undone`/`expired`), `reason`, `alert_id`, `expires_at`.
- **Telegram inline Confirm/Undo buttons** (`src/guardian/telegram_listener.py`) — long-polls `getUpdates` (no webhook required) to let an operator confirm a block as permanent or undo it early. Inactive until `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID` are set; the guardian still blocks and auto-rolls-back on schedule without it.
- **PostgreSQL service in `docker-compose.yml`** — `api` and `detector` run as separate containers, and SQLite has no concurrent-writer support, so a `postgres` service is now part of the default compose stack instead of a documented-but-manual option.
- **Per-service resource limits in `docker-compose.yml`** (`mem_limit`/`cpus` on `api`, `detector`, `postgres`, `dashboard`) so a single-board/homelab host isn't starved by other services on the same box.

### Changed
- **`docker-compose.yml` `env_file` order** — `.env.example` now loads before `.env` in every service. Compose applies the *last* listed file as the override; with the previous order, `.env.example`'s blank defaults were silently clobbering real values set in `.env` (`JWT_SECRET`, `CAPTURE_INTERFACE`, `LOG_FORMAT`, etc.).
- **`dashboard/app.py`** — the Streamlit dashboard is now gated behind the `dashboard` compose profile rather than started unconditionally, since Grafana or the guardian's own notifications may already cover monitoring in some deployments.

### Fixed
- **Missing `requests` dependency** — `src/enrichment/threat_intel.py` imports `requests` unconditionally, but it was never declared in `requirements.txt`. Unit tests never caught it because they don't exercise the full FastAPI lifespan (the import is lazy, inside `lifespan()`); first real boot against a production database failed with `ModuleNotFoundError` and Uvicorn exit code 3.
- **Missing `psycopg2-binary` dependency** — `alembic/env.py` converts the async `DATABASE_URL` (`+asyncpg`) to `+psycopg2` for Alembic's synchronous migration engine, but nothing installed that driver. The resulting exception was silently swallowed by `database.py`'s broad `except Exception: fall back to create_all()`, masking the real failure and leaving Alembic's own `alembic_version` tracking table unpopulated even though the schema was created.
- **Timezone-aware datetimes bound against naive `DateTime` columns** — the new guardian code and `MitigationAction.created_at`'s default both used `datetime.now(timezone.utc)` (aware) against plain `DateTime` (naive, matching `Alert`/`Incident`/`SuppressionRule` elsewhere in `models.py`). asyncpg rejects this (`can't subtract offset-naive and offset-aware datetimes`) even though SQLite (used in the test suite) does not — the bug only surfaced against a real PostgreSQL deployment. Fixed with a `_utcnow()` helper returning naive UTC, used throughout `src/guardian/`.
- **Dashboard `ZeroDivisionError`** (`dashboard/app.py`) — the Acknowledge Rate metric used `stats.get('total_alerts', 1)` to guard a division, but `dict.get(key, default)` only falls back to `default` when the key is *absent*, not when it's present and falsy. With zero alerts, `total_alerts` is `0` (present), so the guard never applied.

## [1.1.1] - 2026-05-05

### Added
- **`FT_TEMPERATURE` env var** — temperature scaling factor applied to FT-Transformer logits before softmax (default `2.0`). Reduces systematic over-confidence in Transformer classifiers (observed max probability drops from ~0.97 to ~0.85 on typical attack flows). Set to `1.0` to disable. Documented in `.env.example`, `src/config.py`, and `doc/ml-models.md`.
- **ARM64 Docker support** — `ARG TARGETARCH=amd64` added to `Dockerfile`. `amd64` builds pull the explicit `+cpu` PyTorch wheel from the PyTorch index; `arm64` (e.g. Raspberry Pi 5) pulls the standard PyPI `manylinux2014_aarch64` wheel; `arm/v7` has no official PyTorch wheel and degrades gracefully to the RF fallback.

### Changed
- **`scikit-learn>=1.6.1,<2.0` pin in `requirements.txt`** — upper bound added to prevent a scikit-learn 2.0 ABI break from silently invalidating the serialized `StandardScaler` in `unified_scaler.pkl`.

---

## [1.1.0] - 2026-05-04

### Added
- **Unified FT-Transformer supervised engine** — `FTTransformerEngine` (`src/engines/ft_transformer_engine.py`) wraps the Optuna-tuned FT-Transformer trained jointly for ML-IDS and cnds. Test F1 macro 0.6197 on UNSW-NB15 (vs 0.6095 XGBoost baseline). Smoke-test reproduces 0.6194 through the cnds engine path.
- **Importable model class** — `src/models/ft_transformer.py` exposes the `FTTransformer` `nn.Module`, `load_checkpoint`/`build_from_checkpoint` helpers, and the `UNIFIED_CLASS_LABELS` tuple for consumers that need to decode class ids.
- **MLflow registry loading** — engine pulls `models:/ml-ids-unified-ft-transformer/<latest>` from the homelab MLflow server, with automatic local-checkpoint fallback (`models/unified/unified_ft_transformer.pt` + `unified_scaler.pkl`).
- **Config knobs** — `FT_MODEL_FILE`, `FT_SCALER_FILE`, `FT_USE_GPU`, `FT_SCORE_THRESHOLD`, `MLFLOW_FT_REGISTRY_NAME`, `MLFLOW_FT_STAGE`.
- **Smoke test script** — `scripts/smoke_test_ft_unified.py` reproduces the published test F1 macro on the held-out 15 % split.
- **Integration tests** — `tests/test_ft_transformer_engine.py` (7 tests) exercises the load → scale → forward → softmax path on real attack/benign rows from the dataset.
- **Live capture runbook** — `doc/UNIFIED_FT_LIVE_RUNBOOK.md` documents the manual hping3 + nmap end-to-end test against real traffic.

### Changed
- **Engine registry** — `src/engines/registry.py` now picks `FTTransformerEngine` when its checkpoint is available, otherwise falls back to the legacy `SupervisedEngine` (Random Forest). Both implement the same `predict` / `anomaly_score` interface, so `pipeline.py`, the ensemble, and the API are unchanged.
- **Test isolation** — `tests/conftest.py` sets `FT_MODEL_FILE=__disabled_in_tests__` so the registry singleton does not pull torch into `sys.modules` during pytest collection (which would break `test_baseline_engine`'s fake-torch fixture).
- **Model construction** — `FTTransformer.__init__` now wraps tokenizer + encoder construction in `torch.no_grad()` and uses two-step `nn.Parameter` init to survive autograd state contamination from the same fake-torch fixture.
- **`.dockerignore`** — switched to `models/**/*.{joblib,pkl,pt}` plus explicit allow-list for the bundled RF lite, the FT-Transformer checkpoint, the FT scaler, and the FT metadata. The previous patterns (`models/*.joblib` etc.) silently excluded `models/rf_lite_model.joblib` — committed for out-of-the-box detection — from every Docker image, leaving the supervised slot disabled when MLflow was unreachable.

### Fixed
- **Logging under pytest** — `setup_logging()` is now a no-op when `pytest` is in `sys.modules`. Before, `src/api/main.py` calling it at module load wiped pytest's `caplog` handlers, which silently broke `caplog.text` assertions for every test that imported the API (the `test_full_cycle_drop_then_fire_then_log` regression).
- **`stub_torch` fixture in `tests/engines/test_baseline_engine.py`** — reworked from `scope="session"` (with a guard that silently no-op'd whenever torch was already in `sys.modules`) to `scope="function"` with a snapshot/restore of every `torch.*` key, so the fake mock is always installed during these tests and the real module is fully restored afterwards. Previously, sibling files (`test_window_stability.py`, `test_ft_transformer_engine.py`) saw a half-mocked torch and failed with `AttributeError: 'builtin_function_or_method' object has no attribute 'side_effect'` and `ModuleNotFoundError: torch._C is not a package`.

## [1.0.9] - 2026-04-06

### Added
- **Bundled lite supervised model** — `models/rf_lite_model.joblib` (1.6MB) committed to the repo; trained on 50k stratified sample of CIC-UNSW-NB15 (91% accuracy, 2.4% FP rate at threshold 0.90). Users get functional intrusion detection on `git clone` with no setup required.
- **3-tier model load chain** — `SupervisedEngine` now tries: (1) MLflow registry, (2) full local `rf_model.joblib`, (3) bundled `rf_lite_model.joblib`.
- **`--lite` flag in `train_rf.py`** — generates the bundled lite model in ~0.3s (50k sample, 25 estimators, max_depth=10, no SMOTE).
- **`RF_LITE_MODEL_PATH` config** — env var `RF_LITE_MODEL_FILE` overrides the lite model path.

## [1.0.8] - 2026-04-06

### Added
- **MLflow artifact store** — model artifacts registered to S3-compatible storage on `your-minio-host:9000`; model `cnds-supervised` available in registry at `your-mlflow-host:5050`.
- **Proxy bypass in MLflow init** — `mlflow_registry.init()` and `train_rf.py` unset `HTTP_PROXY`/`HTTPS_PROXY` so boto3 reaches the S3-compatible storage LAN endpoint directly.
- **`.env.example`** — documents `MLFLOW_TRACKING_URI`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `MLFLOW_S3_ENDPOINT_URL` for homelab setup.

## [1.0.7] - 2026-04-06

### Changed
- **Full Pipeline in `train_rf.py`** — training now wraps preprocessing (clip → log1p on 48 skewed features → StandardScaler) + RF into a single sklearn `Pipeline`; no separate scaler needed at inference time.
- **Pipeline-aware `SupervisedEngine`** — `_get_classifier()`, `_get_n_features()`, `_get_classes()` helpers unwrap `Pipeline` objects; supports both Pipeline and plain estimator formats transparently.
- **`MLFLOW_TRACKING_URI` default** — points to homelab server (`your-mlflow-host:5050`); set to empty to disable.

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
- **Extended Prometheus metrics** — `cnds_alerts_suppressed_total` counter (labels: `reason=dedup|suppression_rule`) and `cnds_ensemble_score` histogram (fine-grained buckets, label: `is_anomaly`).
- **Engine label on alert counter** — `cnds_alerts_total` now includes `engine` label (primary engine by score contribution).
- **`observe_ensemble_score()`** — called on every `/api/predict` request regardless of whether an alert fires.
- **`inc_suppressed()`** — incremented on both dedup hits and suppression rule matches.
- **Test suites** — `test_predict.py`, `test_pipeline.py`, `test_suppression.py`, `test_correlation.py` (67 tests).

## [1.0.4] - 2026-03-31

### Changed

- **Pipeline extraction** — detection pipeline callback (`on_flow_complete`, alert persistence, dedup, trusted-outbound filtering) extracted from `main.py` into `src/pipeline.py` for cleaner separation of concerns
- **CIDR support for IP lists** — `IP_ALLOWLIST` and `IP_BLOCKLIST` now accept CIDR ranges (e.g. `10.0.0.0/8,192.168.1.50`) in addition to individual IPs
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
