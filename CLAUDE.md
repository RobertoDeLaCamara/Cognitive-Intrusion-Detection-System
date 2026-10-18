# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Setup
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# Run (requires root for raw sockets)
sudo venv/bin/python main.py --iface eth0 --api

# API only (no capture)
uvicorn src.api.main:app --host 0.0.0.0 --port 8000

# Tests
pytest tests/ -v
pytest tests/ --cov=src --cov-report=term-missing
pytest tests/test_flow_extractor.py -v          # single module

# Database migrations
alembic revision --autogenerate -m "describe change"
alembic upgrade head

# Train supervised model (requires CIC-UNSW-NB15 dataset)
python scripts/train_rf.py --data-dir /path/to/CIC-UNSW-NB15
```

## Architecture

Traffic flows through the system in this order:

1. **Capture layer** (`src/capture/`): Scapy sniffs packets → `PacketProcessor` queues them across 4 worker threads → `Dispatcher` tracks flows and calls `on_flow_complete()` when a flow expires (timeout or idle).

2. **Feature extraction** (`src/features/`): On flow expiry, three parallel extractors produce:
   - `flow_extractor.py` → 76 CICFlowMeter-compatible flow features
   - `host_extractor.py` → 18 per-IP host features (sliding window per IP)
   - `payload_analyzer.py` → regex pattern matches + 10 numeric payload features
   - `ja3.py` → JA3 MD5 fingerprint from TLS ClientHello

3. **Detection engines** (`src/engines/`): All engines are instantiated as singletons in `registry.py` and implement the `DetectionEngine` protocol from `protocol.py`. Engines gracefully degrade when model files are absent (`is_available` flag):
   - `ft_transformer_engine.py` — preferred supervised engine (unified FT-Transformer, 76 flow features, UNSW-NB15 classes); loaded from MLflow, then `models/unified/`; needs `torch`. `registry.py` picks it when its checkpoint is available
   - `supervised.py` — Random Forest fallback on 76 flow features; bundled lite model at `models/rf_lite_model.joblib` works out of the box
   - `isolation_forest.py` — novelty scoring on 18 host features
   - `lstm_autoencoder.py` — sequence reconstruction error on host feature time-series per IP
   - `rules.py` — threshold/pattern rules including JA3 blocklist checks
   - `baseline_engine.py` — live-trained IsolationForest+LSTM from the unsupervised pipeline

4. **Ensemble** (`src/ensemble/scorer.py`): `EnsembleScorer.score()` takes an `EngineScores` dataclass, redistributes weights of unavailable engines proportionally, applies Platt temperature calibration, and returns an `EnsembleResult`. Default weights (`src/config.py`): supervised 30%, iforest 20%, lstm 10%, rules 25%, baseline 15%. Weights must sum to 1.0 (±0.01) or startup raises `ConfigurationError`. Any rule listed in `CRITICAL_RULES` forces score 1.0 and an alert regardless of the blend; a threat-intel hit adds +0.30. Severity (`severity_from_score`): ≥0.85 critical, ≥0.70 high, ≥0.55 medium, else low; DoS/DDoS/Infiltration/Web Attack labels reach critical from 0.70.

5. **Pipeline callback** (`src/pipeline.py`): `on_flow_complete()` is the central callback wiring features → engines → ensemble → deduplication → alert persistence. Alert writes are off-loaded to a background writer thread via a bounded queue to avoid blocking capture workers.

6. **Unsupervised baseline** (`src/unsupervised/`): A background pipeline continuously collects host feature vectors. `CompositeTrigger` fires when four conditions are all met (50k vectors, 20 distinct IPs, 30 min elapsed, port entropy ≥ 2.5 bits); a 500k-vector hard cap also forces a window. `WindowTrainer` then fits a new IsolationForest + LSTM Autoencoder and logs artifacts to MLflow under experiment `cnds-unsupervised-baseline`.

7. **API** (`src/api/`): Async FastAPI app with SQLAlchemy (aiosqlite/asyncpg). Alembic migrations run automatically on startup. The API refuses to start unless `API_KEY`, `JWT_SECRET` or `AUTH_DISABLED=true` is set: `API_KEY` adds an `X-API-Key` header check on (almost) every route; `JWT_SECRET` enables Bearer tokens (roles `admin`/`analyst`/`viewer`) enforced with `require_role` on every route except `/health`, `/metrics` and `/api/auth/token` (reads: any role; writes: analyst/admin; user admin: admin). An `API_KEY` caller is admin-equivalent. WebSocket endpoint `/ws/alerts` streams alerts that arrive through `POST /api/predict` (JWT on: `?token=`; key-only: `X-API-Key` header or `?key=`). The Guardian background tasks start in the API lifespan when `GUARDIAN_ENABLED=true`.

8. **Enrichment** (`src/enrichment/`): Every persisted alert gets MITRE ATT&CK mappings (`mitre.py`) and optional GeoIP (`geoip.py`) on both the capture and API paths. Only the `POST /api/predict` path additionally applies IP allow/block lists, confidence decay, suppression rules, correlation (`correlation.py`, auto-incident when the same IP reaches ≥ `CORRELATION_THRESHOLD` alerts within `CORRELATION_WINDOW_SECS`), the WebSocket broadcast and webhook/Telegram notifications (`notifications.py`); the capture pipeline (`src/pipeline.py`) does not call them.

9. **MCP server + triage agent** (`src/mcp_server/`, `src/triage/`): the MCP server is read-only at the DB engine and has no enforcement tools. The triage agent (`python -m src.triage`, out of process) writes only the append-only `triage_annotations` table — never `alerts` workflow fields, never `mitigation_actions`. The Guardian and the human are the only actuators; keep it that way (`tests/test_triage.py::test_triage_package_has_no_actuation_paths`). See `doc/triage-agent.md`.

## Key design constraints

- **SQLite does not support concurrent writers.** When running `main.py --api`, only one process writes; for multi-container Docker deployments use `DATABASE_URL=postgresql+asyncpg://...`.
- **Engine weights** (including `WEIGHT_BASELINE`) must sum to 1.0 (±0.01) — validated at import time in `src/config.py`.
- **Model files** are gitignored (`models/**/*.joblib|pt|pkl`) except `rf_lite_model.joblib` (1.6 MB bundled), `lstm_config.json` and the small `*_meta.json` / `unified/unified_metadata.json` files. Missing engines are skipped, not errors.
- **Reserved config values:** `API_HOST`, `API_PORT`, `MIN_PACKETS_FOR_ML`, `RATE_SPIKE_MULTIPLIER`, `ALERT_COOLDOWN_SECS` and `IF_*` are defined in `src/config.py` but no runtime code reads them.
- **`pytest.ini`** sets `asyncio_mode = auto` — all async tests run without explicit `@pytest.mark.asyncio`.
- Test fixtures and an in-memory DB are in `tests/conftest.py`.
- **`torch` is not in `requirements.txt`** — it is installed separately in Docker to force the CPU build. Tests that require torch use `pytest.importorskip("torch")` and skip gracefully in bare environments.
- **GeoIP is disabled by default** (`GEOIP_DB_PATH` empty). `geoip.lookup()` returns `None` when no DB is configured; `geoip.is_enabled()` returns `False`. The mock data that was previously embedded in `geoip.py` has been removed.

## Known invariants (do not break)

- `SupervisedEngine._build_vec()` always calls `.ravel()` before `reshape(1, -1)` to handle both 1D and 2D input arrays.
- `_resolve_hostname()` in `pipeline.py` runs in a `ThreadPoolExecutor` with a 2-second timeout — never blocks the capture worker threads.
- Alert writer thread (`_writer_thread`) is drained via `drain_alert_queue()` before `sys.exit()` in the shutdown handler — ensures pending alerts are persisted on Ctrl+C.
- Dedup cache cleanup runs on a time-based trigger (every 300 s) rather than a size threshold, so low-rate traffic doesn't cause unbounded cache growth.
- `LSTMAutoencoderEngine._load()` reads `lstm_config.json` exactly once; all architecture kwargs (`hidden_dim`, `latent_dim`, `num_layers`, `dropout`) come from the same parsed dict.
