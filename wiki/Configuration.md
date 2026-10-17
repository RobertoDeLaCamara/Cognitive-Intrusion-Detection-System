# Configuration

All settings are driven by environment variables. Copy `.env.example` to `.env` and adjust as needed.

`docker-compose.yml` loads `.env.example` then `.env` into the `api`, `detector` and `demo-seed` containers. The Python code does not read `.env` itself: for a bare run export the variables (`uvicorn src.api.main:app --env-file .env`, or `set -a; . ./.env; set +a; sudo -E venv/bin/python main.py`). Defaults below are those of `src/config.py`; `.env.example` overrides a few of them (notably the five `WEIGHT_*` values).

Configuration is validated on startup (`src/config.py`). Invalid settings (the five engine weights not summing to 1.0 ± 0.01, `ENSEMBLE_THRESHOLD` outside [0, 1], `CALIBRATION_TEMPERATURE` outside (0, 10], `FT_TEMPERATURE` outside [0.1, 10], non-positive `FLOW_TIMEOUT` / `PACKET_WORKERS` / Guardian intervals, an unknown `GUARDIAN_MIN_SEVERITY`) cause a `ConfigurationError`.

Variables marked _reserved_ are defined in `src/config.py` but no runtime code reads them today.

## Capture & Flow Settings

| Variable | Default | Description |
|---|---|---|
| `CAPTURE_INTERFACE` | auto | Network interface (e.g. `eth0`) |
| `PACKET_WORKERS` | `4` | Async worker threads |
| `PACKET_QUEUE_SIZE` | `20000` | Internal packet queue size |
| `FLOW_TIMEOUT` | `120` | Seconds before idle flow is flushed |
| `MAX_ACTIVE_FLOWS` | `50000` | Max simultaneous tracked flows |
| `ACTIVE_IDLE_THRESH` | `1.0` | Seconds of inactivity to mark a flow idle |

## Feature Extraction

| Variable | Default | Description |
|---|---|---|
| `HOST_WINDOW_SIZE` | `100` | Packet history window per IP for host features |
| `MAX_TRACKED_IPS` | `5000` | Max IPs tracked by host extractor / LSTM buffers |
| `MIN_PACKETS_FOR_ML` | `10` | _Reserved_ — the host extractor actually returns features once an IP has seen 3 packets |
| `MAX_PAYLOAD_SAMPLES` | `50` | Max payload samples stored per flow |
| `PAYLOAD_SAMPLE_BYTES` | `4096` | Max bytes kept per payload sample |
| `JA3_ENABLED` | `true` | Extract JA3 fingerprints from TLS ClientHello |
| `MALICIOUS_JA3_FILE` | _(empty)_ | Path to known-malicious JA3 hashes (one per line) |

## Ensemble & Scoring

| Variable | Default | Description |
|---|---|---|
| `ENSEMBLE_THRESHOLD` | `0.55` | Score above which an alert fires |
| `WEIGHT_SUPERVISED` | `0.30` | Supervised engine weight |
| `WEIGHT_IFOREST` | `0.20` | Isolation Forest weight |
| `WEIGHT_LSTM` | `0.10` | LSTM weight |
| `WEIGHT_RULES` | `0.25` | Rules weight (raised from 0.05 so a signature match is felt in the blend) |
| `WEIGHT_BASELINE` | `0.15` | Unsupervised baseline engine weight |
| `ATTACK_TYPE_WEIGHTS` | `{}` | JSON: per-attack-type engine weight overrides, keyed by the supervised label; engine keys are `supervised`, `isolation_forest`, `lstm`, `rules`, `baseline` |
| `CALIBRATION_TEMPERATURE` | `1.0` | Platt scaling temperature (>1 softer, <1 sharper) |
| `CRITICAL_RULES` | `payload:sql_injection,payload:command_injection,payload:log4j,payload:shellshock,payload:xss,payload:path_traversal,malicious_ja3` | Comma-separated rules that force score 1.0 / alert regardless of the blend |
| `FT_TEMPERATURE` | `2.0` | FT-Transformer logit temperature; `1.0` disables |

## Rules Engine Thresholds

| Variable | Default | Description |
|---|---|---|
| `LARGE_PAYLOAD_BYTES` | `10000` | Largest forward packet size (bytes) that triggers the `large_payload` rule |
| `RATE_SPIKE_MULTIPLIER` | `2.0` | _Reserved_ — there is no rate-spike rule in `src/engines/rules.py` |
| `ICMP_FLOOD_THRESHOLD` | `50` | ICMP packet count that triggers flood rule |
| `PORT_SCAN_THRESHOLD` | `20` | SYN count threshold for scan detection |

## Alert Management

| Variable | Default | Description |
|---|---|---|
| `ALERT_COOLDOWN_SECS` | `60` | _Reserved_ — duplicate suppression is `DEDUP_WINDOW_SECS` |
| `DEDUP_WINDOW_SECS` | `300` | Deduplication window per `(src_ip, attack_type)` (seconds) |
| `CONFIDENCE_DECAY_FACTOR` | `0.9` | Score multiplier per repeat alert from same IP |
| `CONFIDENCE_DECAY_WINDOW` | `300` | Seconds to track repeat alerts for decay |
| `CORRELATION_WINDOW_SECS` | `300` | Time window for alert correlation (seconds) |
| `CORRELATION_THRESHOLD` | `5` | Alerts from same IP before auto-incident creation |

## Model Files

| Variable | Default | Description |
|---|---|---|
| `MODELS_DIR` | `models` | Directory containing model files |
| `FT_MODEL_FILE` | `unified/unified_ft_transformer.pt` | FT-Transformer checkpoint (preferred supervised) |
| `FT_SCALER_FILE` | `unified/unified_scaler.pkl` | StandardScaler matched to the FT checkpoint |
| `FT_USE_GPU` | `false` | Run FT-T inference on CUDA when available |
| `FT_SCORE_THRESHOLD` | `0.50` | Min FT anomaly score (1 − P(Benign)) to contribute |
| `MLFLOW_FT_REGISTRY_NAME` | `ml-ids-unified-ft-transformer` | MLflow registered model name to load FT from |
| `MLFLOW_FT_STAGE` | `None` | MLflow stage to pin (default = latest version) |
| `RF_MODEL_FILE` | `rf_model.joblib` | Random Forest model filename (fallback) |
| `RF_LITE_MODEL_FILE` | `rf_lite_model.joblib` | Bundled lite RF model (committed, second-tier fallback) |
| `RF_SCORE_THRESHOLD` | `0.90` | Min RF anomaly score to avoid false positives |
| `IF_CONTAMINATION`, `IF_N_ESTIMATORS`, `IF_MIN_SAMPLES`, `IF_TRAINING_STATUS_FILE` | `0.05`, `200`, `100`, `/tmp/cnds_if_training_status.json` | _Reserved_ — not read; the baseline trainer uses its own defaults |
| `IF_MODEL_FILE` | `isolation_forest.joblib` | Isolation Forest model filename |
| `IF_SCALER_FILE` | `if_scaler.joblib` | IF scaler filename |
| `LSTM_MODEL_FILE` | `lstm_autoencoder.pt` | LSTM model filename |
| `LSTM_CONFIG_FILE` | `lstm_config.json` | LSTM config filename |

## Database

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite+aiosqlite:///./cnds.db` | SQLite or PostgreSQL URL |

## API Server

| Variable | Default | Description |
|---|---|---|
| `API_HOST` | `0.0.0.0` | _Reserved_ — the bind address is fixed by the uvicorn command / `main.py` |
| `API_PORT` | `8000` | _Reserved_ — see `API_HOST` |
| `API_KEY` | _(empty)_ | Static key matched against the `X-API-Key` header; empty means no key check, and then `JWT_SECRET` or `AUTH_DISABLED=true` is required to start |
| `AUTH_DISABLED` | `false` | Only the literal `true` lets the API start with no `API_KEY` or `JWT_SECRET` (logs a warning); lab/local use only |
| `CORS_ORIGINS` | _(empty)_ | Comma-separated allowed origins; empty falls back to `http://localhost:3000` |
| `RATE_LIMIT_REQUESTS` | `60` | Max API requests per window per IP |
| `RATE_LIMIT_WINDOW` | `60` | Rate limit window (seconds) |

## Authentication

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET` | _(empty)_ | JWT signing secret; empty disables JWT auth (then `API_KEY` or `AUTH_DISABLED=true` is required to start) |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `JWT_EXPIRE_MINUTES` | `60` | JWT token expiry (minutes) |

## Observability

| Variable | Default | Description |
|---|---|---|
| `PROMETHEUS_ENABLED` | `false` | Enable Prometheus metrics at `/metrics` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | _(empty)_ | OpenTelemetry OTLP endpoint |
| `MLFLOW_TRACKING_URI` | _(empty)_ | MLflow server URL; empty disables MLflow |
| `MLFLOW_REGISTRY_NAME` | `cnds` | MLflow model registry name |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `MLFLOW_S3_ENDPOINT_URL` | _(unset)_ | Standard S3 settings read by MLflow/boto3 for the artifact store (not parsed by `src/config.py`) |
| `LOG_FORMAT` | `text` | Log output format: `text` or `json` (structured) |

## Enrichment & Notifications

| Variable | Default | Description |
|---|---|---|
| `GEOIP_DB_PATH` | _(empty)_ | Path to GeoLite2-City.mmdb; empty disables GeoIP |
| `ADAPTIVE_WEIGHTS_ENABLED` | `false` | Enable adaptive engine weight computation |
| `ADAPTIVE_MIN_SAMPLES` | `100` | Min acknowledged alerts before adapting weights |
| `WEBHOOK_URLS` | _(empty)_ | Comma-separated webhook/Slack notification URLs |
| `NOTIFY_MIN_SEVERITY` | `high` | Minimum severity to trigger webhook notification |
| `TELEGRAM_BOT_TOKEN` | _(empty)_ | Telegram bot token; empty disables |
| `TELEGRAM_CHAT_ID` | _(empty)_ | Telegram chat/group ID |
| `DNS_LOGGING_ENABLED` | `false` | Enable DNS query logging from captured traffic |
| `TRUSTED_OUTBOUND` | `{}` | JSON `{"<src_ip>": ["domain.suffix", ...]}`; capture-pipeline flows from that IP to a reverse-resolved matching host skip detection |

## IP Lists

| Variable | Default | Description |
|---|---|---|
| `IP_ALLOWLIST` | _(empty)_ | Comma-separated IPs or CIDR ranges to skip detection entirely |
| `IP_BLOCKLIST` | _(empty)_ | Comma-separated IPs or CIDR ranges to auto-flag as critical |

## Guardian Auto-Response

| Variable | Default | Description |
|---|---|---|
| `GUARDIAN_ENABLED` | `false` | Master switch for the auto-response module |
| `GUARDIAN_MIN_SEVERITY` | `critical` | Minimum alert severity that triggers an auto-block |
| `GUARDIAN_POLL_INTERVAL_SECS` | `15` | How often the guardian polls the alerts table |
| `GUARDIAN_BLOCK_MINUTES` | `30` | How long an auto-block lasts before automatic rollback |
| `GUARDIAN_WHITELIST` | `192.168.1.1,192.168.1.62` | Comma-separated IPs/CIDRs the guardian never blocks — **never a broad LAN CIDR**, see [Deployment](Deployment.md) |
| `GUARDIAN_CIRCUIT_MAX_ACTIONS` | `5` | Max auto-blocks within the circuit-breaker window before pausing |
| `GUARDIAN_CIRCUIT_WINDOW_SECS` | `600` | Circuit-breaker window (seconds) |
| `ADGUARD_URL` | `http://192.168.1.62:8001` | AdGuard Home base URL (the current enforcement backend) |
| `ADGUARD_USERNAME` | _(empty)_ | AdGuard Home basic-auth username |
| `ADGUARD_PASSWORD` | _(empty)_ | AdGuard Home basic-auth password |

## Threat Intelligence Feeds

| Variable | Default | Description |
|---|---|---|
| `ABUSEIPDB_URL` | _(empty)_ | AbuseIPDB blacklist URL; empty disables the IP feed |
| `ABUSEIPDB_API_KEY` | _(empty)_ | AbuseIPDB API key |
| `MALICIOUS_JA3_URL` | _(empty)_ | URL of a known-bad JA3 hash list (one per line) |
| `MISP_URL`, `MISP_API_KEY` | _(empty)_ | MISP instance and key |
| `THREAT_INTEL_REFRESH_MINUTES` | `60` | Refresh interval |

(`.env.example` pre-fills `ABUSEIPDB_URL` and `MALICIOUS_JA3_URL`; the code defaults are empty.)

## Unsupervised Baseline

| Variable | Default | Description |
|---|---|---|
| `BASELINE_COLLECTION_ENABLED` | `true` | Collect host vectors and train baseline models (read by `main.py`) |
| `BASELINE_DRIFT_WARN` | `0.30` | Drift score for the `warning` verdict |
| `BASELINE_DRIFT_CRIT` | `0.60` | Drift score for the `critical` verdict |

## Triage Agent (`python -m src.triage`)

| Variable | Default | Description |
|---|---|---|
| `TRIAGE_MODE` | `workflow` | `workflow` (no tools) or `agent` (read-only MCP tools) |
| `TRIAGE_MIN_SEVERITY` | `high` | Lowest severity annotated |
| `TRIAGE_LOOKBACK_HOURS` | `24` | Lookback for unannotated alerts |
| `TRIAGE_BATCH_SIZE` | `10` | Alerts per run |
| `TRIAGE_MIN_CONFIDENCE` | `0.6` | Below this the verdict becomes `needs_human` |
| `TRIAGE_DAILY_BUDGET_USD` | `2.0` | Rolling 24 h spend cap |
| `TRIAGE_MAX_USD_PER_ALERT` | `0.25` | Per-call spend cap |
| `TRIAGE_MAX_TURNS` | `8` | Max agent turns |
| `TRIAGE_TIMEOUT_SECS` | `180` | Per-call timeout |
| `TRIAGE_POLL_INTERVAL_SECS` | `300` | `--loop` interval |
| `TRIAGE_CLAUDE_BIN` | `claude` | Claude CLI binary |
| `TRIAGE_CLAUDE_MODEL` | _(empty)_ | Empty = CLI default |
| `TRIAGE_CLAUDE_BARE` | `true` | `--bare` needs `ANTHROPIC_API_KEY`; `false` uses the CLI login |
| `TRIAGE_MCP_CONFIG` | _(empty)_ | Agent mode only: MCP config registering the read-only `cnds` server |

## Compose and tooling variables

| Variable | Used by | Description |
|---|---|---|
| `POSTGRES_PASSWORD` | `docker-compose.yml` | Required; compose refuses to start without it |
| `CNDS_API_URL` | `dashboard/app.py` | API base URL for the dashboard (default `http://localhost:8000`) |
