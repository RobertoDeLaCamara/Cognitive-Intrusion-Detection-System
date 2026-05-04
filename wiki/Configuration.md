# Configuration

All settings are driven by environment variables. Copy `.env.example` to `.env` and adjust as needed.

Configuration is validated on startup. Invalid settings (e.g., weights not summing to 1.0, thresholds out of range) cause a `ConfigurationError`.

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
| `MIN_PACKETS_FOR_ML` | `10` | Min packets before ML engines activate |
| `MAX_PAYLOAD_SAMPLES` | `50` | Max payload samples stored per flow |
| `PAYLOAD_SAMPLE_BYTES` | `4096` | Max bytes kept per payload sample |
| `JA3_ENABLED` | `true` | Extract JA3 fingerprints from TLS ClientHello |
| `MALICIOUS_JA3_FILE` | _(empty)_ | Path to known-malicious JA3 hashes (one per line) |

## Ensemble & Scoring

| Variable | Default | Description |
|---|---|---|
| `ENSEMBLE_THRESHOLD` | `0.55` | Score above which an alert fires |
| `WEIGHT_SUPERVISED` | `0.40` | Supervised engine weight |
| `WEIGHT_IFOREST` | `0.30` | Isolation Forest weight |
| `WEIGHT_LSTM` | `0.20` | LSTM weight |
| `WEIGHT_RULES` | `0.10` | Rules weight |
| `ATTACK_TYPE_WEIGHTS` | `{}` | JSON: per-attack-type engine weight overrides |
| `CALIBRATION_TEMPERATURE` | `1.0` | Platt scaling temperature (>1 softer, <1 sharper) |

## Rules Engine Thresholds

| Variable | Default | Description |
|---|---|---|
| `LARGE_PAYLOAD_BYTES` | `10000` | Payload size (bytes) that triggers the large-payload rule |
| `RATE_SPIKE_MULTIPLIER` | `2.0` | Multiplier for rate-spike rule detection |
| `ICMP_FLOOD_THRESHOLD` | `50` | ICMP packet count that triggers flood rule |
| `PORT_SCAN_THRESHOLD` | `20` | SYN count threshold for scan detection |

## Alert Management

| Variable | Default | Description |
|---|---|---|
| `ALERT_COOLDOWN_SECS` | `60` | Seconds before a duplicate alert can fire again |
| `DEDUP_WINDOW_SECS` | `300` | Alert deduplication window (seconds) |
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
| `API_HOST` | `0.0.0.0` | API bind address |
| `API_PORT` | `8000` | API listen port |
| `API_KEY` | _(empty)_ | Bearer token; leave empty to disable auth |
| `CORS_ORIGINS` | _(empty)_ | Comma-separated allowed origins |
| `RATE_LIMIT_REQUESTS` | `60` | Max API requests per window per IP |
| `RATE_LIMIT_WINDOW` | `60` | Rate limit window (seconds) |

## Authentication

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET` | _(empty)_ | JWT signing secret; empty disables JWT auth |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `JWT_EXPIRE_MINUTES` | `60` | JWT token expiry (minutes) |

## Observability

| Variable | Default | Description |
|---|---|---|
| `Monitoring Service_ENABLED` | `false` | Enable Monitoring Service metrics at `/metrics` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | _(empty)_ | OpenTelemetry OTLP endpoint |
| `ML Tracking_TRACKING_URI` | _(empty)_ | ML Tracking server URL; empty disables ML Tracking |
| `ML Tracking_REGISTRY_NAME` | `cnds` | ML Tracking model registry name |
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

## IP Lists

| Variable | Default | Description |
|---|---|---|
| `IP_ALLOWLIST` | _(empty)_ | Comma-separated IPs or CIDR ranges to skip detection entirely |
| `IP_BLOCKLIST` | _(empty)_ | Comma-separated IPs or CIDR ranges to auto-flag as critical |
