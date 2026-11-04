# Deployment

## Docker Compose (Recommended)

The included `docker-compose.yml` defines these services (the first three start by default; `dashboard` and `demo-seed` are opt-in profiles). `POSTGRES_PASSWORD` must be set in `.env` — compose refuses to start without it.

| Service | Container | Port | Description |
|---|---|---|---|
| `api` | `cnds-api` | 8000 | FastAPI REST API + alert persistence |
| `detector` | `cnds-detector` | host network | Scapy packet capture + detection pipeline |
| `postgres` | `cnds-postgres` | 127.0.0.1:5432 | Required — see Database Concurrency below |
| `dashboard` | `cnds-dashboard` | 8501 | Streamlit analytics dashboard; profile `dashboard` |
| `demo-seed` | `cnds-demo-seed` | — | One-shot synthetic data seeder; profile `demo` |

```bash
docker-compose up -d                          # postgres + api + detector
docker-compose --profile dashboard up -d      # add the Streamlit dashboard
```

**arm64 / Raspberry Pi:** without `docker buildx build --platform ...`, the Dockerfile's `ARG TARGETARCH` silently defaults to `amd64` even on an arm64 host. Build with `docker compose build --build-arg TARGETARCH=arm64` explicitly.

### Important: Database Concurrency

The default SQLite backend does not support concurrent writers, and `api`/`detector` run as **separate containers** in this compose file — this isn't just a "recommendation," SQLite will corrupt or lose writes under this topology. PostgreSQL is part of the default compose stack:

```bash
DATABASE_URL=postgresql+asyncpg://user:pass@db:5432/cnds
```

### Detector Privileges

The detector container runs as `root` with `network_mode: host` because Scapy requires raw socket access for packet capture.

## Database Migrations

CNDS uses [Alembic](https://alembic.sqlalchemy.org/) for schema versioning. On startup, the API automatically runs pending migrations (falling back to `create_all` for in-memory test databases).

```bash
# Generate a new migration after changing models
alembic revision --autogenerate -m "describe your change"

# Apply all pending migrations
alembic upgrade head

# Downgrade one step
alembic downgrade -1

# View current revision
alembic current
```

Migration files live in `alembic/versions/` and are tracked in git.

## Production Checklist

- [ ] Use PostgreSQL instead of SQLite for concurrent access
- [ ] Set `JWT_SECRET` to a strong random value to enable authentication
- [ ] Configure `CORS_ORIGINS` to restrict allowed origins
- [ ] Set `API_KEY` (checks every route) and/or `JWT_SECRET` (role checks on every route except `/health`, `/metrics` and `/api/auth/token`; give the dashboard its own account via `CNDS_API_USER` / `CNDS_API_PASSWORD`). One of them is required: with neither, the API refuses to start unless `AUTH_DISABLED=true` (lab use only). Seed the first admin directly in the database, see [API Reference](API-Reference.md#authentication)
- [ ] Pin `CAPTURE_INTERFACE` to the correct network interface
- [ ] Set `LOG_FORMAT=json` for structured logging compatible with ELK/Loki/CloudWatch
- [ ] Enable `PROMETHEUS_ENABLED=true` and configure scraping
- [ ] Configure `WEBHOOK_URLS` or `TELEGRAM_BOT_TOKEN` for alert notifications
- [ ] Set `IP_ALLOWLIST` for trusted infrastructure IPs (monitoring, load balancers)
- [ ] Review and tune `ENSEMBLE_THRESHOLD` and engine weights for your environment
- [ ] Set up SIEM integration (see [SIEM Integration](SIEM-Integration.md))
- [ ] If enabling the Guardian, review `GUARDIAN_WHITELIST` first — never a broad LAN CIDR — and keep `GUARDIAN_ENABLED=false` until it's populated

## Guardian Auto-Response (Optional)

Off by default (`GUARDIAN_ENABLED=false`). A background task in the `api` process polls the alerts table and, for alerts at or above `GUARDIAN_MIN_SEVERITY` (default `critical`), blocks the offending `src_ip` via AdGuard Home's DNS access-control API — unless it's in `GUARDIAN_WHITELIST`, already has an active action, or the circuit breaker (`GUARDIAN_CIRCUIT_MAX_ACTIONS`/`_WINDOW_SECS`) has tripped. Every block auto-expires after `GUARDIAN_BLOCK_MINUTES` (rollback) unless confirmed permanent via Telegram inline buttons (`TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`, long-polling `getUpdates` — no webhook needed). All actions are logged in the `mitigation_actions` table.

```bash
GUARDIAN_ENABLED=true
GUARDIAN_MIN_SEVERITY=critical
GUARDIAN_BLOCK_MINUTES=30
GUARDIAN_WHITELIST=192.168.1.1,192.168.1.10,192.168.1.11   # never a broad /24
ADGUARD_URL=http://192.168.1.62:8001
ADGUARD_USERNAME=
ADGUARD_PASSWORD=
```

See [Configuration](Configuration.md) for the full variable list and the [deployment guide](https://github.com/RobertoDeLaCamara/Cognitive-Intrusion-Detection-System/blob/master/doc/deployment.md#guardian-auto-response-setup) in the main repo for the step-by-step setup/verification checklist.

## Streamlit Dashboard

The dashboard (`dashboard/app.py`) is a Streamlit client of the REST API with six tabs: alerts (with in-place acknowledge), trends, top talkers, engines, MITRE and geo-intel. The UI labels are in Spanish, and it sends no `X-API-Key` / Bearer header, so it cannot talk to an API that has `API_KEY` set.

Access at `http://localhost:8501` when started with `docker-compose --profile dashboard up -d`, or run it by hand with `pip install -r requirements-dashboard.txt && streamlit run dashboard/app.py` (it reads `CNDS_API_URL`, default `http://localhost:8000`).

## Operating Notes

- **`[ALERT]` vs `[SUPPRESSED]`.** The detector logs `[ALERT]` when an alert is scored, *before* suppression rules are evaluated. Alerts then dropped by a rule are logged as `[SUPPRESSED] src=… | dst=… | dport=… | score=… | type=… | rule=#N`. Count `[SUPPRESSED]` to separate them: the number of `[ALERT]` lines overstates what reaches the database.
- **Tune suppression rules narrowly.** Prefer `src_ip` / `dst_ip` together with `dst_port` (up to 365 days) over IP-wide rules (at most 7 days). Review the top `[SUPPRESSED]` flows after the first days: a monitoring probe or a proxy is the usual source.
- **Baseline training takes time.** `GET /api/baseline/status` and the `baseline_progress` log line show which trigger threshold is the bottleneck. On a small LAN lower `BASELINE_MIN_SRC_IPS`; a retrain window that arrives with a very different LSTM threshold is held back by the stability gate (`BASELINE_THRESHOLD_MAX_RATIO`). Every detector restart empties the in-memory collection window.
- **Memory.** The detector holds the collection window in RAM. The compose file limits it to 2 GB; on a small board watch `docker stats` after the first retrains.
- **Threat-intel feeds are optional.** The IP feed needs `ABUSEIPDB_API_KEY`; without it the feed is skipped with one warning. The default JA3 list is a static abuse.ch file last updated in 2021.
- **Labels feed tuning.** Mark alerts `tp` / `fp` (`PATCH /api/alerts/{id}`) and read `GET /api/feedback-stats` before changing weights or `ENSEMBLE_THRESHOLD`.

## Upgrading to 2.0

2.0 changes defaults for security; check these before upgrading a 1.x deployment:

1. **Set `API_KEY` or `JWT_SECRET`.** The API exits at start-up without one (or `AUTH_DISABLED=true`, lab use only).
2. **JWT deployments:** every client, including the dashboard and `scripts/demo_seed.py`, must send a token or `CNDS_API_KEY`.
3. **Apply migrations before starting the detector:** recreate the `api` service first (it runs Alembic), then the detector.
4. **Rebuild the image.** Dependencies are hash-pinned (`requirements-lock-*.txt`) and torch is 2.6.0.
5. **Optional:** set `METRICS_TOKEN`, and `GUARDIAN_ALERT_SOURCES` if you relied on `/api/predict` alerts triggering the Guardian.
