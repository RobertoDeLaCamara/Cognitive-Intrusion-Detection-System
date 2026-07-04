# Deployment

## Docker Compose (Recommended)

The included `docker-compose.yml` runs four services:

| Service | Container | Port | Description |
|---|---|---|---|
| `api` | `cnds-api` | 8000 | FastAPI REST API + alert persistence |
| `detector` | `cnds-detector` | host network | Scapy packet capture + detection pipeline |
| `dashboard` | `cnds-dashboard` | 8501 | Streamlit real-time analytics dashboard |
| `postgres` | `cnds-postgres` | 5432 (internal) | Required — see Database Concurrency below |

```bash
docker-compose up -d
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
- [ ] Set `API_KEY` or use JWT auth — don't leave the API open
- [ ] Pin `CAPTURE_INTERFACE` to the correct network interface
- [ ] Set `LOG_FORMAT=json` for structured logging compatible with ELK/Loki/CloudWatch
- [ ] Enable `Monitoring Service_ENABLED=true` and configure scraping
- [ ] Configure `WEBHOOK_URLS` or `TELEGRAM_BOT_TOKEN` for alert notifications
- [ ] Set `IP_ALLOWLIST` for trusted infrastructure IPs (monitoring, load balancers)
- [ ] Review and tune `ENSEMBLE_THRESHOLD` and engine weights for your environment
- [ ] Set up SIEM integration (see [SIEM Integration](SIEM-Integration))
- [ ] If enabling the Guardian, review `GUARDIAN_WHITELIST` first — never a broad LAN CIDR — and keep `GUARDIAN_ENABLED=false` until it's populated

## Guardian Auto-Response (Optional)

Off by default (`GUARDIAN_ENABLED=false`). A background task in the `api` process polls the alerts table and, for alerts at or above `GUARDIAN_MIN_SEVERITY` (default `critical`), blocks the offending `src_ip` via AdGuard Home's DNS access-control API — unless it's in `GUARDIAN_WHITELIST`, already has an active action, or the circuit breaker (`GUARDIAN_CIRCUIT_MAX_ACTIONS`/`_WINDOW_SECS`) has tripped. Every block auto-expires after `GUARDIAN_BLOCK_MINUTES` (rollback) unless confirmed permanent via Telegram inline buttons (`TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`, long-polling `getUpdates` — no webhook needed). All actions are logged in the `mitigation_actions` table.

```bash
GUARDIAN_ENABLED=true
GUARDIAN_MIN_SEVERITY=critical
GUARDIAN_BLOCK_MINUTES=30
GUARDIAN_WHITELIST=[GATEWAY_IP],[YOUR_DEVICE_IPS]   # never a broad /24
ADGUARD_URL=http://[ADGUARD_HOST]:8001
ADGUARD_USERNAME=
ADGUARD_PASSWORD=
```

See [Configuration](Configuration) for the full variable list and [Deployment guide](../doc/deployment.md#guardian-auto-response-setup) in the main repo for the step-by-step setup/verification checklist.

## Streamlit Dashboard

The dashboard (`dashboard/app.py`) provides:
- Real-time alert feed
- Top talkers view
- Attack type breakdown
- Timeline visualization

Access at `http://localhost:8501` when running via Docker Compose.
