# Deployment

## Docker Compose (Recommended)

The included `docker-compose.yml` runs three services:

| Service | Container | Port | Description |
|---|---|---|---|
| `api` | `cnds-api` | 8000 | FastAPI REST API + alert persistence |
| `detector` | `cnds-detector` | host network | Scapy packet capture + detection pipeline |
| `dashboard` | `cnds-dashboard` | 8501 | Streamlit real-time analytics dashboard |

```bash
docker-compose up -d
```

### Important: Database Concurrency

The default SQLite backend does not support concurrent writers. In the Docker Compose setup:
- Only the `api` service mounts the DB volume and writes to the database.
- The `detector` service persists alerts via the API (`CNDS_API_URL=http://api:8000`), not directly to the DB.

For production multi-container deployments, use PostgreSQL:

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

## Streamlit Dashboard

The dashboard (`dashboard/app.py`) provides:
- Real-time alert feed
- Top talkers view
- Attack type breakdown
- Timeline visualization

Access at `http://localhost:8501` when running via Docker Compose.
