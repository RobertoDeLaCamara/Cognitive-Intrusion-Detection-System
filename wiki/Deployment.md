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

The detector container runs as `root` with `network_mode: host` because Scapy requires raw socket access for packet capture. The compose file drops every capability except `NET_RAW` and `NET_ADMIN` and sets `no-new-privileges`.

## Database Migrations

CNDS uses [Alembic](https://alembic.sqlalchemy.org/) for schema versioning. On startup, the API automatically runs pending migrations (falling back to `create_all` for in-memory test databases). If a migration fails on a database that already carries an Alembic revision, the API logs the error and refuses to start, so it never serves on a schema that is behind the code (ADR 0004). A database whose tables were created by `create_all` (for example by the detector, before the API ever ran) has no revision: there the API still starts, logs an error and asks you to adopt the database with `alembic stamp <revision>`.

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

## Production Hardening

### First admin user

With `JWT_SECRET` set, `POST /api/auth/users` needs an admin Bearer token (an `X-API-Key` does not satisfy it), so the first admin cannot be created through the API. Insert it once, with `DATABASE_URL` pointing at the production database:

```bash
openssl rand -hex 32          # a value for JWT_SECRET

venv/bin/python - <<'PY'
import asyncio
from src.api.database import AsyncSessionLocal, init_db
from src.api.models import User
from src.api.auth import hash_password

async def main():
    await init_db()
    async with AsyncSessionLocal() as db:
        db.add(User(username="admin", password_hash=hash_password("strong-password"), role="admin"))
        await db.commit()

asyncio.run(main())
PY
```

Further users are created with `POST /api/auth/users` and an admin token.

### Metrics endpoint

`/metrics` is open unless `METRICS_TOKEN` is set; then it needs `Authorization: Bearer <token>` (in `prometheus.yml`: `authorization: {credentials: <token>}`).

### TLS

CNDS serves plain HTTP. Put a reverse proxy with TLS in front; the `Upgrade` and `Connection` headers are needed for `/ws/alerts`:

```nginx
server {
    listen 443 ssl;
    server_name cnds.internal;

    ssl_certificate /etc/ssl/cnds.crt;
    ssl_certificate_key /etc/ssl/cnds.key;

    location / {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### Capacity settings

On a busier network raise the bounds of the capture path (defaults in brackets): `PACKET_WORKERS` (4), `PACKET_QUEUE_SIZE` (20000), `MAX_ACTIVE_FLOWS` (50000), `MAX_TRACKED_IPS` (5000); a shorter `FLOW_TIMEOUT` (120) frees flow state sooner. When the API runs in the capture process (`main.py --api`), `capture_stats.dropped_packets` in `GET /health` counts packets dropped because the queue was full: if it grows, add workers or queue size. There is no Prometheus series for it.

### Logs

Logs go to stdout/stderr; `LOG_FORMAT=json` makes them structured. In Docker, bound them with the `json-file` driver options:

```yaml
logging:
  driver: "json-file"
  options:
    max-size: "100m"
    max-file: "10"
```

### Health check

`GET /health` always answers 200 with the availability of each engine while the API process is up; it does not turn into an error when engines are missing. To alert on a degraded detector, read the `engines` object (and `GET /api/baseline/status` for the baseline engine).

### Background cleanup

Every 5 minutes the API deletes expired suppression rules and prunes its in-memory rate limiter. Alerts are never deleted automatically: prune the `alerts` table yourself if it has to stay bounded.

### GeoIP (optional)

Download the free MaxMind `GeoLite2-City.mmdb` (needs a MaxMind account) and set `GEOIP_DB_PATH` to it. Without it `src_geo` is null on every alert.

## Running without Docker (systemd)

```ini
# /etc/systemd/system/cnds.service
[Unit]
Description=Cognitive Network Defense System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/cnds
EnvironmentFile=/opt/cnds/.env
ExecStart=/opt/cnds/venv/bin/python main.py --api
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now cnds
sudo journalctl -u cnds -f
```

This runs capture and API in one process, so SQLite is enough for a single small host; the Guardian, `capture_stats` and `/api/drift-status` also work in this layout because they live in that same process.

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

See [Configuration](Configuration.md) for the full variable list.

### Guardian setup

Do these in order, and keep `GUARDIAN_ENABLED=false` until the last step.

1. **Enforcement backend.** The only backend shipped is `AdGuardBackend`: DNS-level blocking through AdGuard Home's access-control API (`/control/access/list` and `/control/access/set`). It needs an AdGuard Home instance that is already your network's DNS resolver (`ADGUARD_URL`, `ADGUARD_USERNAME`, `ADGUARD_PASSWORD`). A DNS block stops a device from resolving names, which disrupts most C2 and exfiltration traffic; it does **not** stop traffic to a hardcoded IP or to names the device already cached. Another enforcement point can be added behind the `MitigationBackend` protocol (`src/guardian/backends.py`) without touching `engine.py`.
2. **Whitelist, before enabling.** List the gateway, your infrastructure hosts and your own devices one by one in `GUARDIAN_WHITELIST`. Never a CIDR that covers the subnet the detector monitors: the Guardian would then never block anything. A device on DHCP needs a reservation on the router, or its entry goes stale and a false positive can block it until the rollback.
3. **Safety limits.** `GUARDIAN_MIN_SEVERITY=critical` is the conservative start (`high` blocks more, with more false positives). `GUARDIAN_BLOCK_MINUTES` is how long a block lasts before the automatic rollback. `GUARDIAN_CIRCUIT_MAX_ACTIONS` blocks inside `GUARDIAN_CIRCUIT_WINDOW_SECS` pause the Guardian and send one notice.
4. **Alert sources.** Only alerts whose `source` is in `GUARDIAN_ALERT_SOURCES` (default `detector`) can cause a block, so alerts from `POST /api/predict` and logwatch do not, unless you add `api` or `logwatch`.
5. **Telegram Confirm / Undo (optional).** With `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`, every block is sent with **Confirm** (make it permanent, cancel the rollback) and **Undo now** buttons. The listener long-polls `getUpdates`, so nothing has to be exposed to the internet. Button presses are accepted only from `TELEGRAM_CHAT_ID` when it is a private chat; in a group chat set `TELEGRAM_ALLOWED_USER_IDS`. Without a token the Guardian still blocks and rolls back on schedule.
6. **Enable and verify.** Set `GUARDIAN_ENABLED=true` and restart the `api` service (the Guardian tasks run inside the API process). Then, before trusting it unattended:
   1. Produce a `critical` alert from a non-whitelisted, disposable test address.
   2. Within one `GUARDIAN_POLL_INTERVAL_SECS` cycle, check for a new `mitigation_actions` row with `status=pending` and for the address in AdGuard's `disallowed_clients`.
   3. Check that the same alert from a whitelisted address produces no action.
   4. Wait for `expires_at` (or set it to a past time in the database) and check that the next cycle unblocks the address and sets `status=expired`.

## Streamlit Dashboard

The dashboard (`dashboard/app.py`) is a Streamlit client of the REST API with three pages: **Alerts overview** (KPIs, timeline, filters, table, acknowledge and label), **Alert detail** (network and detection data, triage, other alerts from the same source, raw features) and **Analytics** (tabs for trends, top talkers, engines, MITRE and geo).

It authenticates with the API through `dashboard/api_client.py`: `CNDS_API_KEY` is sent as `X-API-Key` (API-key deployments), and `CNDS_API_USER` + `CNDS_API_PASSWORD` log in at `/api/auth/token` and send the JWT as a Bearer token (JWT deployments; use an `analyst` or `admin` account so it can acknowledge alerts). The compose file passes `API_KEY` from `.env` as `CNDS_API_KEY`.

Access at `http://localhost:8501` when started with `docker-compose --profile dashboard up -d`, or run it by hand with `pip install -r requirements-dashboard.txt && streamlit run dashboard/app.py` (it reads `CNDS_API_URL`, default `http://localhost:8000`, and the credentials above).

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
2. **Clients must authenticate:** the dashboard uses `CNDS_API_KEY`, or `CNDS_API_USER` / `CNDS_API_PASSWORD` with JWT; `scripts/demo_seed.py` sends `API_KEY` and, with JWT, the token in `CNDS_API_TOKEN`.
3. **Apply migrations before starting the detector:** recreate the `api` service first (it runs Alembic), then the detector.
4. **Rebuild the image.** Dependencies are hash-pinned (`requirements-lock-*.txt`) and torch is 2.13.0+cpu.
5. **Optional:** set `METRICS_TOKEN`, and `GUARDIAN_ALERT_SOURCES` if you relied on `/api/predict` alerts triggering the Guardian.
