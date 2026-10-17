# REST API

Base URL: `http://localhost:8000`

> Quick table and curl examples. The per-endpoint reference (parameters, bodies, responses, role matrix) is [API Reference](API-Reference.md); both pages describe the same routes and were checked against `src/api/routers/*.py`.

## Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Engine availability + capture stats |
| `/api/predict` | POST | Run all engines on supplied features |
| `/api/alerts` | GET | List alerts (filter: `severity`, `src_ip`, `acknowledged`, `start`, `end`, `hours` 1–87600; paging: `limit` ≤ 500, `offset`) |
| `/api/alerts/export` | GET | Export alerts as CSV/JSON (filter: `format`, `severity`, `src_ip`, `hours` 1–87600, `limit` ≤ 10000) — requires `admin` or `analyst` role when JWT is on |
| `/api/alerts/trends` | GET | Alert counts bucketed by hour/day (filter: `hours` 1–168, `bucket`) |
| `/api/alerts/{alert_id}` | GET | Get single alert by ID |
| `/api/alerts/{alert_id}` | PATCH | Acknowledge alert, add notes, link to incident |
| `/api/incidents` | GET / POST | Incident management (POST requires admin/analyst) |
| `/api/stats` | GET | Alert counts grouped by severity |
| `/api/suppression-rules` | GET / POST | List or create suppression rules (POST requires admin/analyst) |
| `/api/suppression-rules/{rule_id}` | DELETE | Remove a suppression rule (requires admin) |
| `/api/adaptive-weights` | GET | Compute adaptive engine weights from feedback |
| `/api/baseline/status` | GET | Live collector snapshot, trigger progress, drift score — any valid role when JWT is on |
| `/api/baseline/windows` | GET | Rolling history of last N trained windows (`limit` 1–20) — any valid role when JWT is on |
| `/api/dns-log` | GET | DNS query logs (filter: `src_ip`) |
| `/api/auth/token` | POST | Issue JWT token from a JSON body (501 unless `JWT_SECRET` is set) |
| `/api/auth/users` | GET / POST | User management (requires admin) |
| `/api/auth/users/{user_id}` | DELETE | Delete user (requires admin) |
| `/ws/alerts` | WebSocket | Real-time alert stream (`?token=JWT` when auth enabled) |
| `/metrics` | GET | Prometheus metrics (when `PROMETHEUS_ENABLED=true`) |
| `/docs` | GET | Swagger UI (auto-generated) |

## Authentication

Authentication is required: the API refuses to start unless `API_KEY` or `JWT_SECRET` is set, or `AUTH_DISABLED=true` (lab use only). Two independent mechanisms exist:

- `API_KEY` — static key sent as `X-API-Key`; checked on every HTTP route except `/health`, `/docs`, `/openapi.json`, `/metrics` and `/api/auth/*` (`/ws/alerts` authenticates inside its own handler).
- `JWT_SECRET` — enables Bearer tokens, but **only the routes that declare a role** are protected (see the role list below); other read routes such as `GET /api/alerts` and `GET /api/stats` stay open unless `API_KEY` is also set.

### Get a token

The body is JSON (a form-encoded body returns 422):

```bash
curl -X POST http://localhost:8000/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "yourpassword"}'
```

### Use the token

```bash
curl -H "Authorization: Bearer <token>" "http://localhost:8000/api/alerts/export?format=csv"
```

### WebSocket auth

When `JWT_SECRET` is set, WebSocket connections require a token:

```
ws://localhost:8000/ws/alerts?token=<JWT>
```

Connections without a token are closed with code 4001, invalid/expired tokens with 4003, and the 101st concurrent client with 4029.

### RBAC Roles

- `admin` — everything below plus user management and suppression-rule deletion
- `analyst` — export alerts, create incidents, create suppression rules, read baseline status
- `viewer` — read `/api/baseline/*` (the other read routes need no role)

## Usage Examples

### Manual prediction

```bash
curl -X POST http://localhost:8000/api/predict \
  -H "Content-Type: application/json" \
  -d '{
    "src_ip": "192.168.1.50",
    "dst_ip": "10.0.0.1",
    "dst_port": 80,
    "protocol": 6,
    "host_features": [45.2, 5200.0, 115.0, 800.0, 452, 52000,
                      0.02, 0.005, 12.0, 10.0, 0.9, 0.1, 0.0,
                      3.0, 0.2, 3.5, 80.0, 200.0]
  }'
```

### List high-severity alerts

```bash
curl "http://localhost:8000/api/alerts?severity=high&limit=20"
```

### Export alerts as CSV

```bash
curl "http://localhost:8000/api/alerts/export?format=csv&severity=high&hours=24" -o alerts.csv
```

### Alert trends

```bash
curl "http://localhost:8000/api/alerts/trends?hours=48&bucket=hour"
```

## Rate Limiting

Per-IP sliding-window rate limiting is enabled by default (`RATE_LIMIT_REQUESTS=0` disables it; HTTP 429 with `Retry-After` when exceeded):
- `RATE_LIMIT_REQUESTS` — max requests per window (default 60)
- `RATE_LIMIT_WINDOW` — window duration in seconds (default 60)

## CORS

Configure allowed origins with `CORS_ORIGINS` (comma-separated). Defaults to `http://localhost:3000`. Cross-origin requests are allowed for the `GET`, `POST` and `PATCH` methods only, so a browser app on another origin cannot call the `DELETE` routes.
