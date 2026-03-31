# REST API

Base URL: `http://localhost:8000`

## Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Engine availability + capture stats |
| `/api/predict` | POST | Run all engines on supplied features |
| `/api/alerts` | GET | List alerts (filter: `severity`, `src_ip`, `acknowledged`) |
| `/api/alerts/export` | GET | Export alerts as CSV/JSON (filter: `format`, `severity`, `hours`) |
| `/api/alerts/trends` | GET | Alert counts bucketed by hour/day (filter: `hours`, `bucket`) |
| `/api/alerts/{alert_id}` | GET | Get single alert by ID |
| `/api/alerts/{alert_id}` | PATCH | Acknowledge alert, add notes, link to incident |
| `/api/incidents` | GET / POST | Incident management (POST requires admin/analyst) |
| `/api/stats` | GET | Alert counts grouped by severity |
| `/api/suppression-rules` | GET / POST | List or create suppression rules (POST requires admin/analyst) |
| `/api/suppression-rules/{rule_id}` | DELETE | Remove a suppression rule (requires admin) |
| `/api/adaptive-weights` | GET | Compute adaptive engine weights from feedback |
| `/api/dns-log` | GET | DNS query logs (filter: `src_ip`) |
| `/api/auth/token` | POST | Issue JWT token (when `JWT_SECRET` is set) |
| `/api/auth/users` | GET / POST | User management (requires admin) |
| `/api/auth/users/{user_id}` | DELETE | Delete user (requires admin) |
| `/ws/alerts` | WebSocket | Real-time alert stream (`?token=JWT` when auth enabled) |
| `/metrics` | GET | Prometheus metrics (when `PROMETHEUS_ENABLED=true`) |
| `/docs` | GET | Swagger UI (auto-generated) |

## Authentication

Authentication is optional. Set `JWT_SECRET` in `.env` to enable JWT-based auth.

### Get a token

```bash
curl -X POST http://localhost:8000/api/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=yourpassword"
```

### Use the token

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8000/api/alerts
```

### WebSocket auth

When `JWT_SECRET` is set, WebSocket connections require a token:

```
ws://localhost:8000/ws/alerts?token=<JWT>
```

Unauthenticated connections are rejected with close code 4001/4003.

### RBAC Roles

- `admin` — full access (user management, suppression rule deletion)
- `analyst` — create incidents, create suppression rules
- `viewer` — read-only access to alerts and stats

## Usage Examples

### Manual prediction

```bash
curl -X POST http://localhost:8000/api/predict \
  -H "Content-Type: application/json" \
  -d '{
    "src_ip": "192.168.1.100",
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

Per-IP rate limiting is enabled by default:
- `RATE_LIMIT_REQUESTS` — max requests per window (default 60)
- `RATE_LIMIT_WINDOW` — window duration in seconds (default 60)

## CORS

Configure allowed origins with `CORS_ORIGINS` (comma-separated). Defaults to `http://localhost:3000`.
