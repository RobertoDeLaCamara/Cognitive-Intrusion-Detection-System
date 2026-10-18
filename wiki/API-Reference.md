# API Reference

FastAPI application at `src/api/main.py`. Default port: **8000**. Interactive docs: `/docs` (Swagger) and `/openapi.json`.

> This page and [REST API](REST-API.md) cover the same endpoints. This one is the per-endpoint reference (parameters, bodies, responses); REST API is the quick table plus curl examples. Both were checked against `src/api/routers/*.py`.

## Authentication

At least one mechanism must be configured: the API refuses to start with neither `API_KEY` nor `JWT_SECRET` unless `AUTH_DISABLED=true` (lab use only), which leaves every endpoint open.

| Mechanism | Env Var | Header / Param | Scope |
|-----------|---------|----------------|-------|
| API key (legacy) | `API_KEY` | `X-API-Key: <key>` | Every HTTP route except `/health`, `/docs`, `/openapi.json`, `/metrics`, `/api/auth/*` (`/ws/alerts` authenticates inside its own handler) |
| JWT | `JWT_SECRET` | `Authorization: Bearer <token>` | Every route except `/health`, `/metrics` and `/api/auth/token` (role table below), plus the `/ws/alerts` `?token=` |

### JWT roles

Tokens carry a `role` claim: `admin`, `analyst` or `viewer`. A route with `require_role(...)` returns 401 when the token is missing/invalid and 403 when the role is not allowed. Every API route except `/health`, `/metrics` and `/api/auth/token` declares a role, so a valid token is always required.

| Route | Roles allowed (when `JWT_SECRET` is set) |
|---|---|
| `GET /api/alerts/export` | admin, analyst |
| `POST /api/incidents`, `PATCH /api/incidents/{id}` | admin, analyst |
| `POST /api/suppression-rules` | admin, analyst |
| `DELETE /api/suppression-rules/{rule_id}` | admin |
| `GET /api/baseline/status`, `GET /api/baseline/windows` | admin, analyst, viewer |
| `POST`/`GET /api/auth/users`, `DELETE /api/auth/users/{user_id}` | admin |
| `GET /api/alerts`, `GET /api/alerts/{id}`, `GET /api/alerts/trends`, `GET /api/incidents`, `GET /api/stats`, `GET /api/suppression-rules`, `GET /api/adaptive-weights`, `GET /api/dns-log` | admin, analyst, viewer |
| `PATCH /api/alerts/{id}`, `POST /api/predict` | admin, analyst |

There is no bootstrap user: the first `admin` has to be inserted directly into the `users` table (password hashed with bcrypt), because `POST /api/auth/users` itself needs an admin token once `JWT_SECRET` is set.

### `POST /api/auth/token`

JSON body (not form-encoded). Returns 501 if `JWT_SECRET` is not configured, 401 on bad credentials.

```bash
curl -X POST http://localhost:8000/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "secret"}'
# {"access_token": "<jwt>", "token_type": "bearer"}
```

### User management (admin)

- `POST /api/auth/users` body `{"username", "password", "role"}` (`role` defaults to `viewer`; 400 on an unknown role, 409 on a duplicate username)
- `GET /api/auth/users` lists users (`id`, `username`, `role`, `is_active`)
- `DELETE /api/auth/users/{user_id}` returns `{"status": "deleted"}` or 404

---

## Health

### `GET /health`

Always open. Returns engine availability and capture statistics (`capture_stats` is `null` unless the API runs inside `main.py --api`).

```json
{
  "status": "ok",
  "engines": {
    "supervised": true,
    "isolation_forest": true,
    "lstm": false,
    "rules": true
  },
  "capture_stats": null
}
```

The baseline engine is not listed here; see `GET /api/baseline/status`.

---

## Prediction

### `POST /api/predict`

Run the supervised, Isolation Forest, LSTM and rules engines on pre-extracted features and (for anomalies) persist an alert. Useful for testing and integration. All fields except `src_ip` are optional.

| Field | Type | Notes |
|---|---|---|
| `src_ip` | string | Required, must be a valid IP (else 422) |
| `dst_ip` | string | Optional, validated as an IP |
| `src_port`, `dst_port`, `protocol` | int | Optional |
| `flow_features` | float[76] | Exactly 76 values; enables supervised + rules |
| `host_features` | float[18] | Exactly 18 values; enables Isolation Forest + LSTM |
| `payload_features` | float[10] | Exactly 10 values |
| `payload_matches` | string[] | Pattern names, e.g. `["sql_injection"]` |

```json
{
  "src_ip": "192.168.1.50",
  "dst_ip": "10.0.0.1",
  "dst_port": 80,
  "protocol": 6,
  "host_features": [45.2, 5200.0, 115.0, 800.0, 452, 52000, 0.02, 0.005, 12.0, 10.0, 0.9, 0.1, 0.0, 3.0, 0.2, 3.5, 80.0, 200.0]
}
```

**Response** (`PredictResponse`) for the request above, run against the bundled models (output of a real call; only the Isolation Forest is active because only `host_features` were sent; `supervised`/`rules` appear when `flow_features` is supplied, `lstm` once its per-IP buffer is warm):

```json
{
  "src_ip": "192.168.1.50",
  "ensemble_score": 0.663,
  "is_anomaly": true,
  "severity": "medium",
  "attack_type": null,
  "engine_scores": {
    "supervised": null, "isolation_forest": 0.663, "lstm": null, "rules": null,
    "attack_type": null, "triggered_rules": []
  },
  "active_engines": ["isolation_forest"],
  "alert_id": 1,
  "src_geo": null,
  "mitre_techniques": [],
  "ja3_hash": null
}
```

Behaviour worth knowing:

- Addresses in `IP_ALLOWLIST` return score 0 with no engines; addresses in `IP_BLOCKLIST` return score 1.0, `severity: "critical"`, `attack_type: "Blocklisted"` (no alert row is written for either).
- The score is multiplied by `CONFIDENCE_DECAY_FACTOR` per repeat from the same IP inside `CONFIDENCE_DECAY_WINDOW`.
- A repeat `(src_ip, attack_type)` inside `DEDUP_WINDOW_SECS` returns `alert_id: null`; so does a match against a suppression rule, in which case the alert is not stored and the response carries `suppressed: true` and `suppression_reason` (`rule #<id>: <reason>`).
- A persisted alert is broadcast on `/ws/alerts`, correlated into incidents and sent to webhook/Telegram if its severity meets `NOTIFY_MIN_SEVERITY`.
- This path does not run the baseline engine or the threat-intel check; the live-capture pipeline does.

---

## Alerts

### `GET /api/alerts`

List alerts, newest first.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `severity` | string | — | `low`, `medium`, `high`, `critical` |
| `src_ip` | string | — | Exact source IP |
| `acknowledged` | bool | — | Acknowledged / unacknowledged |
| `start` | datetime | — | Inclusive lower bound, ISO 8601. Naive values are UTC. |
| `end` | datetime | — | Inclusive upper bound, ISO 8601. Naive values are UTC. `start` after `end` returns 422. |
| `hours` | int | — | Only alerts from the last N hours; `1 <= hours <= 87600` (10 years), otherwise 422 |
| `limit` | int | 50 | Max results, `le=500` |
| `offset` | int | 0 | Pagination offset |

There is no `attack_type` filter and no default time window. All filters combine with AND; if both `hours` and `start` are given, both lower bounds apply.

```bash
curl "http://localhost:8000/api/alerts?severity=high&hours=6&acknowledged=false"
curl "http://localhost:8000/api/alerts?start=2026-10-01T00:00:00Z&end=2026-10-02T00:00:00Z"
```

Each item (`AlertOut`): `id`, `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `attack_type`, `severity`, `ensemble_score`, `engine_scores`, `triggered_rules`, `acknowledged`, `notes`, `incident_id`, `src_geo`, `mitre_techniques`, `ja3_hash`.

### `GET /api/alerts/{alert_id}`

Single alert (same fields as above; the raw feature vectors are stored but not returned). 404 if unknown.

### `PATCH /api/alerts/{alert_id}`

Update any of `acknowledged`, `notes`, `incident_id`. This is also how an alert is linked to an incident.

```json
{"acknowledged": true, "notes": "Confirmed DoS from 192.168.1.50", "incident_id": 3}
```

### `GET /api/alerts/export`

Bulk export (requires `admin` or `analyst` when JWT is on).

| Parameter | Values | Default |
|-----------|--------|---------|
| `format` | `csv`, `json` | `json` |
| `severity` | string | — |
| `src_ip` | string | — |
| `hours` | int, `1..87600` | — (no time filter) |
| `limit` | int, `le=10000` | 1000 |

Returned as a download (`alerts.csv` / `alerts.json`). There is no `start`/`end` here.

### `GET /api/alerts/trends`

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hours` | 24 | Lookback window, 1–168 |
| `bucket` | `hour` | `hour` or `day` |

Response: `{"bucket": "hour", "hours": 24, "data": {"2026-10-01T10:00:00Z": {"total": 3, "by_severity": {"high": 2, "medium": 1}}}}`.

### `GET /api/stats`

`{"total_alerts": N, "unacknowledged": N, "by_severity": {"low": N, "medium": N, "high": N, "critical": N}}`

---

## Incidents

### `GET /api/incidents`

List incidents, newest first. Query: `limit` (default 20, max 200), `status` (`open`, `investigating`, `resolved`, `closed`). There is no `severity` filter.

### `POST /api/incidents`

Create an incident (201; `admin`/`analyst` when JWT is on).

```json
{"title": "DDoS campaign", "description": "...", "severity": "critical", "assigned_to": "analyst@example.com"}
```

### `PATCH /api/incidents/{id}`

Update `status`, `notes` and/or `assigned_to` (`admin`/`analyst` when JWT is on). Status only moves forward through `open` → `investigating` → `resolved` → `closed` (steps may be skipped); a backward move returns 409 and an unknown id 404. `resolved_at` is set automatically the first time the status reaches `resolved` or `closed`.

```json
{"status": "resolved", "notes": "Blocked at the firewall"}
```

Incidents are also created automatically by correlation when one source IP reaches `CORRELATION_THRESHOLD` alerts inside `CORRELATION_WINDOW_SECS` (title `Correlated attack from <ip>`); this happens on the `/api/predict` path.

---

## Suppression rules

### `GET /api/suppression-rules`

Rules that have not expired yet.

### `POST /api/suppression-rules`

Create a rule (201; `admin`/`analyst`). All match fields are optional; `duration_minutes` defaults to 120 (1–10080, i.e. at most 7 days). The server computes `expires_at`; clients do not send it.

```json
{
  "src_ip": "192.168.1.20",
  "attack_type": null,
  "min_severity": null,
  "reason": "Scheduled vulnerability scan",
  "duration_minutes": 240
}
```

### `DELETE /api/suppression-rules/{rule_id}`

204 on success (`admin`), 404 if unknown. Expired rules are purged by a background task every 5 minutes.

Suppression is applied on the `/api/predict` path only.

---

## Adaptive weights

### `GET /api/adaptive-weights`

Returns `{"status": "ok", "weights": {...}}` or `{"status": "insufficient_data", "weights": null}`. Requires `ADAPTIVE_WEIGHTS_ENABLED=true` and at least `ADAPTIVE_MIN_SAMPLES` (default 100) acknowledged alerts. The weights cover supervised / isolation_forest / lstm / rules only and are informational: nothing applies them automatically.

---

## Baseline

### `GET /api/baseline/status`

Collector progress, trigger thresholds/ratios and ETA, loaded baseline-engine info, and a drift score versus the last trained window (`verdict`: `nominal`, `warning`, `critical`). Fields are `null` when the collector is disabled.

### `GET /api/baseline/windows`

`{"windows": [...], "total": N}`, most recent first. Query `limit` 1–20 (default 20).

---

## DNS log

### `GET /api/dns-log`

Queries captured by the detector when `DNS_LOGGING_ENABLED=true`; optional `src_ip` filter. The log lives in the memory of the process that captures, so an API running in a different container (the default compose layout) returns an empty log.

---

## WebSocket — real-time alert stream

### `WS /ws/alerts`

Broadcasts alerts persisted through `POST /api/predict`. When `JWT_SECRET` is set, connect with `?token=<JWT>`; closes with 4001 (missing token), 4003 (invalid/expired) or 4029 (more than 100 clients). The `API_KEY` header check does not apply to WebSockets.

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/alerts');
ws.onmessage = (event) => {
  const alert = JSON.parse(event.data);
  console.log(alert.attack_type, alert.severity, alert.src_ip);
};
```

Message fields: `id`, `src_ip`, `dst_ip`, `ensemble_score`, `severity`, `attack_type`, `triggered_rules`, `timestamp`, `src_geo`. Alerts written by the live-capture process are not pushed here; they appear in `GET /api/alerts`.

---

## Observability

### `GET /metrics`

Registered only when `PROMETHEUS_ENABLED=true` and `prometheus_client` is installed. Main series:

| Metric | Type | Labels |
|--------|------|--------|
| `cnds_http_requests_total` | Counter | method, endpoint, status |
| `cnds_http_request_duration_seconds` | Histogram | method, endpoint |
| `cnds_alerts_total` | Counter | severity, engine |
| `cnds_alerts_suppressed_total` | Counter | reason (`dedup`, `suppression_rule`) |
| `cnds_ensemble_score` | Histogram | is_anomaly |
| `cnds_baseline_*` | Gauges | collector, trigger progress, engine and drift state |

OpenTelemetry traces are exported to `OTEL_EXPORTER_OTLP_ENDPOINT` if set.

---

## Rate limiting

Per-client-IP sliding window, in memory (`src/api/rate_limit.py`). Set `RATE_LIMIT_REQUESTS` to 0 to disable.

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_REQUESTS` | 60 | Requests per window |
| `RATE_LIMIT_WINDOW` | 60 | Window in seconds |

Returns HTTP 429 with a `Retry-After` header when exceeded. `/health`, `/docs`, `/openapi.json` and `/metrics` are exempt.
