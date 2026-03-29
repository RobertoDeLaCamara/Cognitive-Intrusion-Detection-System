# CNDS — API Reference

Base URL: `http://<host>:8000`

Interactive docs: `http://<host>:8000/docs` (Swagger UI)

---

## Authentication

CNDS supports two authentication modes:

### JWT (Recommended)
1. Obtain a token:
```http
POST /api/auth/token
Content-Type: application/x-www-form-urlencoded

username=analyst&password=secret
```
Response:
```json
{"access_token": "eyJ...", "token_type": "bearer"}
```
2. Use the token on subsequent requests:
```http
Authorization: Bearer eyJ...
```

### Legacy API Key
Set `API_KEY` in `.env`. Send as:
```http
X-API-Key: <your-key>
```

### WebSocket Authentication
Append the JWT token as a query parameter:
```
ws://host:8000/ws/alerts?token=eyJ...
```

### Roles

| Role | Capabilities |
|---|---|
| `viewer` | Read alerts, incidents, stats |
| `analyst` | All viewer + acknowledge alerts, create incidents, manage suppression rules |
| `admin` | All analyst + create/delete users, delete suppression rules |

---

## Health

### `GET /health`

Returns engine availability and capture statistics. No authentication required.

**Response:**
```json
{
  "status": "ok",
  "engines": {
    "supervised": true,
    "isolation_forest": true,
    "lstm": false,
    "rules": true
  },
  "capture": {
    "processed": 124853,
    "dropped": 0,
    "queue_size": 12,
    "active_workers": 4
  },
  "uptime_seconds": 3621
}
```

---

## Alerts

### `GET /api/alerts`

List alerts with optional filtering. Requires authentication.

**Query Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `severity` | string | — | Filter: `low`, `medium`, `high`, `critical` |
| `src_ip` | string | — | Filter by source IP |
| `acknowledged` | bool | — | Filter by acknowledgement status |
| `hours` | int | 24 | Return alerts from last N hours |
| `limit` | int | 100 | Max results |
| `offset` | int | 0 | Pagination offset |

**Response:**
```json
[
  {
    "id": 1,
    "timestamp": "2026-03-29T14:22:01Z",
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.5",
    "src_port": 54231,
    "dst_port": 80,
    "protocol": "TCP",
    "attack_type": "DoS Hulk",
    "severity": "high",
    "ensemble_score": 0.83,
    "engine_scores": {
      "supervised": 0.91,
      "iforest": 0.74,
      "lstm": 0.61,
      "rules": 1.0
    },
    "triggered_rules": ["icmp_flood"],
    "src_geo": {
      "country": "United States",
      "city": "San Jose",
      "lat": 37.338,
      "lon": -121.886
    },
    "mitre_techniques": [
      {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"}
    ],
    "ja3_hash": "a0e9f5d64349fb13191bc781f81f42e1",
    "ja3_string": "771,49195-49199...,0-23...",
    "acknowledged": false,
    "notes": null,
    "incident_id": null
  }
]
```

---

### `GET /api/alerts/{id}`

Fetch a single alert by ID.

**Response:** Same structure as the list item above.

---

### `PATCH /api/alerts/{id}`

Acknowledge an alert, add notes, or link it to an incident. Requires `analyst` role.

**Request body:**
```json
{
  "acknowledged": true,
  "notes": "Confirmed DoS from customer lab. Suppressing.",
  "incident_id": 5
}
```

All fields are optional. Only provided fields are updated.

**Response:** Updated alert object.

---

### `GET /api/alerts/export`

Stream alerts as CSV or JSON for SIEM/ticketing ingestion. Requires authentication.

**Query Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `format` | string | `json` | `json` or `csv` |
| `severity` | string | — | Filter by severity |
| `hours` | int | 24 | Export from last N hours |

**Response:** Streaming file download with `Content-Disposition: attachment`.

---

### `GET /api/alerts/trends`

Alert counts bucketed by time period for trend analysis.

**Query Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `bucket` | string | `hour` | `hour` or `day` |
| `hours` | int | 24 | Lookback window |

**Response:**
```json
[
  {"bucket": "2026-03-29T13:00:00Z", "count": 12},
  {"bucket": "2026-03-29T14:00:00Z", "count": 47}
]
```

---

### `GET /api/stats`

Alert counts by severity for dashboard summary widgets.

**Response:**
```json
{
  "total": 142,
  "by_severity": {
    "low": 65,
    "medium": 48,
    "high": 24,
    "critical": 5
  },
  "acknowledged": 89,
  "unacknowledged": 53
}
```

---

## Incidents

### `GET /api/incidents`

List incidents. Requires authentication.

**Query Parameters:** `status` (open/investigating/resolved/closed), `severity`, `limit`, `offset`.

**Response:**
```json
[
  {
    "id": 1,
    "title": "Repeated DoS from 192.168.1.100",
    "description": "Auto-created: 7 alerts from same source in 300s",
    "status": "open",
    "severity": "high",
    "assigned_to": null,
    "created_at": "2026-03-29T14:22:05Z",
    "updated_at": "2026-03-29T14:22:05Z",
    "resolved_at": null,
    "notes": null,
    "alert_count": 7
  }
]
```

---

### `POST /api/incidents`

Create an incident manually. Requires `analyst` role.

**Request body:**
```json
{
  "title": "Suspected lateral movement",
  "description": "Multiple internal IPs generating scan alerts",
  "severity": "high",
  "assigned_to": "alice"
}
```

---

### `GET /api/incidents/{id}`

Fetch incident with all linked alerts.

---

### `PATCH /api/incidents/{id}`

Update status, assignee, or notes. Requires `analyst` role.

**Request body:**
```json
{
  "status": "investigating",
  "assigned_to": "bob",
  "notes": "Coordinating with network team."
}
```

---

### `DELETE /api/incidents/{id}`

Delete incident. Requires `admin` role.

---

## Suppression Rules

### `GET /api/suppression-rules`

List active suppression rules. Requires authentication.

**Response:**
```json
[
  {
    "id": 1,
    "src_ip": "192.168.1.200",
    "dst_ip": null,
    "attack_type": "PortScan",
    "min_severity": "low",
    "reason": "Vulnerability scanner — authorized",
    "created_at": "2026-03-29T12:00:00Z",
    "expires_at": "2026-03-30T12:00:00Z"
  }
]
```

---

### `POST /api/suppression-rules`

Create a suppression rule. Requires `analyst` role.

**Request body:**
```json
{
  "src_ip": "192.168.1.200",
  "attack_type": "PortScan",
  "min_severity": "low",
  "reason": "Authorized vulnerability scanner",
  "expires_at": "2026-03-30T12:00:00Z"
}
```

All fields except `reason` are optional. A rule with all null match fields suppresses all alerts.

---

### `DELETE /api/suppression-rules/{id}`

Delete a suppression rule. Requires `admin` role.

---

## Adaptive Weights

### `GET /api/adaptive-weights`

Compute suggested engine weights from analyst TP/FP feedback. Requires authentication.

**Response:**
```json
{
  "current_weights": {
    "supervised": 0.40,
    "iforest": 0.30,
    "lstm": 0.20,
    "rules": 0.10
  },
  "suggested_weights": {
    "supervised": 0.48,
    "iforest": 0.27,
    "lstm": 0.17,
    "rules": 0.08
  },
  "sample_count": 215,
  "meets_min_samples": true
}
```

Apply suggested weights by updating `.env` and restarting.

---

## DNS Log

### `GET /api/dns-log`

Return logged DNS queries. Requires authentication.

**Query Parameters:** `src_ip`, `hours` (default 24), `limit` (default 100).

**Response:**
```json
[
  {
    "timestamp": "2026-03-29T14:20:11Z",
    "src_ip": "192.168.1.100",
    "query": "evil.domain.com",
    "query_type": "A",
    "response": "203.0.113.5"
  }
]
```

---

## Manual Prediction

### `POST /api/predict`

Run the full detection pipeline on pre-computed feature vectors. Suitable for integration into external capture tools (Zeek, Arkime, etc.) or CI/CD pipeline testing. Requires authentication.

**Request body:**
```json
{
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.5",
  "dst_port": 80,
  "protocol": "TCP",
  "flow_features": [0.0, 15.0, 1200.0, 300.0, ...],
  "host_features": [45.2, 18300.0, 406.7, ...],
  "payload_features": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 4.1, 406.0, 0.02]
}
```

- `flow_features`: 76 floats in `FLOW_FEATURE_NAMES` order.
- `host_features`: 18 floats in `HOST_FEATURE_NAMES` order.
- `payload_features`: 10 floats (optional; zeros if omitted).

**Response:**
```json
{
  "ensemble_score": 0.81,
  "attack_type": "PortScan",
  "is_anomaly": true,
  "severity": "high",
  "engine_scores": {
    "supervised": 0.88,
    "iforest": 0.72,
    "lstm": null,
    "rules": 1.0
  },
  "triggered_rules": ["syn_scan"],
  "mitre_techniques": [
    {"id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery"}
  ]
}
```

`lstm` is `null` when the LSTM sequence buffer for the IP is not yet full.

---

## Authentication Endpoints

### `POST /api/auth/token`

Issue a JWT access token. No authentication required.

**Request body** (form-encoded):
```
username=alice&password=secret123
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

---

### `GET /api/auth/users`

List users. Requires `admin` role.

**Response:**
```json
[
  {"id": 1, "username": "alice", "role": "admin", "is_active": true},
  {"id": 2, "username": "bob", "role": "analyst", "is_active": true}
]
```

---

### `POST /api/auth/users`

Create a user. Requires `admin` role.

**Request body:**
```json
{
  "username": "carol",
  "password": "strongpassword",
  "role": "analyst"
}
```

---

### `DELETE /api/auth/users/{id}`

Delete a user. Requires `admin` role.

---

## WebSocket

### `WS /ws/alerts`

Real-time alert stream. Each fired alert is broadcast as a JSON message immediately after enrichment and persistence.

**Connection:**
```
ws://host:8000/ws/alerts?token=eyJ...
```

When `JWT_SECRET` is not set, the token parameter is not required.

**Message format:** Same schema as `GET /api/alerts` list item.

**Example (Python):**
```python
import asyncio
import websockets
import json

async def stream_alerts():
    uri = "ws://localhost:8000/ws/alerts?token=eyJ..."
    async with websockets.connect(uri) as ws:
        async for message in ws:
            alert = json.loads(message)
            print(f"[{alert['severity']}] {alert['attack_type']} from {alert['src_ip']}")

asyncio.run(stream_alerts())
```

---

## Observability

### `GET /metrics`

Prometheus metrics. No authentication required.

**Key metrics exposed:**

| Metric | Type | Description |
|---|---|---|
| `cnds_alerts_total` | Counter | Total alerts by severity and attack_type |
| `cnds_packets_processed_total` | Counter | Packets processed |
| `cnds_packets_dropped_total` | Counter | Packets dropped (queue full) |
| `cnds_ensemble_score` | Histogram | Score distribution |
| `cnds_engine_latency_seconds` | Histogram | Per-engine inference latency |
| `cnds_active_flows` | Gauge | Current tracked flows |
| `cnds_tracked_ips` | Gauge | Current tracked host IPs |
| `http_requests_total` | Counter | HTTP request count by endpoint |
| `http_request_duration_seconds` | Histogram | HTTP latency by endpoint |

---

## Error Responses

All endpoints use standard HTTP status codes:

| Code | Meaning |
|---|---|
| 400 | Bad request — validation error on request body |
| 401 | Unauthorized — missing or invalid token |
| 403 | Forbidden — insufficient role |
| 404 | Not found |
| 422 | Unprocessable entity — Pydantic schema error |
| 429 | Too many requests — rate limit exceeded |
| 500 | Internal server error |

**Error body:**
```json
{"detail": "Human-readable error message"}
```

---

## Rate Limiting

Per-IP rate limiting is enforced on all endpoints:
- Default: `RATE_LIMIT_REQUESTS` requests per `RATE_LIMIT_WINDOW` seconds.
- Exceeded requests receive `429 Too Many Requests`.
- The `/health` and `/metrics` endpoints are exempt.
