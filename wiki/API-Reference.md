# API Reference

FastAPI application at `src/api/main.py`. Default port: **8000**.

## Authentication

Two optional auth mechanisms (both disabled if env vars not set):

| Mechanism | Env Var | Header / Param | Scope |
|-----------|---------|----------------|-------|
| API Key | `API_KEY` | `X-API-Key: <key>` | All endpoints except `/health`, `/docs`, `/ws/alerts`, `/api/auth/*` |
| JWT | `JWT_SECRET` | `Authorization: Bearer <token>` | Endpoints decorated with `@require_role()` |

### JWT Roles

| Role | Permissions |
|------|------------|
| admin | All endpoints |
| analyst | Read/write alerts and incidents |
| viewer | Read-only |

```bash
# Obtain JWT token
curl -X POST http://localhost:8000/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "secret"}'
```

---

## Health & Status

### `GET /health`

Returns engine availability and capture statistics.

```json
{
  "status": "healthy",
  "engines": {
    "supervised": true,
    "isolation_forest": true,
    "lstm": true,
    "rules": true
  },
  "capture": {
    "packets_processed": 142340,
    "packets_dropped": 0,
    "active_flows": 47,
    "queue_size": 3
  }
}
```

---

## Prediction

### `POST /api/predict`

Run all engines on manually supplied features. Useful for testing and offline replay.

**Request body:**
```json
{
  "flow_features": [0.0, ...],      // 76 float values
  "host_features": [0.0, ...],      // 18 float values (optional)
  "payload_features": [0.0, ...],   // 10 float values (optional)
  "src_ip": "192.168.1.100",        // optional — for dedup/GeoIP
  "ja3_hash": "abc123..."           // optional
}
```

**Response:**
```json
{
  "is_anomaly": true,
  "score": 0.81,
  "calibrated_score": 0.79,
  "severity": "high",
  "attack_type": "DoS Hulk",
  "engine_scores": {
    "supervised": 0.92,
    "isolation_forest": 0.74,
    "lstm": 0.55,
    "rules": 1.0
  },
  "triggered_rules": ["syn_scan"],
  "mitre_techniques": [
    {"id": "T1498", "name": "Network DoS", "tactic": "Impact"}
  ]
}
```

---

## Alerts

### `GET /api/alerts`

List alerts with optional filters.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| severity | string | — | low, medium, high, critical |
| src_ip | string | — | Filter by source IP |
| attack_type | string | — | Filter by attack class |
| acknowledged | bool | — | Filter acknowledged/unacknowledged |
| hours | int | 24 | Lookback window |
| limit | int | 100 | Max results (max 1000) |
| offset | int | 0 | Pagination offset |

```bash
curl "http://localhost:8000/api/alerts?severity=high&hours=6&acknowledged=false"
```

### `GET /api/alerts/{alert_id}`

Single alert with full detail including GeoIP, MITRE techniques, engine scores, and raw features.

### `PATCH /api/alerts/{alert_id}`

Update acknowledged status and/or add investigation notes.

```json
{"acknowledged": true, "notes": "Confirmed DoS from 192.168.1.100"}
```

### `GET /api/alerts/export`

Bulk export as CSV or JSON.

| Parameter | Values | Default |
|-----------|--------|---------|
| format | csv, json | json |
| hours | int | 24 |
| severity | string | — |

### `GET /api/alerts/trends`

Alerts bucketed by time interval.

| Parameter | Default | Description |
|-----------|---------|-------------|
| hours | 24 | Lookback window |
| interval | hour | hour or day |

---

## Incidents

### `GET /api/incidents`

List incidents. Filter by `status` (open/investigating/resolved/closed) or `severity`.

### `POST /api/incidents`

Manually create an incident.

```json
{
  "title": "DDoS campaign from 10.0.0.x subnet",
  "description": "...",
  "severity": "critical",
  "assigned_to": "analyst@example.com"
}
```

### `POST /api/incidents/{id}/alerts/{alert_id}`

Link an alert to an existing incident.

---

## Suppression Rules

### `GET /api/suppression-rules`

List active maintenance-window suppression rules.

### `POST /api/suppression-rules`

Create a suppression rule (e.g., scheduled maintenance window).

```json
{
  "src_ip": "192.168.1.50",
  "attack_type": null,
  "expires_at": "2025-04-01T06:00:00Z",
  "reason": "Scheduled vulnerability scan"
}
```

---

## Adaptive Weights

### `GET /api/adaptive-weights`

Compute dynamic engine weights from analyst feedback (acknowledged alerts).

Requires `ADAPTIVE_WEIGHTS_ENABLED=true` and at least `ADAPTIVE_MIN_SAMPLES` (default 100) acknowledged alerts.

Returns adjusted weights per engine based on TP/FP feedback ratios.

---

## DNS Log

### `GET /api/dns-log`

DNS queries captured during monitoring. Useful for DGA detection and lateral movement analysis.

---

## WebSocket — Real-Time Alert Stream

### `WS /ws/alerts`

Real-time alert broadcast. JWT optional (controlled by same auth flag as REST).

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/alerts');
ws.onmessage = (event) => {
  const alert = JSON.parse(event.data);
  console.log(alert.attack_type, alert.severity, alert.src_ip);
};
```

Message format matches `GET /api/alerts/{id}` response schema.

---

## Observability

### `GET /metrics`

Prometheus scrape endpoint. Exposes:

| Metric | Type | Labels |
|--------|------|--------|
| cnds_alerts_total | Counter | severity, attack_type |
| cnds_packets_processed_total | Counter | — |
| cnds_packets_dropped_total | Counter | — |
| cnds_active_flows | Gauge | — |
| cnds_ensemble_score | Histogram | — |
| cnds_engine_latency_seconds | Histogram | engine |

OpenTelemetry traces exported to `OTEL_EXPORTER_OTLP_ENDPOINT` if set.

---

## Rate Limiting

Per-IP token bucket. Configurable via:

| Variable | Default | Description |
|----------|---------|-------------|
| RATE_LIMIT_REQUESTS | 100 | Requests per window |
| RATE_LIMIT_WINDOW | 60 | Window in seconds |

Returns HTTP 429 with `Retry-After` header when exceeded.
