# Alert Enrichment

After the ensemble scorer fires an alert, enrichment modules process it. GeoIP and MITRE apply to every persisted alert; the remaining modules below run only on the `POST /api/predict` path (marked _predict path_) and are not called by the live-capture pipeline in `src/pipeline.py`.

## GeoIP Enrichment

**File:** `src/enrichment/geoip.py`

Looks up the source IP's geographic location using a MaxMind GeoLite2-City database. Adds `src_geo` (country, city, coordinates) to the alert.

- **Config:** `GEOIP_DB_PATH` — path to `GeoLite2-City.mmdb`; empty disables GeoIP.
- Works in both the capture pipeline and the API predict endpoint (the capture pipeline resolves it in the alert writer thread).

## Alert Correlation (_predict path_)

**File:** `src/enrichment/correlation.py`

Automatically groups related alerts into incidents:

- Alerts from the same source IP within `CORRELATION_WINDOW_SECS` (default 300s) are correlated.
- When `CORRELATION_THRESHOLD` (default 5) alerts from the same IP accumulate (the new alert plus `THRESHOLD - 1` earlier ones inside the window), an incident titled `Correlated attack from <ip>` is created; later alerts from that IP join the open incident.
- Incidents can also be created manually via `POST /api/incidents`.

## Suppression Rules (_predict path_)

**File:** `src/enrichment/suppression.py`

Temporary rules to suppress alerts matching specific criteria (e.g., during maintenance windows or for known false positives).

- Create: `POST /api/suppression-rules` (requires admin/analyst role)
- Delete: `DELETE /api/suppression-rules/{rule_id}` (requires admin role)
- List: `GET /api/suppression-rules`
- Expired rules are automatically purged by a background cleanup task every 5 minutes.

## Confidence Decay (_predict path_)

**File:** `src/enrichment/confidence_decay.py`

Reduces alert fatigue from persistent scanners. Repeat alerts from the same source IP have their ensemble score multiplied by `CONFIDENCE_DECAY_FACTOR ** n` (default 0.9), where `n` counts earlier hits within `CONFIDENCE_DECAY_WINDOW` (default 300 seconds).

The decay tracker is bounded by `MAX_TRACKED_IPS` with LRU eviction.

## IP Allowlist / Blocklist (_predict path_)

**File:** `src/enrichment/ip_lists.py`

- `IP_ALLOWLIST` — comma-separated IPs or CIDR ranges (e.g. `10.0.0.1,192.168.0.0/16`) that skip detection entirely (e.g., monitoring infrastructure, load balancers).
- `IP_BLOCKLIST` — comma-separated IPs or CIDR ranges that are automatically flagged as critical severity regardless of ensemble score.

## Webhook / Slack / Telegram Notifications (_predict path_ and Guardian)

**File:** `src/enrichment/notifications.py`

Sends alert summaries to external services when severity meets `NOTIFY_MIN_SEVERITY` (default `high`).

- `WEBHOOK_URLS` — comma-separated URLs (Slack incoming webhooks, custom endpoints; a plain JSON POST with no auth header, so authenticated collectors such as Splunk HEC need a relay)
- `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` — Telegram bot notifications

Webhook payloads contain only summary fields (`text`, IPs, severity, score, attack type, timestamp) — no internal data is leaked. The Telegram text also lists the triggered rules.

The optional Guardian module (`GUARDIAN_ENABLED`, off by default) can act on critical alerts instead of only notifying — see [Deployment](Deployment.md#guardian-auto-response-optional).

## DNS Logging

**File:** `src/enrichment/dns_logger.py`

When `DNS_LOGGING_ENABLED=true`, DNS queries from captured traffic are logged in the capturing process's memory and queryable via `GET /api/dns-log?src_ip=...`; an API served from a different process or container (the default compose layout) does not see them.

The DNS log is bounded by `MAX_TRACKED_IPS` with LRU eviction.
