# Alert Enrichment

After the ensemble scorer fires an alert, several enrichment modules process it before persistence.

## GeoIP Enrichment

**File:** `src/enrichment/geoip.py`

Looks up the source IP's geographic location using a MaxMind GeoLite2-City database. Adds `src_geo` (country, city, coordinates) to the alert.

- **Config:** `GEOIP_DB_PATH` — path to `GeoLite2-City.mmdb`; empty disables GeoIP.
- Works in both the capture pipeline and the API predict endpoint.

## Alert Correlation

**File:** `src/enrichment/correlation.py`

Automatically groups related alerts into incidents:

- Alerts from the same source IP within `CORRELATION_WINDOW_SECS` (default 300s) are correlated.
- When `CORRELATION_THRESHOLD` (default 5) alerts from the same IP accumulate, an incident is automatically created.
- Incidents can also be created manually via `POST /api/incidents`.

## Suppression Rules

**File:** `src/enrichment/suppression.py`

Temporary rules to suppress alerts matching specific criteria (e.g., during maintenance windows or for known false positives).

- Create: `POST /api/suppression-rules` (requires admin/analyst role)
- Delete: `DELETE /api/suppression-rules/{rule_id}` (requires admin role)
- List: `GET /api/suppression-rules`
- Expired rules are automatically purged by a background cleanup task every 5 minutes.

## Confidence Decay

**File:** `src/enrichment/confidence_decay.py`

Reduces alert fatigue from persistent scanners. Repeat alerts from the same source IP have their ensemble score multiplied by `CONFIDENCE_DECAY_FACTOR` (default 0.9) for each repeat within `CONFIDENCE_DECAY_WINDOW` (default 300 seconds).

The decay tracker is bounded by `MAX_TRACKED_IPS` with LRU eviction.

## IP Allowlist / Blocklist

**File:** `src/enrichment/ip_lists.py`

- `IP_ALLOWLIST` — comma-separated IPs or CIDR ranges (e.g. `10.0.0.1,192.168.0.0/16`) that skip detection entirely (e.g., monitoring infrastructure, load balancers).
- `IP_BLOCKLIST` — comma-separated IPs or CIDR ranges that are automatically flagged as critical severity regardless of ensemble score.

## Webhook / Slack / Telegram Notifications

**File:** `src/enrichment/notifications.py`

Sends alert summaries to external services when severity meets `NOTIFY_MIN_SEVERITY` (default `high`).

- `WEBHOOK_URLS` — comma-separated URLs (Slack incoming webhooks, Splunk HEC, custom endpoints)
- `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` — Telegram bot notifications

Webhook payloads contain only safe summary fields (IP, severity, score, attack type, timestamp) — no internal data is leaked.

The optional Guardian module (`GUARDIAN_ENABLED`, off by default) can act on critical alerts instead of only notifying — see [Deployment](Deployment#guardian-auto-response-optional).

## DNS Logging

**File:** `src/enrichment/dns_logger.py`

When `DNS_LOGGING_ENABLED=true`, DNS queries from captured traffic are logged and queryable via `GET /api/dns-log?src_ip=...`.

The DNS log is bounded by `MAX_TRACKED_IPS` with LRU eviction.
