# Enrichment & SIEM Integration

## Enrichment Pipeline

Two paths produce alerts, and they do not enrich identically.

**Live capture** (`main.py` → `src/pipeline.py`):

```
EnsembleResult (score, attack_type, triggered_rules)
    ↓
1. Trusted-outbound filter and threat-intel lookup (before scoring)
2. Dedup on (src_ip, attack_type) within DEDUP_WINDOW_SECS
3. Writer thread: GeoIP lookup (src_ip), MITRE ATT&CK mapping, JA3 fields
    ↓
SQLite / PostgreSQL INSERT
```

**`POST /api/predict`** (`src/api/routers/predict.py`):

```
EnsembleResult
    ↓
1. IP allowlist skip / blocklist escalate (before scoring)
2. Confidence decay on the score
3. Dedup on (src_ip, attack_type)
4. GeoIP lookup, MITRE ATT&CK mapping
5. Suppression rule check         → discard if matched
6. Incident correlation check     → auto-create incident if threshold met
    ↓
INSERT, then WebSocket broadcast and notification dispatch (webhook / Telegram)
```

IP lists, decay, suppression, correlation, WebSocket broadcast and webhook/Telegram notifications are not applied to alerts written by the capture pipeline.

---

## GeoIP Enrichment

File: `src/enrichment/geoip.py`

- Database: MaxMind GeoLite2 (`.mmdb` file)
- Set path via `GEOIP_DB_PATH`; silently disabled if empty
- Fields added to alert: `src_geo: {country, city, latitude, longitude}`
- Used in Streamlit dashboard world map

---

## MITRE ATT&CK Mapping

File: `src/enrichment/mitre.py`

Maps `attack_type` (from the supervised engine) and `triggered_rules` (from rules engine) to ATT&CK technique IDs. Multiple sources deduplicated by technique ID.

| Source | Example | Technique |
|--------|---------|-----------|
| attack_type=DoS Hulk | T1498 | Network Denial of Service (Impact) |
| attack_type=PortScan | T1046 | Network Service Scanning (Discovery) |
| attack_type=SSH-Patator | T1110.001 | Password Guessing (Credential Access) |
| attack_type=Web Attack – Sql Injection | T1190 | Exploit Public-Facing Application (Initial Access) |
| attack_type=Bot | T1071 | Application Layer Protocol (Command and Control) |
| attack_type=Infiltration | T1041, T1071 | Exfiltration Over C2 Channel, Application Layer Protocol |
| rule=syn_scan | T1046 | Network Service Scanning |
| rule=malicious_ja3 | T1071, T1573 | Application Layer Protocol, Encrypted Channel |
| rule=payload:sql_injection | T1190 | Exploit Public-Facing Application |

Full tables: [MITRE ATT&CK Mapping](MITRE-ATT&CK-Mapping.md). Stored as JSON array: `[{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"}]`

---

## Incident Correlation

File: `src/enrichment/correlation.py`

Auto-groups N alerts from the same IP within a time window into a new Incident record.

| Variable | Default | Description |
|----------|---------|-------------|
| `CORRELATION_WINDOW_SECS` | 300 | Time window |
| `CORRELATION_THRESHOLD` | 5 | Alert count to trigger incident creation |

Incident title auto-generated: `"Correlated attack from {src_ip}"`; further alerts from that IP join the open incident. Correlation runs on the `/api/predict` path.

---

## Confidence Decay

File: `src/enrichment/confidence_decay.py`

Reduces the ensemble score for repeat alerts from the same IP using geometric decay:

```
decayed_score = score × CONFIDENCE_DECAY_FACTOR ** repeats_in_window     (default factor 0.9, window 300 s)
```

Prevents a single noisy IP from generating perpetual high-severity alerts. Applied on the `/api/predict` path only.

---

## IP Lists

File: `src/enrichment/ip_lists.py`

| List | Variable | Effect |
|------|----------|--------|
| Allowlist | `IP_ALLOWLIST` | Skip detection entirely for these IPs/CIDRs |
| Blocklist | `IP_BLOCKLIST` | Auto-escalate to CRITICAL severity (`/api/predict` returns score 1.0, `attack_type: Blocklisted`, no alert row) |
| Trusted outbound | `TRUSTED_OUTBOUND` | Per-device → domain suffix map; skip detection for matched pairs (capture pipeline only) |

`TRUSTED_OUTBOUND` format (JSON): `{"192.168.1.20": ["nas-provider.com", "dropbox.com"]}`
DNS reverse lookup with 1-hour TTL cache.

---

## Alert Suppression

File: `src/enrichment/suppression.py`

Suppress alerts during scheduled maintenance windows:

`POST /api/suppression-rules` body (the server derives `expires_at` from `duration_minutes`, default 120, max 10080):

```json
{
  "src_ip": "192.168.1.20",
  "attack_type": null,
  "min_severity": null,
  "reason": "Scheduled vulnerability scan",
  "duration_minutes": 240
}
```

Expired rules auto-deleted by background cleanup task (every 300s). Suppression is applied on the `/api/predict` path only.

---

## Notifications

File: `src/enrichment/notifications.py`

Async delivery (non-blocking). Failure does not prevent alert persistence.

| Channel | Variable | Format |
|---------|----------|--------|
| Webhook / Slack | `WEBHOOK_URLS` (comma-separated) | JSON POST with a summary: `text`, `src_ip`, `dst_ip`, `severity`, `attack_type`, `ensemble_score`, `timestamp` |
| Telegram | `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` | Formatted MarkdownV2 message |

There is no separate Slack variable: a Slack incoming-webhook URL goes in `WEBHOOK_URLS`. Notifications are dispatched from `/api/predict` and by the Guardian (circuit-breaker notice); the capture pipeline does not call them.

Minimum severity filter: `NOTIFY_MIN_SEVERITY` (default: `high`). Alerts below this level are not dispatched.

The optional Guardian module (`src/guardian/`) extends the Telegram channel with an inline **Confirm**/**Undo** keyboard on every auto-block it creates, and receives button presses via `getUpdates` long-polling (not a webhook). See [Architecture and Data Flow](Architecture-and-Data-Flow.md#guardian-auto-response-optional) and [Deployment](Deployment.md#guardian-auto-response-optional).

---

## Adaptive Weights

File: `src/enrichment/adaptive_weights.py`

When `ADAPTIVE_WEIGHTS_ENABLED=true`, analyst feedback (acknowledged TP/FP) drives weight retuning:

```
weight_engine ∝ (TP + 1) / (TP + FP + 2)
```

where TP / FP are each engine's share of the engine-score total over acknowledged alerts; an alert counts as a false positive when its notes contain "false positive" (case-insensitive). The result is normalised to sum to 1.0 over supervised / isolation_forest / lstm / rules. Requires `ADAPTIVE_WEIGHTS_ENABLED=true` and `ADAPTIVE_MIN_SAMPLES` (default 100) acknowledged alerts. Weights are recomputed on `GET /api/adaptive-weights`; they must be applied manually through the `WEIGHT_*` variables.

---

## DNS Logging

File: `src/enrichment/dns_logger.py`

Captures DNS queries seen during monitoring. Useful for:
- DGA (Domain Generation Algorithm) detection
- Lateral movement tracking
- Data exfiltration via DNS

Accessible via `GET /api/dns-log`.

---

## SIEM Integration

### Splunk HEC

Files: `siem/splunk/inputs.conf`, `siem/splunk/props.conf`, `siem/splunk/savedsearches.conf`

```ini
# inputs.conf — configure HEC token and index
[http://cnds_alerts]
token = <your-hec-token>
index = security
sourcetype = cnds:alert
```

`WEBHOOK_URLS` posts an unauthenticated JSON summary (see [SIEM Integration](SIEM-Integration.md) for the limits: no `Authorization` header, no HEC `event` wrapper), so a direct push to HEC needs a relay. `savedsearches.conf` includes pre-built searches.

### Elastic / OpenSearch

Files: `siem/elastic/index_template.json`, `siem/elastic/logstash_cnds.conf`

```
logstash_cnds.conf:
  input { http { port => 8080 } }
  filter { json { source => "message" } }
  output { elasticsearch { hosts => ["localhost:9200"] index => "cnds-alerts-%{+YYYY.MM.dd}" } }
```

### Syslog-CEF

File: `siem/syslog/forwarder.py`

CEF (Common Event Format) over UDP (default) or TCP; the port is configurable (514 by default). Compatible with QRadar, ArcSight, and any CEF-aware SIEM.

```bash
# Start CEF forwarder (polls GET /api/alerts)
python siem/syslog/forwarder.py --syslog-host 192.168.1.20 --syslog-port 514 --syslog-proto udp
```

CEF line produced by `alert_to_cef()`:
```
CEF:0|CNDS|CognitiveNDS|1.0|{attack_type}|{attack_type}|{severity_int}|
src={src_ip} dst={dst_ip} spt={src_port} dpt={dst_port} cn1={score} cn1Label=EnsembleScore
cs1={rules} cs1Label=TriggeredRules cs2={ja3} cs2Label=JA3Hash cs3={mitre_ids} cs3Label=MITRETechniques externalId={id}
```
