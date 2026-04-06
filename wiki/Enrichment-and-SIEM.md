# Enrichment & SIEM Integration

## Enrichment Pipeline

Every alert passing the ensemble threshold is enriched before persistence:

```
EnsembleResult (score, attack_type, triggered_rules)
    ↓
1. GeoIP lookup (src_ip)          → country, city, lat, lon
2. MITRE ATT&CK mapping           → [{id, name, tactic}, ...]
3. Incident correlation check     → auto-create incident if threshold met
4. Confidence decay check         → reduce score for repeat alerts
5. Suppression rule check         → discard if in maintenance window
6. IP list filtering              → allowlist skip / blocklist escalate
7. Notification dispatch          → webhook / Slack / Telegram
    ↓
SQLite / PostgreSQL INSERT
```

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

Maps `attack_type` (from RF engine) and `triggered_rules` (from rules engine) to ATT&CK technique IDs. Multiple sources deduplicated by technique ID.

| Source | Example | Technique |
|--------|---------|-----------|
| attack_type=DoS Hulk | T1498 | Network DoS (Impact) |
| attack_type=PortScan | T1046 | Network Service Discovery (Discovery) |
| attack_type=SSH-Patator | T1110 | Brute Force (Credential Access) |
| attack_type=Web Attack-SQL Injection | T1190 | Exploit Public-Facing App (Initial Access) |
| attack_type=Bot | T1059 | Command and Scripting Interpreter (Execution) |
| attack_type=Infiltration | T1071 | App Layer Protocol (C&C) |
| rule=syn_scan | T1046 | Network Service Discovery |
| rule=malicious_ja3 | T1071, T1573 | Encrypted Channel |
| rule=sql_injection_pattern | T1190 | Exploit Public-Facing App |

Stored as JSON array: `[{"id": "T1498", "name": "Network DoS", "tactic": "Impact"}]`

---

## Incident Correlation

File: `src/enrichment/correlation.py`

Auto-groups N alerts from the same IP within a time window into a new Incident record.

| Variable | Default | Description |
|----------|---------|-------------|
| `CORRELATION_WINDOW_SECS` | 300 | Time window |
| `CORRELATION_THRESHOLD` | 5 | Alert count to trigger incident creation |

Incident title auto-generated: `"N attacks detected from {src_ip}"`.

---

## Confidence Decay

File: `src/enrichment/confidence_decay.py`

Reduces ensemble score for repeat alerts from the same IP using exponential decay:

```
decayed_score = score × exp(-λ × alert_count_in_window)
```

Prevents a single noisy IP from generating perpetual high-severity alerts.

---

## IP Lists

File: `src/enrichment/ip_lists.py`

| List | Variable | Effect |
|------|----------|--------|
| Allowlist | `IP_ALLOWLIST` | Skip detection entirely for these IPs/CIDRs |
| Blocklist | `IP_BLOCKLIST` | Auto-escalate to CRITICAL severity |
| Trusted outbound | `TRUSTED_OUTBOUND` | Per-device → domain suffix map; skip detection for matched pairs |

`TRUSTED_OUTBOUND` format (JSON): `{"[INTERNAL_IP]": ["nas-provider.com", "dropbox.com"]}`
DNS reverse lookup with 1-hour TTL cache.

---

## Alert Suppression

File: `src/enrichment/suppression.py`

Suppress alerts during scheduled maintenance windows:

```json
{
  "src_ip": "[INTERNAL_IP]",
  "attack_type": null,
  "expires_at": "2025-04-01T06:00:00Z",
  "reason": "Scheduled vulnerability scan"
}
```

Expired rules auto-deleted by background cleanup task (every 300s).

---

## Notifications

File: `src/enrichment/notifications.py`

Async delivery (non-blocking). Failure does not prevent alert persistence.

| Channel | Variable | Format |
|---------|----------|--------|
| Webhook | `WEBHOOK_URLS` | JSON POST with full alert |
| Slack | `SLACK_WEBHOOK_URL` | Attachment with color-coded severity |
| Telegram | `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` | Formatted message |

Minimum severity filter: `NOTIFY_MIN_SEVERITY` (default: `high`). Alerts below this level are not dispatched.

---

## Adaptive Weights

File: `src/enrichment/adaptive_weights.py`

When `ADAPTIVE_WEIGHTS_ENABLED=true`, analyst feedback (acknowledged TP/FP) drives weight retuning:

```
weight_engine ∝ TP_rate_engine / (TP_rate_engine + FP_rate_engine)
```

Requires `ADAPTIVE_MIN_SAMPLES` (default 100) acknowledged alerts before activating. Weights are recomputed on `GET /api/adaptive-weights`; must be manually applied to env vars.

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

CNDS sends JSON to Splunk HEC via `WEBHOOK_URLS`. The `savedsearches.conf` includes pre-built correlation searches for each attack class.

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

CEF (Common Event Format) over UDP/TCP to port 514. Compatible with QRadar, ArcSight, and any CEF-aware SIEM.

```bash
# Start CEF forwarder
python siem/syslog/forwarder.py --host [INTERNAL_IP] --port 514 --proto udp
```

CEF Header format:
```
CEF:0|CNDS|NetworkIDS|1.0|{attack_type}|{attack_type} detected|{severity_int}|
src={src_ip} dst={dst_ip} cs1={mitre_id} cs1Label=MITRE_Technique
```
