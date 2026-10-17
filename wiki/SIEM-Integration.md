# SIEM Integration

Pre-built integration templates live in `siem/`. All templates support two ingestion modes:

- **Pull** — SIEM polls the `/api/alerts/export?format=json` endpoint (needs a Bearer token with `admin`/`analyst` role when `JWT_SECRET` is set, and the `X-API-Key` header when `API_KEY` is set; the bundled Logstash poller sends neither)
- **Push** — CNDS POSTs a JSON summary to each URL in `WEBHOOK_URLS`. The body is `{"text", "src_ip", "dst_ip", "severity", "attack_type", "ensemble_score", "timestamp"}` with only a `Content-Type` header: there is no setting for an `Authorization` header, so endpoints that need one (Splunk HEC expects `Authorization: Splunk <token>` and an `event` key) require a relay in front. Webhook pushes are sent only for alerts persisted through `POST /api/predict`; alerts written by the live-capture process are not pushed, so use the pull modes or the syslog forwarder for those.

## Splunk

**Files:** `siem/splunk/inputs.conf`, `props.conf`, `savedsearches.conf`

### Setup

1. Create an HTTP Event Collector (HEC) token in Splunk
2. Set `WEBHOOK_URLS` in `.env`:
   ```bash
   WEBHOOK_URLS=https://splunk.example.com:8088/services/collector/event
   ```
3. Copy `props.conf` to your Splunk app for field extraction and CIM mapping
4. Import `savedsearches.conf` for pre-built alert searches

## Elastic / OpenSearch

**Files:** `siem/elastic/index_template.json`, `logstash_cnds.conf`, `filebeat_cnds.yml`

### Option A: Logstash Pipeline

Use `logstash_cnds.conf` to either:
- Poll the CNDS export endpoint, or
- Receive webhook pushes from CNDS

### Option B: Filebeat Log Tail

Use `filebeat_cnds.yml` to tail CNDS log files (works well with `LOG_FORMAT=json`).

### Index Template

Apply `index_template.json` to Elasticsearch for typed mappings including `geo_point` for GeoIP data and nested objects for MITRE techniques.

## Syslog / CEF (QRadar, ArcSight, Sentinel)

**File:** `siem/syslog/forwarder.py`

A standalone CEF syslog forwarder that polls `GET /api/alerts` and forwards new alerts over UDP (default) or TCP:

```bash
python siem/syslog/forwarder.py --syslog-host 10.0.0.50 --syslog-port 514
# other options: --cnds-url http://localhost:8000  --syslog-proto udp|tcp  --poll-interval 60  --severity medium
```

The forwarder keeps its last forwarded alert id in `~/.cnds_forwarder_state.json`. It sends no auth header, and `--severity` is passed to the API as an exact-match `severity` filter (it forwards only that severity, not "that severity and above").

Compatible with any syslog-based SIEM: QRadar, ArcSight, Microsoft Sentinel, etc.

## Multiple Targets

You can push to multiple SIEMs simultaneously:

```bash
WEBHOOK_URLS=https://splunk.example.com:8088/services/collector/event,https://elastic.example.com:9200/cnds-alerts/_doc
```

See `siem/README.md` in the repository for detailed setup instructions.
