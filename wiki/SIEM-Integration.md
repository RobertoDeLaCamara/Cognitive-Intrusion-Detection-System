# SIEM Integration

Pre-built integration templates live in `siem/`. All templates support two ingestion modes:

- **Pull** — SIEM polls the `/api/alerts/export?format=json` endpoint
- **Push** — CNDS sends alerts to the SIEM's HTTP collector via `WEBHOOK_URLS`

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

A standalone CEF syslog forwarder that polls CNDS alerts and forwards them over UDP or TCP:

```bash
python siem/syslog/forwarder.py --syslog-host 10.0.0.50 --syslog-port 514
```

Compatible with any syslog-based SIEM: QRadar, ArcSight, Microsoft Sentinel, etc.

## Multiple Targets

You can push to multiple SIEMs simultaneously:

```bash
WEBHOOK_URLS=https://splunk.example.com:8088/services/collector/event,https://elastic.example.com:9200/cnds-alerts/_doc
```

See `siem/README.md` in the repository for detailed setup instructions.
