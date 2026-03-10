# CNDS SIEM Integration Templates

Pre-built configurations for forwarding CNDS alerts to popular SIEM platforms.

## Quick Setup

1. **Splunk** — `splunk/` contains an HEC input config and a saved search for CNDS alerts
2. **Elastic / OpenSearch** — `elastic/` contains an index template, Logstash pipeline, and Filebeat config
3. **Generic Syslog / CEF** — `syslog/` contains a CEF formatter that works with any syslog-compatible SIEM (QRadar, ArcSight, etc.)

All templates assume CNDS alerts are exported via:
- The `/api/alerts/export?format=json` endpoint (pull), or
- Webhook notifications to your SIEM's HTTP input (push — configure `WEBHOOK_URLS` in `.env`)

## Webhook Push (Recommended)

Set `WEBHOOK_URLS` in your `.env` to your SIEM's HTTP collector endpoint:

```bash
# Splunk HEC
WEBHOOK_URLS=https://splunk.example.com:8088/services/collector/event

# Elastic
WEBHOOK_URLS=https://elastic.example.com:9200/cnds-alerts/_doc

# Multiple targets
WEBHOOK_URLS=https://splunk.example.com:8088/services/collector/event,https://syslog-relay.example.com:5140/cef
```

## Syslog Forwarder

For syslog/CEF output, run the included forwarder alongside CNDS:

```bash
python siem/syslog/forwarder.py --syslog-host 10.0.0.50 --syslog-port 514
```
