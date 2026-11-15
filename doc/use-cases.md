# CNDS — Use Cases

This document describes operational scenarios for CNDS across different deployment contexts and user roles.

How to read the detection scenarios (2 to 7):

- **Scores are illustrative.** The per-engine numbers are examples, not measurements. Ensemble sums use the default weights in `src/config.py` (supervised 0.30, Isolation Forest 0.20, LSTM 0.10, rules 0.25, baseline 0.15) with the baseline engine not yet trained, so the other four are renormalised over 0.85.
- **Labels.** The shipped models (FT-Transformer, Random Forest fallback) emit UNSW-NB15 classes: `Benign`, `Analysis`, `Backdoor`, `DoS`, `Exploits`, `Fuzzers`, `Generic`, `Reconnaissance`, `Shellcode`, `Worms`. CIC-IDS2017 names such as `PortScan` or `SSH-Patator` only appear with a model trained on that label set.
- **Timing.** A flow is scored when it expires: no packet for `FLOW_TIMEOUT` (default 120 s), checked every 10 s. A flow that keeps receiving packets is not scored until it goes quiet. Detection is therefore minutes after onset, not seconds.
- **Two alert paths.** WebSocket broadcast, webhook/Telegram/ntfy notifications, confidence decay and incident correlation run only for alerts created through `POST /api/predict`. Alerts written by the live detector are stored (with MITRE and GeoIP) and are read from the dashboard or the API.

---

## Use Case Index

1. [SOC Alert Triage](#1-soc-alert-triage)
2. [Detecting a DoS Attack](#2-detecting-a-dos-attack)
3. [Detecting a Port Scan](#3-detecting-a-port-scan)
4. [Detecting Brute Force Authentication](#4-detecting-brute-force-authentication)
5. [Detecting Slow/Covert Exfiltration](#5-detecting-slowcovert-exfiltration)
6. [Web Application Attack Detection](#6-web-application-attack-detection)
7. [TLS/JA3 Malware Identification](#7-tlsja3-malware-identification)
8. [API-Only Integration with Zeek/Arkime](#8-api-only-integration-with-zeekarkime)
9. [SOC Incident Management Workflow](#9-soc-incident-management-workflow)
10. [Compliance Reporting with MITRE ATT&CK](#10-compliance-reporting-with-mitre-attck)
11. [Alert Suppression for Authorized Scanners](#11-alert-suppression-for-authorized-scanners)
12. [Adaptive Weight Tuning from Analyst Feedback](#12-adaptive-weight-tuning-from-analyst-feedback)
13. [SIEM Integration for Splunk SOC](#13-siem-integration-for-splunk-soc)
14. [Trusted Outbound Device Profiling](#14-trusted-outbound-device-profiling)
15. [Offline / Air-Gapped Evaluation](#15-offline--air-gapped-evaluation)
16. [Guardian Auto-Response for Small Networks](#16-guardian-auto-response-for-small-networks)

---

## 1. SOC Alert Triage

**Actor:** Tier-1 SOC analyst
**Goal:** Quickly triage an incoming alert and decide whether to escalate.

**Workflow:**

1. Analyst sees a new `high`-severity alert in the Streamlit dashboard, or calls `GET /api/alerts?severity=high&acknowledged=false`. (A webhook, Telegram or ntfy message arrives only for alerts created through `POST /api/predict`.)
2. Alert record includes:
   - `attack_type: "Exploits"` — supervised engine label
   - `engine_scores: {supervised: 0.92, isolation_forest: 0.78, lstm: 0.65, rules: 0.0}` — cross-engine agreement
   - `src_geo: {country: "RO", city: "Bucharest", lat: ..., lon: ...}` — geographic origin (only with `GEOIP_DB_PATH` set)
   - `triggered_rules` and `mitre_techniques` — filled when a rule fired
3. Three independent engines agree (supervised + IF + LSTM all elevated). Analyst escalates to Tier-2.
4. Analyst calls `PATCH /api/alerts/42` with `{"acknowledged": true, "label": "tp", "notes": "Escalated to Tier-2 per SOP."}`.
5. Analyst creates an incident: `POST /api/incidents` with title "Exploit attempts from Bucharest IP", then links the alert with `PATCH /api/alerts/42` `{"incident_id": <id>}`.

**Value:** Engine-level transparency eliminates the "why did this fire?" question — analysts immediately see which signals agreed and why.

---

## 2. Detecting a DoS Attack

**Actor:** Automated detection pipeline
**Goal:** Alert on a volumetric attack.

**Signal chain:**

1. Attacker sends a SYN flood against web server `10.0.0.5:80` from one source port, so all packets fall on one flow.
2. When the flow expires, the **Rules Engine** fires `syn_scan`: more than `PORT_SCAN_THRESHOLD` (20) SYNs and fewer than 5 forward packets carrying data. `syn_scan` is in the default `CRITICAL_RULES`, so the score is forced to 1.0 and the alert is `critical` whatever the other engines say.
3. **Isolation Forest**: `bytes_per_sec` and `packets_per_sec` of the source host diverge from what the model was fit on. Example score: 0.89.
4. **Supervised engine** may label the flow `DoS`. Example confidence: 0.87.
5. **LSTM**: 0.0 until the source IP has 20 completed flows in its buffer.
6. Without the critical-rule override the blend would be `(0.30×0.87 + 0.20×0.89 + 0.10×0.0 + 0.25×1.0) / 0.85 ≈ 0.81` → `high`.
7. The alert is written to the database. For ICMP floods the equivalent rule is `icmp_flood` (more than `ICMP_FLOOD_THRESHOLD` forward ICMP packets in the flow); it is not a critical rule, so it only contributes through the blend.

**Response time:** the alert appears after the flood flow has been idle for `FLOW_TIMEOUT` seconds (120 by default) plus up to 10 s. A flood that never pauses on the same 5-tuple is not scored until it stops or the flow is evicted.

---

## 3. Detecting a Port Scan

**Actor:** Automated detection pipeline
**Goal:** Detect nmap-style TCP SYN scan.

`nmap -sS` sends one SYN per destination port, so every probe is its own flow with a single SYN. The `syn_scan` rule counts SYNs inside one flow and does not fire, and each flow on its own is unremarkable to the supervised engine. The host-level `port_scan` rule (issue #87) covers this case: when one source starts TCP connections to `HOST_SCAN_PORTS` (15) distinct ports of one target within `HOST_SCAN_WINDOW_SECS` (60 s), every probe flow of the scan carries `port_scan`, which is in the default `CRITICAL_RULES`, so each flow that expires produces a critical alert candidate (deduplicated per source and attack type). As with every rule, the flows are scored after `FLOW_TIMEOUT` (120 s) of idle time, not while the scan runs. UDP scans and scans slower than the threshold per window are not detected; add monitoring sources to `HOST_SCAN_ALLOWLIST`.

Other signals that can add to an alert:

1. **Isolation Forest / baseline engine**: the scanning host's vector shows very high `unique_ports` and `uncommon_port_ratio`. Whether that crosses `ENSEMBLE_THRESHOLD` depends on the weights; with the defaults, a host-engine score alone usually does not.
2. **Supervised engine**: may label individual probe flows `Reconnaissance`.
3. **Threat intelligence**: a scanner whose IP is in a configured feed gets +0.30.

A repeated-SYN scan against a single port (same 5-tuple, more than 20 SYNs) does trigger `syn_scan` and a critical alert, with `mitre_techniques: [{id: "T1046", name: "Network Service Scanning", tactic: "Discovery"}]`.

---

## 4. Detecting Brute Force Authentication

**Actor:** Automated detection pipeline
**Goal:** Detect repeated failed login attempts against SSH.

**Current state: not detected by a dedicated rule.** `hydra` against SSH produces many short flows to port 22; no rule counts repeated short connections to one service (issue #88), and SSH is encrypted, so payload rules see nothing.

What can still raise an alert:

1. **Isolation Forest / LSTM / baseline**: elevated `packets_per_sec` with `unique_ports = 1`, and after 20 flows an unusual sequence for that source. Example scores 0.67 and 0.73.
2. **Supervised engine**: there is no brute-force class in the UNSW-NB15 label set; it may report `Benign` (score 0.0) or another class.
3. Example blend with the supervised engine at 0.0: `(0.30×0.0 + 0.20×0.67 + 0.10×0.73 + 0.25×0.0) / 0.85 ≈ 0.24` → no alert. A `Benign` supervised vote outweighing anomaly signals is tracked in issue #90.

For exposed services with application logs, the logwatch rules (`rules/gitea.yaml`: login brute force, sign-up floods) cover this case from the log side, but only through `python -m src.logwatch.replay` today; no live log tailer is wired in.

---

## 5. Detecting Slow/Covert Exfiltration

**Actor:** Automated detection pipeline
**Goal:** Detect gradual data exfiltration below rate thresholds.

**Context:** An attacker with insider access exfiltrates data at 50 KB/minute over 6 hours — well below any packet-rate threshold.

**Signal chain:**

1. Rate-based signals stay low (the rate is deliberately low).
2. Supervised engine sees no single anomalous flow (each individual flow looks normal).
3. **Rules engine**: `asymmetric_upload` fires on any flow with more than 10 forward packets, at least one backward packet and a forward/backward byte ratio above 50. Rules score 1.0, MITRE T1041.
4. **Isolation Forest**: the host features have no upload/download ratio, so the IF only reacts if payload size or entropy for the host drifts. Example score: 0.40.
5. **LSTM**: once the source has 20 completed flows, a sustained change in its host vectors raises the reconstruction error. Example score: 0.81.
6. **Ensemble**: `(0.30×0.15 + 0.20×0.40 + 0.10×0.81 + 0.25×1.0) / 0.85 ≈ 0.54` — just below the default 0.55 threshold.

**Tuning for this scenario:**
- Lower `ENSEMBLE_THRESHOLD` to 0.50, or
- Add `asymmetric_upload` to `CRITICAL_RULES` so a hit always alerts (expect false positives from backups and uploads; pair it with suppression rules), or
- Shift weight towards rules and LSTM (`WEIGHT_RULES`, `WEIGHT_LSTM`); the five weights must still sum to 1.0.

This illustrates the **tuning knobs** available: the system can be made more or less sensitive per attack category.

---

## 6. Web Application Attack Detection

**Actor:** Automated detection pipeline
**Goal:** Detect SQL injection and XSS attempts against a web application.

**Signal chain:**

1. Attacker sends `GET /login?user=admin' OR '1'='1 HTTP/1.1` to port 80. (Payload rules need plaintext: TLS records and high-entropy payloads are skipped, so HTTPS traffic must be inspected after TLS termination.)
2. **Payload Analyzer**: the SQLi pattern matches and returns the name `sql_injection`.
3. **Rules Engine**: adds `payload:sql_injection` to the triggered rules; rules score = 1.0.
4. `payload:sql_injection` is in the default `CRITICAL_RULES`: the ensemble score is forced to 1.0 and the alert is `critical`, whatever the supervised label is.
5. **JA3 fingerprint** is stored only for TLS flows (there is none for plaintext HTTP).
6. **MITRE techniques**: T1190 (Exploit Public-Facing Application).

**Multi-attack scenario:** If the same IP sends both SQLi and XSS probes in one flow, both names are stored in `triggered_rules`. On the `POST /api/predict` path, once the IP reaches `CORRELATION_THRESHOLD` (5) alerts within `CORRELATION_WINDOW_SECS` (300 s), the correlation module creates an incident titled "Correlated attack from X.X.X.X" and links later alerts to it. Alerts from the live detector are not correlated automatically.

---

## 7. TLS/JA3 Malware Identification

**Actor:** Automated detection pipeline
**Goal:** Identify malware C2 beacon by TLS fingerprint.

**Context:** A compromised workstation beacons to a C2 server over TLS. The traffic volume is low and looks like normal HTTPS.

**Signal chain:**

1. Workstation connects to `203.0.113.5:443` via TLS.
2. **JA3 fingerprinter** extracts ClientHello fields.
3. JA3 hash `a0e9f5d64349fb13191bc781f81f42e1` matches an entry in `MALICIOUS_JA3_FILE` (e.g., exported from SSLBL or a custom list).
4. **Rules Engine fires**: `malicious_ja3` rule. rules_score = 1.0.
5. `malicious_ja3` is in the default `CRITICAL_RULES`, so the alert fires at `critical` severity even if supervised and IF scores are low (traffic volume looks benign).
6. Alert: `triggered_rules: ["malicious_ja3"]`, `ja3_hash: "a0e9f5d..."`, `ja3_string: "771,49195..."`.
7. Analyst can use the JA3 string to identify the specific TLS implementation (e.g., known Cobalt Strike profile, Metasploit default).

**Maintaining the JA3 list:** Update `MALICIOUS_JA3_FILE` with new hashes; `main.py` reads the file at startup only, so restart the detector. Alternatively set `MALICIOUS_JA3_URL`: the threat-intel store fetches that list and a match adds +0.30 to the score and the `threat_intel_malicious_ja3` entry (it does not force an alert).

---

## 8. API-Only Integration with Zeek/Arkime

**Actor:** DevSecOps team with existing capture infrastructure
**Goal:** Use CNDS ensemble scoring without replacing existing packet capture.

**Architecture:**

```
Zeek / Arkime / CICFlowMeter
        │ conn.log / feature export
        ▼
Custom script (Python)
  └── Parses flow features
  └── Calls POST /api/predict
  └── Receives ensemble_score, attack_type, mitre_techniques
  └── Writes to SIEM or creates tickets
```

**Integration script (pseudocode):**
```python
import httpx

def score_zeek_conn(conn_record):
    flow_features = zeek_conn_to_cicflowmeter(conn_record)  # 76 features
    host_features = get_host_history(conn_record["id.orig_h"])  # 18 features

    resp = httpx.post("http://cnds:8000/api/predict",
        headers={"Authorization": f"Bearer {TOKEN}"},  # or {"X-API-Key": API_KEY}
        json={
            "src_ip": conn_record["id.orig_h"],
            "dst_ip": conn_record["id.resp_h"],
            "dst_port": conn_record["id.resp_p"],
            "protocol": 6,  # IP protocol number (6 TCP, 17 UDP, 1 ICMP)
            "flow_features": flow_features,
            "host_features": host_features
        }
    )
    return resp.json()
```

Run the API on its own with `uvicorn src.api.main:app` (no live capture). `flow_features` must hold exactly 76 values and `host_features` exactly 18. This path also applies IP allow/block lists, confidence decay, correlation and notifications.

---

## 9. SOC Incident Management Workflow

**Actor:** Tier-2 SOC analyst
**Goal:** Investigate a correlated incident and drive it to resolution.

**Workflow:**

1. `GET /api/incidents?status=open` — retrieves all open incidents.
2. There is no `GET /api/incidents/{id}`: read the incident from the list above and its alerts with `GET /api/alerts?src_ip=10.0.0.99` (each alert carries `incident_id`).
3. Analyst reviews alert timeline: 8 alerts from `10.0.0.99` over 10 minutes, a mix of `Reconnaissance` and `Exploits` labels.
4. Analyst updates incident: `PATCH /api/incidents/7` `{status: "investigating", assigned_to: "alice", notes: "Possible external attacker testing perimeter"}`.
5. Analyst creates a suppression rule for the IP while investigation continues (if authorized): `POST /api/suppression-rules` with `src_ip: "10.0.0.99"`, `min_severity: "low"`, `duration_minutes: 1440` (the server computes `expires_at`), `reason: "Under investigation — suppressing low-severity alerts"`.
6. After firewall block is confirmed, analyst resolves: `PATCH /api/incidents/7` `{status: "resolved", notes: "Blocked at perimeter firewall. No lateral movement detected."}`.
7. Export alert history: `GET /api/alerts/export?format=csv&hours=48` for post-incident report.

---

## 10. Compliance Reporting with MITRE ATT&CK

**Actor:** CISO / Compliance officer
**Goal:** Generate evidence that network monitoring covers required MITRE ATT&CK techniques.

**Workflow:**

1. `GET /api/alerts/export?format=json&hours=720` (30 days).
2. Parse `mitre_techniques` array from each alert.
3. Aggregate unique technique IDs and tactics covered.
4. Map to organizational threat model (e.g., MITRE Navigator layer).

**Techniques covered by CNDS detection:**

| Tactic | Techniques |
|---|---|
| Discovery | T1046 (Network Service Scanning), T1083 (File and Directory Discovery) |
| Initial Access | T1190 (Exploit Public-Facing Application) |
| Execution | T1059 (Command and Scripting Interpreter), T1059.007 (JavaScript), T1203 (Exploitation for Client Execution) |
| Command and Control | T1071 (Application Layer Protocol), T1573 (Encrypted Channel) |
| Exfiltration | T1041 (Exfiltration Over C2 Channel), T1030 (Data Transfer Size Limits) |
| Impact | T1498 (Network Denial of Service), T1498.001 (Direct Network Flood) |
| Credential Access | T1110 (Brute Force), T1110.001 (Password Guessing): only with a model that emits CIC-IDS2017 labels |

The table lists what `src/enrichment/mitre.py` can attach. With the shipped models the techniques come from the rules that fired, because the UNSW-NB15 class names have no entry in the label map.

This coverage maps directly to PCI DSS Requirement 11.4 (intrusion detection) and NIST CSF DE.CM-1 (network monitoring).

---

## 11. Alert Suppression for Authorized Scanners

**Actor:** Security engineer running a scheduled vulnerability scan
**Goal:** Prevent CNDS from generating tickets for authorized Nessus/OpenVAS scans.

**Workflow:**

1. Before scan window: `POST /api/suppression-rules`:
```json
{
  "src_ip": "192.168.1.20",
  "reason": "Authorized Nessus scan — change #2026-042",
  "duration_minutes": 240
}
```
2. During scan: alerts matching `src_ip=192.168.1.20` are not stored (the detector logs them as `[SUPPRESSED]`).
3. After scan window: the rule expires automatically (the server computes `expires_at` from `duration_minutes`; default 120, at most 7 days for an IP-wide rule). Or delete it with `DELETE /api/suppression-rules/3` (admin).

**Granular suppression:** The rule can also match on `dst_ip`, `src_port`, `dst_port`, `attack_type` and `min_severity` (for example, suppress only `Reconnaissance` from the scanner IP while still alerting on payload signatures). This allows suppressing known-benign scan behaviors while maintaining detection for unexpected activity from the same IP.

---

## 12. Adaptive Weight Tuning from Analyst Feedback

**Actor:** Senior SOC analyst or detection engineer
**Goal:** Improve ensemble accuracy based on observed false positive patterns.

**Context:** On this specific network, the Isolation Forest generates frequent false positives for NAS backup traffic (large byte rates that look anomalous but are normal).

**Workflow:**

1. Set `ADAPTIVE_WEIGHTS_ENABLED=true`. Analysts label alerts over two weeks:
   - `PATCH /api/alerts/{id}` `{"acknowledged": true, "label": "fp", "notes": "NAS backup traffic"}`
   - An acknowledged alert counts as a false positive when `label` is `fp` (or its notes contain the words "false positive"); every other acknowledged alert counts as a true positive.
2. Once at least `ADAPTIVE_MIN_SAMPLES` (100) alerts are acknowledged, `GET /api/adaptive-weights` returns suggested weights for four engines (the baseline engine is not part of the calculation; the values below are an example):
   ```json
   {
     "status": "ok",
     "weights": {
       "supervised": 0.31,
       "isolation_forest": 0.17,
       "lstm": 0.27,
       "rules": 0.25
     }
   }
   ```
   Before that it returns `{"status": "insufficient_data", "weights": null}`.
3. The suggestion is not applied automatically. Copy it into `.env`, leaving room for the baseline weight so the five values sum to 1.0, for example:
   ```
   WEIGHT_SUPERVISED=0.27
   WEIGHT_IFOREST=0.14
   WEIGHT_LSTM=0.23
   WEIGHT_RULES=0.21
   WEIGHT_BASELINE=0.15
   ```
4. Restart CNDS for the new weights to take effect.

Alternatively, add a suppression rule for the NAS IP to achieve the same effect without reweighting.

---

## 13. SIEM Integration for Splunk SOC

**Actor:** SIEM administrator
**Goal:** Feed CNDS alerts into Splunk Enterprise Security.

**Setup:**

1. Copy `siem/splunk/inputs.conf` to Splunk forwarder config. CNDS has no HEC-specific settings: put the collector URL in `WEBHOOK_URLS`, behind a relay that adds the `Authorization: Splunk <token>` header and the `event` wrapper (CNDS sends neither).
2. Copy `siem/splunk/props.conf` to Splunk for field extractions.
3. Import `siem/splunk/savedsearches.conf` for pre-built correlation searches.

**Data flow:**
- CNDS posts a JSON summary to each `WEBHOOK_URLS` entry for alerts persisted through `POST /api/predict` whose severity reaches `NOTIFY_MIN_SEVERITY`; alerts written by the live detector are not pushed, so pull them with `GET /api/alerts/export` or the syslog forwarder.
- Splunk parses `mitre_techniques`, `engine_scores`, `severity`, `src_geo` as indexed fields.
- Pre-built searches: "Critical alerts last 24h", "Top attacking IPs", "MITRE technique heatmap".

**CIM Mapping:**

| CNDS Field | Splunk CIM Field |
|---|---|
| `src_ip` | `src` |
| `dst_ip` | `dest` |
| `attack_type` | `signature` |
| `severity` | `severity` |
| `src_port` / `dst_port` | `src_port` / `dest_port` |

`props.conf` defines no alias for `mitre_techniques` or `src_geo`; with `KV_MODE = json` Splunk extracts them under their JSON paths (`mitre_techniques{}.id`, `src_geo.country`).

---

## 14. Trusted Outbound Device Profiling

**Actor:** Network administrator in a home/lab network
**Goal:** Prevent CNDS from alerting on known-benign outbound traffic from specific devices.

**Context:** The lab has a NAS that regularly syncs with NAS QuickConnect (relay.nas-provider.com) and a Git Server server that fetches GitHub updates. These generate false positives from the supervised and anomaly engines.

**Configuration in `.env`:**
```
TRUSTED_OUTBOUND='{
  "192.168.1.20": ["relay.nas-provider.com", "nas-provider.to"],
  "192.168.1.30": ["github.com", "api.github.com", "objects.githubusercontent.com"],
  "192.168.1.31": ["registry-1.docker.io", "auth.docker.io"]
}'
```

**Behavior:**
- When a flow from a listed source IP expires, CNDS reverse-resolves the destination IP (PTR lookup, 2 s timeout). If the hostname ends with one of the listed domains, the flow is dropped before scoring.
- The match is on the reverse-DNS name of the destination, not on the name the device queried, so it only works for destinations whose PTR record ends in the listed suffix (many CDN and cloud addresses do not).
- Other traffic from the same IPs still goes through detection.

This is distinct from the IP allowlist (`IP_ALLOWLIST`, applied on the `POST /api/predict` path) — trusted outbound is per source IP and destination domain, on the capture path.

---

## 15. Offline / Air-Gapped Evaluation

**Actor:** Security engineer evaluating CNDS before deployment
**Goal:** Validate detection coverage without root access or live network.

**Workflow:**

1. Clone the repo on any Linux/macOS machine.
2. Run the digital twin demo (no root, no live capture):
   ```bash
   cd demo
   python run_demo.py
   ```
3. The demo generates synthetic PCAPs for the scenarios in `demo/generate_traffic.py`, replays them through the detection pipeline, and prints a summary.
4. Review detection rates per scenario, false positive counts, and MITRE technique coverage.
5. Use `scripts/pcap_replay.py` for custom PCAP evaluation:
   ```bash
   python scripts/pcap_replay.py captures/lab_traffic.pcap --output results.json --report results.md
   ```

See [digital-twin-sandbox.md](digital-twin-sandbox.md) for the full demo documentation.

---

## 16. Guardian Auto-Response for Small Networks

**Actor:** Small business or home-lab operator without a 24/7 SOC
**Goal:** Automatically contain an obvious threat (a compromised IoT device beaconing out, a scanning host) without needing a human to be watching in real time.

**Workflow:**

1. Deploy AdGuard Home as the network's DNS resolver (if not already running).
2. Configure the guardian, starting conservative:
   ```bash
   GUARDIAN_ENABLED=false            # keep off until the whitelist is reviewed
   GUARDIAN_MIN_SEVERITY=critical
   GUARDIAN_BLOCK_MINUTES=30
   GUARDIAN_WHITELIST=192.168.1.1,192.168.1.10,192.168.1.11
   ADGUARD_URL=http://192.168.1.62:8001
   ADGUARD_USERNAME=...
   ADGUARD_PASSWORD=...
   ```
3. Verify the whitelist covers every device you don't want auto-blocked, then set `GUARDIAN_ENABLED=true` and restart the `api` container.
4. A compromised smart-home device starts a port scan or beacons to a known-bad host → CNDS fires a `critical` alert → the guardian blocks its DNS resolution via AdGuard within one poll cycle and logs a `mitigation_actions` row.
5. If `TELEGRAM_BOT_TOKEN` is configured, the operator gets a push notification with **Confirm** (make the block permanent) / **Undo now** buttons. If they do nothing, the block automatically expires after `GUARDIAN_BLOCK_MINUTES` — a false positive never becomes a permanent lockout.
6. Query `GET /api/alerts?src_ip=<device_ip>` and the `mitigation_actions` table afterward to review exactly what happened and why.

**Important:** `GUARDIAN_WHITELIST` must never include a broad range covering the whole monitored subnet (e.g. `192.168.1.0/24`) — that's exactly the range the detector captures traffic on, so it would silently disable every auto-block. List individual devices/infrastructure instead.
