# CNDS — Use Cases

This document describes operational scenarios for CNDS across different deployment contexts and user roles.

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

---

## 1. SOC Alert Triage

**Actor:** Tier-1 SOC analyst
**Goal:** Quickly triage an incoming alert and decide whether to escalate.

**Workflow:**

1. Analyst receives a webhook notification (or Telegram message) for a `high`-severity alert.
2. Analyst opens the Streamlit dashboard or calls `GET /api/alerts?severity=high&acknowledged=false`.
3. Alert record includes:
   - `attack_type: "FTP-Patator"` — supervised engine label
   - `engine_scores: {supervised: 0.92, iforest: 0.78, lstm: 0.65, rules: 0.0}` — cross-engine agreement
   - `src_geo: {country: "Romania", city: "Bucharest"}` — geographic origin
   - `mitre_techniques: [{id: "T1110", name: "Brute Force"}]` — framework context
4. Three independent engines agree (supervised + IF + LSTM all elevated). Analyst escalates to Tier-2.
5. Analyst calls `PATCH /api/alerts/42` to acknowledge and add a note: "Escalated to Tier-2 per brute-force SOP."
6. Analyst creates an incident: `POST /api/incidents` with title "FTP brute force from Bucharest IP" and links the alert.

**Value:** Engine-level transparency eliminates the "why did this fire?" question — analysts immediately see which signals agreed and why.

---

## 2. Detecting a DoS Attack

**Actor:** Automated detection pipeline
**Goal:** Alert on volumetric attack within seconds of onset.

**Signal chain:**

1. Attacker begins HTTP flood at 5,000 requests/second against web server `10.0.0.5`.
2. **Rules Engine fires immediately**: `packet_rate > ICMP_FLOOD_THRESHOLD` within the first few seconds.
3. **Isolation Forest score spikes**: `byte_rate` and `packet_rate` features diverge sharply from the baseline distribution. Score: 0.89.
4. **Supervised engine labels** the flow: "DoS Hulk" at 0.87 confidence (high forward packet counts, IAT drops to near-zero).
5. **LSTM score** is moderate (0.55) — not enough sequence history yet for the new source IP.
6. **Ensemble**: `0.40×0.87 + 0.30×0.89 + 0.20×0.55 + 0.10×1.0 = 0.82` → `critical` severity.
7. Alert fires. WebSocket broadcast to dashboard. Webhook POSTed to Splunk HEC.
8. Telegram notification sent to on-call engineer.

**Response time:** First alert within 1–3 seconds of attack onset (limited by `MIN_PACKETS_FOR_ML` threshold for flow feature stability).

---

## 3. Detecting a Port Scan

**Actor:** Automated detection pipeline
**Goal:** Detect nmap-style TCP SYN scan.

**Signal chain:**

1. Attacker runs `nmap -sS 192.168.1.0/24` from `10.0.0.99`.
2. **Rules Engine fires**: `syn_flag_count > PORT_SCAN_THRESHOLD AND tot_fwd_pkts < 3`. Rule: `syn_scan`.
3. **Supervised engine**: "PortScan" label at 0.85 confidence. The combination of high SYN count, low packet total, and near-zero backward traffic is characteristic.
4. **Isolation Forest**: Host features show massive `unique_ports` and `uncommon_port_ratio` values. Score: 0.91.
5. **LSTM**: After 20+ packets from `10.0.0.99`, the sequence of increasing port diversity scores high. Score: 0.72.
6. **Ensemble**: `0.40×0.85 + 0.30×0.91 + 0.20×0.72 + 0.10×1.0 = 0.85` → `critical`.
7. Alert: `mitre_techniques: [{id: "T1046", name: "Network Service Scanning", tactic: "Discovery"}]`.

**Low false-positive risk:** The rule requires both elevated SYN count AND low forward traffic — a legitimate TLS handshake or HTTP keep-alive does not match.

---

## 4. Detecting Brute Force Authentication

**Actor:** Automated detection pipeline
**Goal:** Detect repeated failed login attempts against SSH.

**Signal chain:**

1. Attacker runs `hydra -t 4 -l root -P rockyou.txt ssh://192.168.1.10`.
2. **Supervised engine**: "SSH-Patator" label at 0.81 confidence. The feature pattern — many short bidirectional flows to port 22 with consistent byte sizes — matches the training data.
3. **Isolation Forest**: Elevated `packet_rate` and `unique_ports = 1` (all traffic to port 22) produces an anomaly score of 0.67.
4. **LSTM**: Repeated short-duration flows over time create an unusual temporal pattern. Score: 0.73 after 20 flows.
5. **Rules Engine**: No rule fires (threshold counts target faster attacks).
6. **Ensemble**: `0.40×0.81 + 0.30×0.67 + 0.20×0.73 + 0.10×0.0 = 0.67` → `medium`.
7. After 5 alerts from the same IP within 300 seconds, the correlation module auto-creates an incident.
8. All subsequent alerts from `10.0.0.99` are linked to the incident.

---

## 5. Detecting Slow/Covert Exfiltration

**Actor:** Automated detection pipeline
**Goal:** Detect gradual data exfiltration below rate thresholds.

**Context:** An attacker with insider access exfiltrates data at 50 KB/minute over 6 hours — well below any packet-rate threshold.

**Signal chain:**

1. Rules engine sees no threshold violations (rate is deliberately low).
2. Supervised engine sees no single anomalous flow (each individual flow looks normal).
3. **Isolation Forest**: Over time, `fwd_bytes / bwd_bytes` ratio (asymmetric upload feature) gradually increases. Eventually the ratio exceeds 10× normal and IF scores 0.72.
4. **LSTM** is the primary detector here: Per-IP sequence buffer accumulates 20 vectors showing a persistent, slow increase in upload ratio. Reconstruction error grows to 0.81.
5. **Ensemble**: `0.40×0.15 + 0.30×0.72 + 0.20×0.81 + 0.10×0.0 = 0.54` — just below the default 0.55 threshold!

**Tuning for this scenario:**
- Lower `ENSEMBLE_THRESHOLD` to 0.50, or
- Increase LSTM weight: `WEIGHT_LSTM=0.35`, reduce supervised: `WEIGHT_SUPERVISED=0.30`
- The `ATTACK_TYPE_WEIGHTS` config can set higher LSTM weight for suspected exfiltration patterns.

This illustrates the **tuning knobs** available: the system can be made more or less sensitive per attack category.

---

## 6. Web Application Attack Detection

**Actor:** Automated detection pipeline
**Goal:** Detect SQL injection and XSS attempts against a web application.

**Signal chain:**

1. Attacker sends `GET /login?user=admin' OR '1'='1 HTTP/1.1` to port 443.
2. **Payload Analyzer**: SQLi pattern regex matches. `payload_features[0] = 1.0`. Triggered rule: `payload_sqli`.
3. **Rules Engine fires**: `any(payload_features[0:6]) == 1` → rules_score = 1.0.
4. **Supervised engine**: "Web Attack – SQL Injection" at 0.79 confidence.
5. **JA3 fingerprint** stored: fingerprint identifies the HTTP client (curl, sqlmap, etc.).
6. **Ensemble**: High rules score pulls ensemble above threshold. `severity: high`.
7. **MITRE techniques**: T1190 (Exploit Public-Facing Application).

**Multi-attack scenario:** If same IP sends both SQLi and XSS probes, both pattern flags fire and multiple triggered_rules are stored. After 5 alerts, the correlation engine groups them into an incident titled "Web application probing from X.X.X.X".

---

## 7. TLS/JA3 Malware Identification

**Actor:** Automated detection pipeline
**Goal:** Identify malware C2 beacon by TLS fingerprint.

**Context:** A compromised workstation beacons to a C2 server over TLS. The traffic volume is low and looks like normal HTTPS.

**Signal chain:**

1. Workstation connects to `203.0.113.5:443` via TLS.
2. **JA3 fingerprinter** extracts ClientHello fields.
3. JA3 hash `a0e9f5d64349fb13191bc781f81f42e1` matches an entry in `MALICIOUS_JA3_FILE` (e.g., from SSLBL or custom threat intel feed).
4. **Rules Engine fires**: `ja3_malicious` rule. rules_score = 1.0.
5. Even if supervised and IF scores are low (traffic volume looks benign), the rules engine weight (10%) pushes the ensemble above threshold.
6. Alert: `triggered_rules: ["malicious_ja3"]`, `ja3_hash: "a0e9f5d..."`, `ja3_string: "771,49195..."`.
7. Analyst can use the JA3 string to identify the specific TLS implementation (e.g., known Cobalt Strike profile, Metasploit default).

**Maintaining the JA3 list:** Update `MALICIOUS_JA3_FILE` with new hashes from threat intel. CNDS reloads the file on startup.

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
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={
            "src_ip": conn_record["id.orig_h"],
            "dst_ip": conn_record["id.resp_h"],
            "dst_port": conn_record["id.resp_p"],
            "protocol": conn_record["proto"],
            "flow_features": flow_features,
            "host_features": host_features
        }
    )
    return resp.json()
```

This mode runs the API without `--api` flag equivalent, using `uvicorn src.api.main:app` in prediction-only mode (no live capture).

---

## 9. SOC Incident Management Workflow

**Actor:** Tier-2 SOC analyst
**Goal:** Investigate a correlated incident and drive it to resolution.

**Workflow:**

1. `GET /api/incidents?status=open` — retrieves all open incidents.
2. `GET /api/incidents/7` — fetches incident with all linked alerts.
3. Analyst reviews alert timeline: 8 alerts from `10.0.0.99` over 10 minutes, mix of PortScan and SSH-Patator types.
4. Analyst updates incident: `PATCH /api/incidents/7` `{status: "investigating", assigned_to: "alice", notes: "Possible external attacker testing perimeter"}`.
5. Analyst creates a suppression rule for the IP while investigation continues (if authorized): `POST /api/suppression-rules` with `src_ip: "10.0.0.99"`, `min_severity: "low"`, `expires_at: "+24h"`, `reason: "Under investigation — suppressing low-severity alerts"`.
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
| Reconnaissance | T1046 (Network Service Scanning) |
| Initial Access | T1190 (Exploit Public-Facing App) |
| Execution | T1059.007 (XSS), T1203 (Client Exploitation) |
| Command & Control | T1071 (App Layer Protocol), T1071.001 (Web) |
| Exfiltration | T1048 (Alt Protocol), T1030 (Size Limits) |
| Impact | T1498 (DoS — Network), T1499 (DoS — Endpoint) |
| Credential Access | T1110 (Brute Force), T1110.001 (Password Guessing) |

This coverage maps directly to PCI DSS Requirement 11.4 (intrusion detection) and NIST CSF DE.CM-1 (network monitoring).

---

## 11. Alert Suppression for Authorized Scanners

**Actor:** Security engineer running a scheduled vulnerability scan
**Goal:** Prevent CNDS from generating tickets for authorized Nessus/OpenVAS scans.

**Workflow:**

1. Before scan window: `POST /api/suppression-rules`:
```json
{
  "src_ip": "192.168.1.50",
  "reason": "Authorized Nessus scan — change #2026-042",
  "expires_at": "2026-03-29T20:00:00Z"
}
```
2. During scan: All alerts matching `src_ip=192.168.1.50` are silently suppressed.
3. After scan window: Rule expires automatically at `expires_at`. Or manually delete with `DELETE /api/suppression-rules/3`.

**Granular suppression:** The rule can match on `attack_type` (suppress only "PortScan" from the scanner IP while still alerting on unusual payloads). This allows suppressing known-benign scan behaviors while maintaining detection for unexpected activity from the same IP.

---

## 12. Adaptive Weight Tuning from Analyst Feedback

**Actor:** Senior SOC analyst or detection engineer
**Goal:** Improve ensemble accuracy based on observed false positive patterns.

**Context:** On this specific network, the Isolation Forest generates frequent false positives for NAS backup traffic (large byte rates that look anomalous but are normal).

**Workflow:**

1. Analysts label 200 alerts over two weeks:
   - `PATCH /api/alerts/{id}` `{notes: "FP — NAS backup traffic", acknowledged: true}`
   - A labeling convention: alerts noted "FP" are tracked internally.
2. After 200+ labels, call `GET /api/adaptive-weights`:
   ```json
   {
     "suggested_weights": {
       "supervised": 0.50,
       "iforest": 0.20,  ← reduced due to FP pattern
       "lstm": 0.22,
       "rules": 0.08
     }
   }
   ```
3. Update `.env`:
   ```
   WEIGHT_SUPERVISED=0.50
   WEIGHT_IFOREST=0.20
   WEIGHT_LSTM=0.22
   WEIGHT_RULES=0.08
   ```
4. Restart CNDS. New weights reduce false positive rate from NAS traffic.

Alternatively, add a suppression rule for the NAS IP to achieve the same effect without reweighting.

---

## 13. SIEM Integration for Splunk SOC

**Actor:** SIEM administrator
**Goal:** Feed CNDS alerts into Splunk Enterprise Security.

**Setup:**

1. Copy `siem/splunk/inputs.conf` to Splunk forwarder config. Configure `SPLUNK_HEC_URL` and `SPLUNK_HEC_TOKEN` in CNDS `.env`.
2. Copy `siem/splunk/props.conf` to Splunk for field extractions.
3. Import `siem/splunk/savedsearches.conf` for pre-built correlation searches.

**Data flow:**
- CNDS fires webhook to Splunk HEC on every alert.
- Splunk parses `mitre_techniques`, `engine_scores`, `severity`, `src_geo` as indexed fields.
- Pre-built searches: "Critical alerts last 24h", "Top attacking IPs", "MITRE technique heatmap".

**CIM Mapping:**

| CNDS Field | Splunk CIM Field |
|---|---|
| `src_ip` | `src` |
| `dst_ip` | `dest` |
| `attack_type` | `signature` |
| `severity` | `severity` |
| `mitre_techniques[].id` | `mitre_technique_id` |
| `src_geo.country` | `src_country` |

---

## 14. Trusted Outbound Device Profiling

**Actor:** Network administrator in a home/lab network
**Goal:** Prevent CNDS from alerting on known-benign outbound traffic from specific devices.

**Context:** The lab has a NAS that regularly syncs with Synology QuickConnect (relay.synology.com) and a Gitea server that fetches GitHub updates. These generate "Bot" and "Infiltration" false positives from the supervised engine.

**Configuration in `.env`:**
```
TRUSTED_OUTBOUND='{
  "192.168.1.60": ["relay.synology.com", "quickconnect.to"],
  "192.168.1.62": ["github.com", "api.github.com", "objects.githubusercontent.com"],
  "192.168.1.86": ["registry-1.docker.io", "auth.docker.io"]
}'
```

**Behavior:**
- Packets from trusted IPs to their listed domains skip the detection pipeline entirely.
- Alerts are not generated, suppression rules are not needed.
- Other traffic from the same IPs (unusual destinations) still goes through detection.

This is distinct from the IP allowlist (which skips all detection from an IP) — trusted outbound is per-destination-domain.

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
3. The demo generates synthetic PCAPs for 5+ attack scenarios, replays them through the detection pipeline, and produces a summary report.
4. Review detection rates per scenario, false positive counts, and MITRE technique coverage.
5. Use `scripts/pcap_replay.py` for custom PCAP evaluation:
   ```bash
   python scripts/pcap_replay.py --pcap captures/lab_traffic.pcap --output results.json
   ```

See [digital-twin-sandbox.md](digital-twin-sandbox.md) for the full demo documentation.
