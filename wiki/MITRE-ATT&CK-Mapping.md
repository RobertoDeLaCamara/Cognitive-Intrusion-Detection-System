# MITRE ATT&CK Mapping

Every alert is automatically enriched with [MITRE ATT&CK](https://attack.mitre.org/) technique IDs.

**File:** `src/enrichment/mitre.py`

## How It Works

When an alert fires, the MITRE mapper looks up technique IDs from two sources:

1. **Supervised model labels** — 14 attack types are mapped to ATT&CK techniques
2. **Rule triggers** — 11 rules (including `malicious_ja3`) are mapped to techniques

Techniques are deduplicated when multiple sources map to the same ID.

## Example Alert Payload

```json
{
  "attack_type": "DoS Hulk",
  "mitre_techniques": [
    {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"}
  ]
}
```

## Mappings

### Supervised Model Attack Types

| Attack Type | Technique ID | Technique Name | Tactic |
|---|---|---|---|
| DoS Hulk | T1498 | Network Denial of Service | Impact |
| DoS Slowloris | T1498 | Network Denial of Service | Impact |
| DoS SlowHTTPTest | T1498 | Network Denial of Service | Impact |
| DoS GoldenEye | T1498 | Network Denial of Service | Impact |
| PortScan | T1046 | Network Service Scanning | Discovery |
| FTP-Patator | T1110 | Brute Force | Credential Access |
| SSH-Patator | T1110 | Brute Force | Credential Access |
| Web Attack – XSS | T1059.007 | JavaScript | Execution |
| Web Attack – SQL Injection | T1190 | Exploit Public-Facing Application | Initial Access |
| Web Attack – Brute Force | T1110 | Brute Force | Credential Access |
| Infiltration | T1071 | Application Layer Protocol | Command and Control |
| Heartbleed | T1190 | Exploit Public-Facing Application | Initial Access |
| Bot | T1071 | Application Layer Protocol | Command and Control |

### Rule Triggers

| Rule | Technique IDs |
|---|---|
| `icmp_flood` | T1498 |
| `syn_scan` | T1046 |
| `sqli` | T1190 |
| `xss` | T1059.007 |
| `lfi` | T1083 (File and Directory Discovery) |
| `malicious_ja3` | T1071, T1573 (Encrypted Channel) |
| `large_payload` | T1030 (Data Transfer Size Limits) |
| `rate_spike` | T1498 |

## Database Storage

MITRE technique data is stored as JSON in the `mitre_techniques` column of the alerts table, making it queryable and exportable.
