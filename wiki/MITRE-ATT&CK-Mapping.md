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

### Attack-type labels

Exact match first, then a case-insensitive partial match in either direction. Labels are CIC-IDS2017 style; the UNSW-NB15 classes emitted by the FT-Transformer / Random Forest (`Exploits`, `Fuzzers`, `Reconnaissance`, `Generic`, `Worms`, `Backdoor`, `Shellcode`, `Analysis`) have no entry, so for those only rule-based techniques are attached. The bare label `DoS` partial-matches the first `DoS *` key and returns T1498.

| Attack Type | Technique ID | Technique Name | Tactic |
|---|---|---|---|
| DoS Hulk | T1498 | Network Denial of Service | Impact |
| DoS GoldenEye | T1498 | Network Denial of Service | Impact |
| DoS Slowhttptest | T1498.001 | Direct Network Flood | Impact |
| DoS slowloris | T1498.001 | Direct Network Flood | Impact |
| DDoS | T1498 | Network Denial of Service | Impact |
| PortScan | T1046 | Network Service Scanning | Discovery |
| FTP-Patator | T1110.001 | Password Guessing | Credential Access |
| SSH-Patator | T1110.001 | Password Guessing | Credential Access |
| Bot | T1071 | Application Layer Protocol | Command and Control |
| Infiltration | T1041, T1071 | Exfiltration Over C2 Channel, Application Layer Protocol | Exfiltration, Command and Control |
| Web Attack – Brute Force | T1110 | Brute Force | Credential Access |
| Web Attack – XSS | T1059.007 | JavaScript | Execution |
| Web Attack – Sql Injection | T1190 | Exploit Public-Facing Application | Initial Access |
| Heartbleed | T1190 | Exploit Public-Facing Application | Initial Access |

### Rule Triggers

| Rule | Technique IDs |
|---|---|
| `icmp_flood` | T1498.001 (Direct Network Flood) |
| `syn_scan` | T1046 (Network Service Scanning) |
| `large_payload` | T1030 (Data Transfer Size Limits) |
| `asymmetric_upload` | T1041 (Exfiltration Over C2 Channel) |
| `payload:sql_injection` | T1190 (Exploit Public-Facing Application) |
| `payload:xss` | T1059.007 (JavaScript) |
| `payload:command_injection` | T1059 (Command and Scripting Interpreter) |
| `payload:path_traversal` | T1083 (File and Directory Discovery) |
| `payload:log4j` | T1190, T1203 (Exploitation for Client Execution) |
| `payload:shellshock` | T1190 (Exploit Public-Facing Application) |
| `malicious_ja3` | T1071 (Application Layer Protocol), T1573 (Encrypted Channel) |

## Database Storage

MITRE technique data is stored as JSON in the `mitre_techniques` column of the alerts table, making it queryable and exportable.
