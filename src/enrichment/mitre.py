"""MITRE ATT&CK mapping for CNDS detections.

Maps supervised model labels and rule triggers to ATT&CK technique IDs.
Reference: https://attack.mitre.org/techniques/enterprise/
"""

from typing import Dict, List, Optional

# Attack type (from supervised model) → ATT&CK techniques
_ATTACK_TYPE_MAP: Dict[str, List[Dict[str, str]]] = {
    "DoS Hulk":        [{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"}],
    "DoS GoldenEye":   [{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"}],
    "DoS Slowhttptest": [{"id": "T1498.001", "name": "Direct Network Flood", "tactic": "Impact"}],
    "DoS slowloris":   [{"id": "T1498.001", "name": "Direct Network Flood", "tactic": "Impact"}],
    "DDoS":            [{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"}],
    "PortScan":        [{"id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery"}],
    "FTP-Patator":     [{"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"}],
    "SSH-Patator":     [{"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"}],
    "Bot":             [{"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"}],
    "Infiltration":    [{"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
                        {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"}],
    "Web Attack – Brute Force": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
    "Web Attack – XSS": [{"id": "T1059.007", "name": "JavaScript", "tactic": "Execution"}],
    "Web Attack – Sql Injection": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "Heartbleed":      [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
}

# Rule trigger name → ATT&CK techniques
_RULE_MAP: Dict[str, List[Dict[str, str]]] = {
    "icmp_flood":       [{"id": "T1498.001", "name": "Direct Network Flood", "tactic": "Impact"}],
    "syn_scan":         [{"id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery"}],
    "large_payload":    [{"id": "T1030", "name": "Data Transfer Size Limits", "tactic": "Exfiltration"}],
    "asymmetric_upload": [{"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"}],
    "payload:sql_injection":    [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "payload:xss":              [{"id": "T1059.007", "name": "JavaScript", "tactic": "Execution"}],
    "payload:command_injection": [{"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}],
    "payload:path_traversal":   [{"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"}],
    "payload:log4j":            [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                                 {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"}],
    "payload:shellshock":       [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "malicious_ja3":            [{"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
                                 {"id": "T1573", "name": "Encrypted Channel", "tactic": "Command and Control"}],
}


def map_attack_type(attack_type: Optional[str]) -> List[Dict[str, str]]:
    """Map a supervised model label to ATT&CK techniques."""
    if not attack_type or attack_type == "BENIGN":
        return []
    # Try exact match first, then partial
    if attack_type in _ATTACK_TYPE_MAP:
        return _ATTACK_TYPE_MAP[attack_type]
    for key, techniques in _ATTACK_TYPE_MAP.items():
        if key.lower() in attack_type.lower() or attack_type.lower() in key.lower():
            return techniques
    return []


def map_rules(triggered_rules: Optional[List[str]]) -> List[Dict[str, str]]:
    """Map triggered rule names to ATT&CK techniques."""
    if not triggered_rules:
        return []
    seen = set()
    result = []
    for rule in triggered_rules:
        for technique in _RULE_MAP.get(rule, []):
            tid = technique["id"]
            if tid not in seen:
                seen.add(tid)
                result.append(technique)
    return result


def enrich(attack_type: Optional[str], triggered_rules: Optional[List[str]]) -> List[Dict[str, str]]:
    """Return deduplicated ATT&CK techniques from both attack type and rules."""
    seen = set()
    result = []
    for t in map_attack_type(attack_type) + map_rules(triggered_rules):
        if t["id"] not in seen:
            seen.add(t["id"])
            result.append(t)
    return result
