# CNDS — Digital Twin & Sandbox

## Overview

The CNDS digital twin is a local simulation environment that replicates the device topology and traffic patterns of a real home/lab network. It enables:

- **Offline evaluation** — test detection coverage without live network traffic or root access.
- **Demo operation** — showcase detection capabilities to stakeholders without deployment risk.
- **Engine validation** — verify model behavior against known attack scenarios before going live.
- **Regression testing** — run after model retraining to confirm detection rates haven't degraded.

The sandbox consists of two components:
1. **`demo/generate_traffic.py`** — Synthetic PCAP generator for the simulated network.
2. **`demo/run_demo.py`** — Demo orchestrator that replays PCAPs and displays results.

---

## Simulated Network Topology

The digital twin models a typical home/small-office network:

```
192.168.1.0/24
│
├── 192.168.1.1    ROUTER      — Default gateway
├── 192.168.1.60   NAS         — Synology NAS (SMB, NFS, HTTP)
├── 192.168.1.62   GITEA       — Self-hosted Git server (HTTP/HTTPS)
├── 192.168.1.86   REGISTRY    — Private Docker registry (HTTPS :5000)
└── 192.168.1.100  CLIENT      — Developer workstation
```

These IPs are representative of a real lab environment and match the `TRUSTED_OUTBOUND` device profiles in `.env.example`. Each device has realistic traffic patterns modeled in the generator.

---

## PCAP Generator (`demo/generate_traffic.py`)

### What it generates

The generator creates Scapy packet sequences that accurately model network behavior for each scenario. Packets are written as binary PCAP files to `demo/traffic/`.

#### Normal Traffic (Baseline)

Models day-to-day device activity:

| Traffic Type | Source | Destination | Protocol |
|---|---|---|---|
| HTTP/HTTPS web browsing | CLIENT | External IPs | TCP 80/443 |
| Git push/pull | CLIENT | GITEA :3000 | TCP |
| Docker pull | CLIENT | REGISTRY :5000 | TCP/HTTPS |
| NAS file access | CLIENT | NAS :445 | SMB/TCP |
| DNS lookups | CLIENT | ROUTER :53 | UDP |
| ICMP ping | CLIENT | ROUTER | ICMP |

Packet sizes, inter-arrival times, and flow durations are randomized within realistic ranges to create varied but recognizable "normal" traffic.

#### Attack Scenarios

| Scenario | Attack Type | Source | Target |
|---|---|---|---|
| `icmp_flood` | ICMP Flood | External `10.0.0.1` | ROUTER |
| `syn_scan` | TCP SYN Scan | External `10.0.0.2` | CLIENT (all ports) |
| `port_scan` | Full Port Scan | External `10.0.0.3` | All local IPs |
| `brute_force` | SSH Brute Force | External `10.0.0.4` | CLIENT :22 |
| `large_payload_exfil` | Data Exfiltration | CLIENT | External :8080 |
| `web_attacks` | SQLi + XSS | External `10.0.0.5` | GITEA :3000 |

### PCAP structure

Each scenario produces one or more PCAP files:
```
demo/traffic/
├── normal_traffic.pcap
├── icmp_flood.pcap
├── syn_scan.pcap
├── port_scan.pcap
├── brute_force.pcap
├── large_payload_exfil.pcap
└── web_attacks.pcap
```

### Generating PCAPs manually

```bash
cd demo
python generate_traffic.py
# → Creates demo/traffic/*.pcap
```

PCAPs can be inspected with Wireshark, analyzed with CICFlowMeter, or fed into any other network analysis tool.

---

## Demo Orchestrator (`demo/run_demo.py`)

### What it does

1. Generates PCAPs (calls `generate_traffic.py` if `demo/traffic/` is empty).
2. Initializes CNDS engines (loads models if available, gracefully degrades if not).
3. Replays each PCAP through the full CNDS detection pipeline (feature extraction → engines → ensemble → enrichment).
4. Prints a color-coded alert summary to terminal.
5. Outputs a final summary report: detection rates, false positive rates, MITRE coverage.

### Running the demo

```bash
cd demo
python run_demo.py
```

No root access required. No network interface binding. No database needed (results printed to stdout).

**Example output:**

```
=== CNDS Local Network Digital Twin Demo ===
Generating synthetic traffic...
  ✓ normal_traffic.pcap       (450 packets)
  ✓ icmp_flood.pcap           (2,100 packets)
  ✓ syn_scan.pcap             (1,800 packets)
  ✓ brute_force.pcap          (340 packets)
  ✓ large_payload_exfil.pcap  (85 packets)
  ✓ web_attacks.pcap          (120 packets)

Replaying traffic through detection pipeline...

--- Scenario: ICMP Flood ---
[CRITICAL] DoS attack from 10.0.0.1 → 192.168.1.1
  Engines: supervised=0.88 | iforest=0.91 | lstm=N/A | rules=1.00
  Ensemble: 0.91 | MITRE: T1498

--- Scenario: SYN Scan ---
[HIGH] PortScan from 10.0.0.2 → 192.168.1.100
  Engines: supervised=0.84 | iforest=0.87 | lstm=0.71 | rules=1.00
  Ensemble: 0.85 | MITRE: T1046

--- Scenario: Brute Force ---
[MEDIUM] SSH-Patator from 10.0.0.4 → 192.168.1.100:22
  Engines: supervised=0.79 | iforest=0.65 | lstm=0.72 | rules=0.00
  Ensemble: 0.69 | MITRE: T1110

--- Scenario: Data Exfiltration ---
[HIGH] Anomaly from 192.168.1.100 → 10.0.0.99:8080
  Engines: supervised=0.21 | iforest=0.73 | lstm=0.84 | rules=0.00
  Ensemble: 0.61 | MITRE: T1048

--- Scenario: Web Attacks ---
[HIGH] Web Attack – SQL Injection from 10.0.0.5 → 192.168.1.62:3000
  Engines: supervised=0.83 | iforest=0.54 | lstm=0.45 | rules=1.00
  Ensemble: 0.76 | MITRE: T1190
[MEDIUM] Web Attack – XSS from 10.0.0.5 → 192.168.1.62:3000
  Engines: supervised=0.71 | iforest=0.49 | lstm=0.42 | rules=1.00
  Ensemble: 0.68 | MITRE: T1059.007

=== DEMO SUMMARY ===
Scenarios tested:  6
Detections fired:  6 / 6  (100%)
False positives:   0 (from normal_traffic.pcap)
MITRE techniques:  T1498, T1046, T1110, T1048, T1190, T1059.007
Engines available: supervised ✓ | iforest ✓ | lstm ✓ | rules ✓
```

### Demo behavior without ML models

If `rf_model.joblib`, `isolation_forest.joblib`, or `lstm_autoencoder.pt` are absent, the demo degrades gracefully:

- Missing engines show `N/A` in engine scores.
- Available weights are redistributed to the remaining engines.
- The rules engine always runs (no model files required).
- ICMP flood, SYN scan, large payload, web injection attacks are still detected via rules.
- A warning is printed: `[WARNING] LSTM unavailable — weight redistributed`.

This makes the demo fully functional for demonstrating rule-based detection even in a fresh checkout.

---

## PCAP Replay Script (`scripts/pcap_replay.py`)

For more controlled evaluation, the replay script processes arbitrary PCAP files:

```bash
python scripts/pcap_replay.py \
    --pcap /path/to/capture.pcap \
    --output results.json \
    --interface-override eth0   # treat packets as if captured on this interface
```

**Output format:**
```json
{
  "pcap": "capture.pcap",
  "total_packets": 8523,
  "alerts": [
    {
      "timestamp": "...",
      "src_ip": "192.168.1.100",
      "attack_type": "PortScan",
      "severity": "high",
      "ensemble_score": 0.83,
      "engine_scores": {...},
      "mitre_techniques": [...]
    }
  ],
  "summary": {
    "alert_count": 12,
    "by_severity": {"low": 3, "medium": 5, "high": 3, "critical": 1},
    "processing_time_ms": 842
  }
}
```

This is the primary tool for **offline PCAP evaluation** against real-world capture files, penetration test captures, or CTF challenge traffic.

---

## Sandbox Considerations

### What is isolated

The demo and replay scripts operate entirely in-memory without:
- Binding to any network interface (no packet capture).
- Writing to a database (results printed or written to file).
- Making outbound connections (no SIEM push, no webhook calls).
- Requiring root or `CAP_NET_RAW` privileges.

This makes the sandbox safe to run in any environment — developer laptops, CI/CD pipelines, air-gapped systems.

### What is NOT a full sandbox

The digital twin simulates traffic patterns but does not:
- Replicate actual device fingerprinting responses (TTL, TCP window sizes, OS stack behavior).
- Model encrypted traffic content (TLS payloads are synthetic).
- Represent malware variants or evasion techniques — it models the statistical signature of known attacks.

For adversarial testing (red team evaluation), provide real PCAP captures via `pcap_replay.py` rather than relying on the synthetic generator.

---

## Extending the Digital Twin

### Adding a new device

In `demo/generate_traffic.py`, add a new IP to the device constants:

```python
# ── Device IPs ────────────────────────────────────────────────────────────────
ROUTER   = "192.168.1.1"
NAS      = "192.168.1.60"
GITEA    = "192.168.1.62"
REGISTRY = "192.168.1.86"
CLIENT   = "192.168.1.100"
NEW_IOT  = "192.168.1.120"  # Add your device
```

Then add traffic generation logic for the device in the `generate_normal_traffic()` function using Scapy packet constructors.

### Adding a new attack scenario

1. Add a new function to `generate_traffic.py`:
```python
def generate_dns_amplification():
    """Generate DNS amplification attack traffic."""
    pkts = []
    for i in range(1000):
        # UDP DNS query spoofed to victim IP
        pkt = IP(src="10.0.0.1", dst=ROUTER) / UDP(dport=53) / Raw(b"\x00" * 512)
        pkts.append(pkt)
    wrpcap("demo/traffic/dns_amplification.pcap", pkts)
```

2. Add the scenario to `run_demo.py`'s scenario list:
```python
SCENARIOS = [
    ("normal_traffic", "Baseline — no attacks"),
    ("icmp_flood", "ICMP Flood DoS"),
    ...
    ("dns_amplification", "DNS Amplification DoS"),  # new
]
```

3. Run the demo to validate detection coverage for the new scenario.

### Using real PCAP as baseline

Replace `generate_normal_traffic()` with a real capture:

```bash
# Capture 5 minutes of normal traffic
sudo tcpdump -i eth0 -w demo/traffic/normal_traffic.pcap -G 300 -W 1

# Run demo with real baseline
python run_demo.py
```

The demo will report false positives from real traffic that the synthetic generator doesn't model (streaming video, cloud sync, background OS traffic).

---

## Integration with CI/CD

The demo and replay scripts can be incorporated into a CI/CD pipeline to gate model deployment:

```yaml
# .github/workflows/model-validation.yml (example)
- name: Run detection regression tests
  run: |
    python demo/run_demo.py --output ci_results.json --exit-code-on-regression
    # fails if any previously-detected attack is no longer detected
```

The `--exit-code-on-regression` flag (if implemented) returns a non-zero exit code when detection rates fall below the baseline, blocking deployment of a degraded model.
