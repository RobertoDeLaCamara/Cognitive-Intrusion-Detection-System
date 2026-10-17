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
├── 192.168.1.60   NAS         — NAS (SMB, NFS, HTTP)
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
| Git push/pull | CLIENT | GITEA :80 | TCP |
| Docker pull | CLIENT | REGISTRY :5000 | TCP/HTTPS |
| NAS file access | CLIENT | NAS :445 | SMB/TCP |
| DNS lookups | CLIENT | ROUTER :53 | UDP |
| ICMP ping | CLIENT | ROUTER | ICMP |

Packet sizes, inter-arrival times, and flow durations are randomized within realistic ranges to create varied but recognizable "normal" traffic.

#### Attack Scenarios

The scenarios are defined in `SCENARIOS` in `demo/generate_traffic.py`. All attacks come from the simulated external host `10.0.0.1`.

| Scenario | What it models | Target | Expected rule(s) |
|---|---|---|---|
| `normal_traffic` | Baseline day-to-day activity (expect 0 alerts) | — | — |
| `icmp_flood` | ICMP flood | NAS | `icmp_flood` |
| `nas_sqli` | SQL injection against the DSM login (:5000) | NAS | `payload:sql_injection` |
| `nas_credential_stuffing` | Repeated SQLi-style login attempts (:5000) | NAS | `payload:sql_injection` |
| `gitea_web_attack` | XSS + path traversal (:80) | GITEA | `payload:xss`, `payload:path_traversal` |
| `command_injection` | Command injection via the webhook API | GITEA | `payload:command_injection` |
| `shellshock` | Shellshock in the HTTP User-Agent (:5000) | NAS | `payload:shellshock` |
| `exfiltration` | Large upload NAS → external | external host | `large_payload`, `asymmetric_upload` |
| `log4shell` | Log4Shell probe | GITEA | `payload:log4j` |

### PCAP structure

One PCAP per scenario, written to `demo/traffic/` (gitignored):
```
demo/traffic/
├── normal_traffic.pcap
├── icmp_flood.pcap
├── nas_sqli.pcap
├── nas_credential_stuffing.pcap
├── gitea_web_attack.pcap
├── command_injection.pcap
├── shellshock.pcap
├── exfiltration.pcap
└── log4shell.pcap
```

### Generating PCAPs manually

```bash
python demo/generate_traffic.py
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
python demo/run_demo.py                          # generate PCAPs, then replay all scenarios
python demo/run_demo.py --no-generate            # reuse existing PCAPs
python demo/run_demo.py --scenario nas_sqli      # one scenario
```

No root access required. No network interface binding. No database needed (results printed to stdout).

**Example output** (abridged; a real run on a checkout with the bundled models, without `torch`, ANSI colours stripped; scores and which scenarios fire depend on the models present):

```
Detection engines:
  ✓  rules engine
  ✓  supervised (RF)
  ✓  isolation forest
  ✗  lstm autoencoder       (requires models/lstm_autoencoder.pt)

  nas_sqli
  SQL injection on NAS DSM login :5000 (rule: sql_injection)

    ALERT  src=10.0.0.1  dst=192.168.1.60  score=1.00  CRITICAL  rules=['payload:sql_injection']  mitre=['T1190']
  → 1 alert(s) in 0.01s

  DEMO COMPLETE   12 alert(s) across 9 scenario(s)

  Scenario                      Alerts  Result
  normal_traffic                     0  ✓ No false positives
  icmp_flood                         0  ✗ Missed (ML models needed?)
  nas_sqli                           1  ✓ Detected
  nas_credential_stuffing            6  ✓ Detected
  gitea_web_attack                   2  ✓ Detected
  command_injection                  1  ✓ Detected
  shellshock                         1  ✓ Detected
  exfiltration                       0  ✗ Missed (ML models needed?)
  log4shell                          1  ✓ Detected
```

The payload-signature scenarios fire because their rules are in `CRITICAL_RULES`. `icmp_flood` and `exfiltration` trigger only non-critical rules, whose 25 % rule weight is diluted by the other engines, so they stay below `ENSEMBLE_THRESHOLD` in this setup.

### Demo behavior without ML models

If a model file is absent, `run_demo.py` lists the engine as unavailable in its header and the ensemble redistributes the remaining weights. The rules engine always runs, and the `CRITICAL_RULES` signature scenarios (`nas_sqli`, `nas_credential_stuffing`, `gitea_web_attack`, `command_injection`, `shellshock`, `log4shell`) are still detected without any ML model. The `icmp_flood` and `exfiltration` scenarios depend on the blended score and are not guaranteed to alert.

---

## PCAP Replay Script (`scripts/pcap_replay.py`)

For more controlled evaluation, the replay script processes arbitrary PCAP files:

```bash
python scripts/pcap_replay.py demo/traffic/nas_sqli.pcap [more.pcap ...] \
    --output results.json \
    [--labels labels.csv] [--threshold 0.5]
```

**Output format** (`results.json`):
```json
{
  "files": {
    "demo/traffic/nas_sqli.pcap": {
      "metrics": {"total_flows": 1, "tp": 0, "fp": 0, "tn": 0, "fn": 0, "precision": 0.0, "recall": 0.0, "f1": 0.0, "accuracy": 0.0},
      "predictions": [
        {"flow_key": "10.0.0.1-192.168.1.60-55000-5000-6", "src_ip": "10.0.0.1", "dst_ip": "192.168.1.60",
         "ensemble_score": 1.0, "is_anomaly": true, "attack_type": "BENIGN",
         "active_engines": ["supervised", "isolation_forest", "rules"],
         "triggered_rules": ["payload:sql_injection"]}
      ]
    }
  },
  "aggregate": {"total_flows": 1, "tp": 0, "fp": 0, "tn": 0, "fn": 0, "precision": 0.0, "recall": 0.0, "f1": 0.0, "accuracy": 0.0},
  "engines": {"supervised": true, "isolation_forest": true, "lstm": false, "rules": true}
}
```

Confusion-matrix metrics are non-zero only when `--labels` is supplied.

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
NEW_IOT  = "192.168.1.101"  # Add your device
```

Then add traffic generation logic for the device in `make_normal_traffic()` using Scapy packet constructors.

### Adding a new attack scenario

1. Add a function to `demo/generate_traffic.py` that returns a list of Scapy packets:
```python
def make_dns_amplification():
    """DNS amplification attack traffic."""
    return [IP(src=ATTACKER, dst=ROUTER) / UDP(dport=53) / Raw(b"\x00" * 512) for _ in range(1000)]
```

2. Register it in `SCENARIOS` in the same file (name, function, description); `generate_all()` writes `demo/traffic/<name>.pcap` and `run_demo.py` picks it up:
```python
SCENARIOS = [
    ("normal_traffic", make_normal_traffic, "Baseline — normal NAS/Gitea/router activity"),
    ...
    ("dns_amplification", make_dns_amplification, "DNS amplification DoS"),  # new
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

```bash
# run_demo.py always exits 0 and has no regression option, so gate on the
# PCAP replay output instead.
python scripts/pcap_replay.py demo/traffic/nas_sqli.pcap --output ci_results.json
python - <<'PYEOF'
import json
d = json.load(open("ci_results.json"))
preds = [p for f in d["files"].values() for p in f["predictions"]]
assert any(p["is_anomaly"] for p in preds), "nas_sqli no longer detected"
PYEOF
```
