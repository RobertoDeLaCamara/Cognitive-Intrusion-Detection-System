# ML Pipeline

## Overview

Four independent detection engines run on every expired flow and produce scores that are fused by a weighted ensemble.

| Engine | Algorithm | Input | Weight | Output |
|--------|-----------|-------|--------|--------|
| Supervised | Random Forest | 76 flow features (+ 10 payload opt.) | 40% | attack_type, confidence [0,1] |
| Isolation Forest | Unsupervised ensemble | 18 host features | 30% | anomaly_score [0,1] |
| LSTM Autoencoder | Temporal reconstruction | 18 host features × seq_len | 20% | reconstruction_error [0,1] |
| Rules | Heuristic thresholds | raw packet stats, payload, JA3 | 10% | binary score + triggered_rules |

---

## Feature Sets

### 76 Flow Features (CICFlowMeter-compatible)

Extracted by `src/features/flow_extractor.py` from bidirectional 5-tuple flows.

| Category | Count | Examples |
|----------|-------|---------|
| Flow statistics | 10 | Duration, total fwd/bwd packets, total fwd/bwd bytes |
| Packet length | 12 | Fwd/bwd pkt length max, min, mean, std |
| IAT (inter-arrival time) | 8 | Flow IAT mean/std/max/min, Fwd IAT total/mean/std |
| TCP flags | 8 | FIN, SYN, RST, PSH, ACK, URG, CWR, ECE counts |
| Speed/rate | 6 | Flow bytes/s, flow pkts/s, fwd/bwd pkts/s |
| Subflow | 4 | Fwd/bwd subflow packets, fwd/bwd subflow bytes |
| Window/header | 6 | Init fwd/bwd win bytes, fwd/bwd header lengths |
| Activity timing | 8 | Active/idle mean, std, max, min |
| Other | 14 | Pkt length variance, size averages, bulk rates, down/up ratio |

### 18 Host Features (per-IP sliding window)

Extracted by `src/features/host_extractor.py`. Window: last 100 packets per IP.

| # | Feature | Category |
|---|---------|----------|
| 0 | packets/sec | Statistical |
| 1 | bytes/sec | Statistical |
| 2 | avg packet size | Statistical |
| 3 | packet size variance | Statistical |
| 4 | total packets | Statistical |
| 5 | total bytes | Statistical |
| 6 | IAT mean | Temporal |
| 7 | IAT std | Temporal |
| 8 | burst rate (last 5s) | Temporal |
| 9 | session duration | Temporal |
| 10 | TCP ratio | Protocol |
| 11 | UDP ratio | Protocol |
| 12 | ICMP ratio | Protocol |
| 13 | unique dst ports | Port |
| 14 | uncommon port ratio | Port |
| 15 | avg entropy (Shannon) | Payload |
| 16 | avg payload size | Payload |
| 17 | payload size variance | Payload |

### 10 Payload Features

Extracted by `src/features/payload_analyzer.py`. Per-flow numeric features from up to `MAX_PAYLOAD_SAMPLE_BYTES` (4096) bytes.

| # | Feature |
|---|---------|
| 0–5 | Binary flags: SQLi, XSS, cmd injection, shells, dir traversal, file inclusion |
| 6 | Total match count |
| 7 | Average payload entropy |
| 8 | Payload size average |
| 9 | Payload size variance |

### JA3 TLS Fingerprint

`src/features/ja3.py`: binary parse of TLS ClientHello (version, cipher suites, extensions, elliptic curves, point formats). GREASE values (RFC 8701 `0x?A?A` pattern) filtered before MD5 hash. Malicious hash list loaded from `MALICIOUS_JA3_FILE` on startup.

---

## Engine Details

### Random Forest (Supervised)

- File: `src/engines/supervised.py`
- Model: scikit-learn `RandomForestClassifier` trained on CIC-IDS2017
- Features: 76 flow features; optionally extended to 86 with payload features (via `scripts/retrain_with_payload.py`)
- 14 Output classes: BENIGN, DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest, DDoS, PortScan, FTP-Patator, SSH-Patator, Web Attack-Brute Force, Web Attack-XSS, Web Attack-SQL Injection, Infiltration, Bot, Heartbleed
- Model file: `models/rf_model.joblib` (gitignored)

### Isolation Forest (Unsupervised)

- File: `src/engines/isolation_forest.py`
- Model: scikit-learn `IsolationForest` + `StandardScaler`
- Detects volumetric/host-level anomalies without labels
- Score mapping: `sigmoid(decision_function)` → [0,1]
- Model file: `models/isolation_forest.joblib` + `models/if_scaler.joblib`

### LSTM Autoencoder (Temporal)

- File: `src/engines/lstm_autoencoder.py`
- Framework: PyTorch (CPU by default)
- Architecture: 2-layer LSTM encoder → latent → 2-layer LSTM decoder
- Input: per-IP sequence buffer (deque, maxlen = `LSTM_SEQUENCE_LENGTH` default 20)
- Score: reconstruction MSE normalized to [0,1]
- Eviction: when `MAX_TRACKED_IPS` reached, IP with shortest buffer evicted
- Model file: `models/lstm_autoencoder.pt` + `models/lstm_config.json`

### Rule-Based Engine

- File: `src/engines/rules.py`
- Heuristic thresholds (all configurable via env vars):

| Rule | Condition | Default Threshold |
|------|-----------|-------------------|
| ICMP flood | ICMP pkt count per window | 50 |
| SYN scan | SYN flag count | 20 |
| Large payload | Payload bytes | 10 000 |
| Asymmetric upload | Fwd/bwd byte ratio | configurable |
| Malicious JA3 | MD5 hash in blocklist | — |

---

## Ensemble Scoring

File: `src/ensemble/scorer.py`

### Default Weights

| Engine | Weight | Env Variable |
|--------|--------|-------------|
| Supervised | 0.40 | `WEIGHT_SUPERVISED` |
| Isolation Forest | 0.30 | `WEIGHT_IF` |
| LSTM | 0.20 | `WEIGHT_LSTM` |
| Rules | 0.10 | `WEIGHT_RULES` |

Weights must sum to 1.0 ± 0.01 (validated at import in `src/config.py`).

### Weight Redistribution

If an engine returns `None` (model unavailable or insufficient data), its weight is redistributed proportionally:

```
active_engines = {e: w for e, w in weights.items() if score[e] is not None}
total_active = sum(active_engines.values())
adjusted = {e: w / total_active for e, w in active_engines.items()}
```

### Temperature Scaling

Platt-style calibration applied to the combined score:

```python
logit = log(score / (1 - score + 1e-9))
calibrated = sigmoid(logit / CALIBRATION_TEMPERATURE)
```

`CALIBRATION_TEMPERATURE` default 1.0 (no-op). Increase to soften scores, decrease to sharpen.

### Severity Thresholds

| Severity | Score Range |
|----------|------------|
| CRITICAL | ≥ 0.85 |
| HIGH | ≥ 0.70 |
| MEDIUM | ≥ 0.55 (alert threshold) |
| (below threshold) | < 0.55 — discarded |

---

## Training Workflow

### 1. Supervised (Random Forest)

```bash
# Train on CIC-IDS2017 dataset
# Dataset must be in data/CIC-IDS2017/
python scripts/train_supervised.py

# Optional: include payload features (86 features)
python scripts/retrain_with_payload.py
```

Output: `models/rf_model.joblib`

### 2. Isolation Forest

```bash
# Collect baseline normal traffic (no attacks)
sudo python main.py --duration 600    # 10 min baseline capture

# Train IF on captured host features
python scripts/train_isolation_forest.py --input data/baseline_host.csv
```

Output: `models/isolation_forest.joblib`, `models/if_scaler.joblib`

### 3. LSTM Autoencoder

```bash
# Use same baseline data
python scripts/train_lstm.py --input data/baseline_host.csv
```

Output: `models/lstm_autoencoder.pt`, `models/lstm_config.json`

### Offline Replay (for model evaluation)

```bash
python scripts/pcap_replay.py --pcap captures/attack.pcap
```

Replays a `.pcap` file through the full detection pipeline without live capture.

---

## Attack → MITRE ATT&CK Mapping

14 attack types + 11 rule triggers mapped to ATT&CK techniques (deduplicated by technique ID).

| Attack / Rule | Technique ID | Name | Tactic |
|--------------|-------------|------|--------|
| DoS Hulk / DDoS | T1498 | Network DoS | Impact |
| PortScan | T1046 | Network Service Discovery | Discovery |
| SSH-Patator / FTP-Patator | T1110 | Brute Force | Credential Access |
| Web Attack-SQL Injection | T1190 | Exploit Public-Facing App | Initial Access |
| Web Attack-XSS | T1059.007 | JavaScript | Execution |
| Infiltration | T1071 | App Layer Protocol | C&C |
| Bot | T1059 | Command and Scripting Interpreter | Execution |
| Heartbleed | T1600 | Weaken Encryption | Defense Evasion |
| syn_scan rule | T1046 | Network Service Discovery | Discovery |
| malicious_ja3 rule | T1071 / T1573 | Encrypted Channel | C&C |
| SQLi pattern | T1190 | Exploit Public-Facing App | Initial Access |
| cmd_injection pattern | T1059 | Command and Scripting Interpreter | Execution |
