# CNDS — Detection Engines

## Engine Overview

CNDS uses four complementary detection engines. Each engine observes a different signal, operates on a different feature representation, and detects a different category of threats. Their scores are fused by the ensemble scorer.

| Engine | Weight | Features | What it detects |
|---|---|---|---|
| Random Forest | 40% | 76 flow features | Named attack classes (10 types) |
| Isolation Forest | 30% | 18 host features | Volume/behavioral anomalies |
| LSTM Autoencoder | 20% | Temporal host sequences | Slow/drift behavioral changes |
| Rules Engine | 10% | All signals | High-confidence threshold patterns |

---

## 1. Random Forest (Supervised Classification)

**File:** `src/engines/supervised.py`

### Purpose
Classify network flows into one of 9 known attack categories or `Benign`. This engine provides the highest precision for known attack types and produces the named `attack_type` label that appears on every alert.

### Model
- **Algorithm:** scikit-learn `Pipeline` (clip → log1p on skewed features → StandardScaler → RandomForestClassifier).
- **Features:** 76 CICFlowMeter flow features (see `FlowExtractor`).
- **Training dataset:** CIC-UNSW-NB15 — 447k labeled flows from the Canadian Institute for Cybersecurity / UNSW.
- **Anomaly score:** `1 - P(Benign)` — calibrated against the actual benign probability.
- **FP threshold:** scores below `RF_SCORE_THRESHOLD` (default `0.90`) are zeroed to suppress low-confidence predictions.

### Model load chain (priority order)

| Priority | Source | When available |
|---|---|---|
| 1 | ML Tracking registry | `ML Tracking_TRACKING_URI` is set and model is registered |
| 2 | `models/rf_model.joblib` | Locally trained full model (gitignored, 124MB+) |
| 3 | `models/rf_lite_model.joblib` | **Bundled lite model — ships with the repo** |

The lite model (1.6MB, 91% accuracy on CIC-UNSW-NB15) provides functional detection out-of-the-box on a fresh `git clone`. The full model or ML Tracking version are used automatically when available.

### Attack Classes

| Label | Attack Category |
|---|---|
| Benign | Normal traffic |
| DoS | Denial of Service |
| Exploits | Exploit attempts |
| Fuzzers | Fuzzing / scanning |
| Generic | Generic attack patterns |
| Reconnaissance | Network reconnaissance |
| Analysis | Deep packet analysis attacks |
| Backdoor | Backdoor / RAT activity |
| Shellcode | Shellcode injection |
| Worms | Self-propagating worms |

### Training

```bash
# Generate bundled lite model (50k sample, ~1.6MB, ships with repo)
python scripts/train_rf.py --lite

# Train full production model (447k samples, ~124MB, gitignored)
python scripts/train_rf.py

# Train and register to ML Tracking
python scripts/train_rf.py --ML Tracking-uri http://[MAIN_NODE_IP]:5050
```

### Extending
To retrain on a custom dataset, provide a `Data.csv` (76 CICFlowMeter features) and `Label.csv` (integer class index) and pass `--data-dir /path/to/dataset` to `train_rf.py`. Update `RF_MODEL_FILE` in `.env` to point to the new model.

---

## 2. Isolation Forest (Unsupervised Anomaly)

**File:** `src/engines/isolation_forest.py`

### Purpose
Detect behavioral anomalies in host-level traffic patterns without requiring labeled data. This engine catches zero-day attacks, novel variants, and any behavior that deviates significantly from the host's baseline — even if the attack type is unknown.

### Model
- **Algorithm:** scikit-learn `IsolationForest`.
- **Features:** 18 per-IP host features (see `HostExtractor`).
- **Storage:** `models/isolation_forest.joblib` + `models/if_scaler.joblib`.
- **Training:** Fit on normal traffic captures (baseline period).

### Score Normalization
The raw IF output is `decision_function()`, which returns negative values for anomalies and near-zero values for inliers. CNDS maps this to [0, 1] using a sigmoid transformation:

```
anomaly_score = 1 / (1 + exp(-5 × (-decision_function(x))))
```

- Steepness factor of 5 creates a sharp transition around the decision boundary.
- Anomalies score close to 1.0; normal traffic scores close to 0.0.

### What it catches
- **Volumetric attacks**: Packet rate, byte rate, and burst rate spikes are among the 18 features.
- **Protocol anomalies**: Unusual TCP/UDP/ICMP ratios.
- **Port diversity**: Scanning behavior (many unique destination ports).
- **Entropy anomalies**: High-entropy payloads characteristic of encrypted exfiltration.

### Limitations
- Requires a representative normal-traffic baseline for training.
- High sensitivity to network topology changes (new servers, large file transfers) — these generate false positives until baseline is updated.
- Does not produce named attack types; `attack_type` from this engine is always `None`.

---

## 3. LSTM Autoencoder (Temporal Behavioral Analysis)

**File:** `src/engines/lstm_autoencoder.py`

### Purpose
Detect attacks that unfold slowly over time — behaviors that look normal in any single-packet snapshot but form an anomalous pattern when viewed as a sequence. The LSTM learns the "normal trajectory" of host behavior and alerts when reconstruction error spikes.

### Architecture
- **Framework:** PyTorch.
- **Architecture:** Sequence-to-sequence LSTM encoder/decoder.
  - Encoder: LSTM layers compress input sequence to latent representation.
  - Decoder: LSTM reconstructs the original sequence from latent space.
- **Input:** Sequence of 18 host feature vectors (default window: 20 steps per IP).
- **Storage:** `models/lstm_autoencoder.pt` (weights) + `models/lstm_config.json` (architecture params).

### Per-IP Sequence Buffers
- Each tracked source IP maintains a FIFO buffer of its last `LSTM_SEQ_LEN` (default: 20) host feature vectors.
- On each new packet, the buffer is updated.
- When the buffer is full, the full sequence is run through the autoencoder.
- LRU eviction removes the oldest IP when `MAX_TRACKED_IPS` is reached.

### Scoring
- Reconstruction error = Mean Squared Error (MSE) between input and reconstructed sequence.
- Normalized to [0, 1] using the empirical max error observed during training.
- High reconstruction error → high anomaly score.

### What it catches
- **Slow scans**: Port scan over hours or days rather than seconds.
- **Low-and-slow exfiltration**: Gradual data transfer below rate-based thresholds.
- **Beaconing**: C2 check-ins at regular intervals (unusual IAT pattern).
- **Progressive brute force**: Authentication attempts spread over time.

### Cold-start behavior
The buffer must be full (20 packets from the same IP) before the LSTM produces a score. New IPs contribute no LSTM signal until their sequence is populated. The weight for LSTM is redistributed to other engines for that IP during this period.

### Training requirements
- Requires labeled or unlabeled normal-traffic captures.
- Training script produces `lstm_autoencoder.pt` and `lstm_config.json`.
- Minimum recommended training data: 2+ hours of representative traffic.

---

## 4. Rules Engine (Heuristic Detection)

**File:** `src/engines/rules.py`

### Purpose
High-precision, zero-latency detection of well-understood attack patterns. Rules fire immediately with 100% confidence when thresholds are exceeded — no probability estimation needed.

### Rules

#### Rule 1: ICMP Flood
```
host_features[icmp_ratio] × packet_count > ICMP_FLOOD_THRESHOLD
```
- Detects ICMP ping floods and Smurf amplification.
- Threshold: `ICMP_FLOOD_THRESHOLD` (default: 100 packets/second).
- MITRE: T1498 (Network Denial of Service).

#### Rule 2: SYN Scan
```
flow_features[syn_flag_count] > PORT_SCAN_THRESHOLD
AND flow_features[tot_fwd_pkts] < 3
```
- Detects TCP SYN-only port scans (nmap default mode).
- Low forward packet count indicates connections are never completed.
- Threshold: `PORT_SCAN_THRESHOLD` (default: 50 SYNs).
- MITRE: T1046 (Network Service Scanning).

#### Rule 3: Large Payload
```
flow_features[max_fwd_len] > LARGE_PAYLOAD_BYTES
```
- Detects unusually large payload packets potentially carrying exploits or exfiltration.
- Threshold: `LARGE_PAYLOAD_BYTES` (default: 65000 bytes).
- MITRE: T1030 (Data Transfer Size Limits violation).

#### Rule 4: Payload Signatures
```
any(payload_features[0:6]) == 1
```
- Fires when any of the 6 payload patterns (SQLi, XSS, CMDi, traversal, Log4J, Shellshock) matches.
- Each matching pattern adds a separate triggered rule entry to the alert.
- MITRE: T1190 (Exploit Public-Facing Application), T1059.007 (XSS).

#### Rule 5: Asymmetric Upload
```
flow_features[fwd_bytes] / flow_features[bwd_bytes] > 50
```
- Detects large upload-to-download ratios characteristic of data exfiltration.
- Ignores flows with zero backward bytes to avoid division errors.
- MITRE: T1048 (Exfiltration Over Alternative Protocol).

#### Rule 6: Malicious JA3
```
ja3_hash in malicious_ja3_set
```
- Fires when the TLS ClientHello fingerprint matches a known-malicious hash.
- Hash list loaded from `MALICIOUS_JA3_FILE` at startup.
- MITRE: T1071.001 (Application Layer Protocol: Web Protocols).

### Scoring
- Rules return `1.0` when any rule fires, `0.0` otherwise.
- `triggered_rules` list contains the names of all fired rules.
- Multiple rules can fire simultaneously from the same packet/flow.

---

## Ensemble Scoring

**File:** `src/ensemble/scorer.py`

### Weight Configuration

Default weights (sum to 1.0):
```
WEIGHT_SUPERVISED = 0.40
WEIGHT_IFOREST    = 0.30
WEIGHT_LSTM       = 0.20
WEIGHT_RULES      = 0.10
```

Override per attack type with `ATTACK_TYPE_WEIGHTS` JSON:
```json
{
  "PortScan": {"rules": 0.40, "supervised": 0.40, "iforest": 0.20, "lstm": 0.00},
  "Bot":      {"lstm": 0.50, "supervised": 0.30, "iforest": 0.20, "rules": 0.00}
}
```

### Dynamic Weight Redistribution
When an engine is unavailable (model missing), its weight is distributed proportionally to the remaining engines:

```
Example: LSTM unavailable (weight 0.20)
Before: supervised=0.40, iforest=0.30, lstm=0.20, rules=0.10
After:  supervised=0.50, iforest=0.375, lstm=0.00, rules=0.125
        (each remaining engine scales by 1/(1-0.20))
```

### Confidence Calibration
Temperature scaling adjusts the sharpness of the probability distribution:

```python
logit = log(score / (1 - score))
calibrated = sigmoid(logit / temperature)
```

- `temperature = 1.0`: No change (default).
- `temperature > 1.0`: Softens scores toward 0.5 (more conservative).
- `temperature < 1.0`: Sharpens scores toward 0 or 1 (more aggressive).

Tune `CALIBRATION_TEMPERATURE` after observing score distributions on your network.

---

## Engine Availability and Graceful Degradation

```python
# From src/engines/registry.py
supervised = SupervisedEngine()    # is_available = False if .joblib missing
iforest    = IsolationForest()     # is_available = False if .joblib missing
lstm       = LSTMAutoencoder()     # is_available = False if .pt missing
rules      = RulesEngine()         # always is_available = True (no model files)
```

The rules engine is always available and provides a minimum detection floor. In a fresh deployment with no trained models, the system still detects ICMP floods, SYN scans, large payloads, payload injection patterns, asymmetric uploads, and known malicious JA3 hashes.

---

## Engine Performance Characteristics

| Engine | Latency | Memory | CPU | False Positive Risk |
|---|---|---|---|---|
| Random Forest | ~1 ms | ~200 MB (model) | Medium (inference) | Low (labeled training) |
| Isolation Forest | ~0.1 ms | ~50 MB (model) | Low | Medium (topology changes) |
| LSTM Autoencoder | ~5 ms | ~100 MB (model) | High (GPU optional) | Low (sequence context) |
| Rules Engine | ~0.01 ms | Negligible | Very Low | Very Low (threshold-based) |

Total pipeline latency (all 4 engines): typically 5–15 ms per packet batch on modern hardware.

---

## Model Retraining

### Random Forest
```bash
# Standard 76-feature model
python -m sklearn ...  # use your labeled dataset

# Extended 86-feature model (adds 10 payload features)
python scripts/retrain_with_payload.py \
    --data data/labeled_flows.csv \
    --output models/rf_model_v2.joblib
```

### Isolation Forest
```bash
# Capture baseline traffic first, then:
python -c "
from sklearn.ensemble import IsolationForest
from joblib import dump
import numpy as np

# X = your 18-feature baseline array
model = IsolationForest(n_estimators=100, contamination=0.01)
model.fit(X)
dump(model, 'models/isolation_forest.joblib')
"
```

### LSTM Autoencoder
Training code is expected in the `scripts/` or `models/` directory. The config file `models/lstm_config.json` must match the architecture used for inference:
```json
{
  "input_size": 18,
  "hidden_size": 64,
  "num_layers": 2,
  "seq_len": 20
}
```

### ML Tracking Integration
When `ML Tracking_TRACKING_URI` is set, models can be loaded from the registry:
```bash
# Register a new model version
python src/ML Tracking_registry.py --register models/rf_model_v2.joblib --name cnds-rf
```

The `src/ML Tracking_registry.py` module provides a unified interface for loading from registry or local path.
