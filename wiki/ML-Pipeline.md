# ML Pipeline

## Overview

Up to five independent detection engines run on every expired flow and produce scores that are fused by a weighted ensemble (weights are the `src/config.py` defaults; see [Ensemble Scoring](Ensemble-Scoring.md)).

| Engine | Algorithm | Input | Weight | Output |
|--------|-----------|-------|--------|--------|
| Supervised | FT-Transformer (preferred) — Random Forest fallback | 76 flow features (+ 10 payload opt. for RF) | 30% | attack_type, confidence [0,1] |
| Isolation Forest | Unsupervised ensemble | 18 host features | 20% | anomaly_score [0,1] |
| LSTM Autoencoder | Temporal reconstruction | 18 host features × seq_len | 10% | reconstruction_error [0,1] |
| Rules | Heuristic thresholds + payload signatures | raw packet stats, payload, JA3 | 25% | binary score + triggered_rules |
| Baseline | IsolationForest + LSTM trained on live traffic | 18 host features | 15% | anomaly_score [0,1] (needs a trained window in MLflow) |

---

## Feature Sets

### 76 Flow Features (CICFlowMeter-compatible)

Extracted by `src/features/flow_extractor.py` from bidirectional 5-tuple flows.

| Category | Count | Examples |
|----------|-------|---------|
| Flow statistics | 5 | Duration, total fwd/bwd packets, total fwd/bwd bytes |
| Packet length | 13 | Fwd/bwd pkt length max, min, mean, std; overall pkt length min, max, mean, std, var |
| IAT (inter-arrival time) | 14 | Flow IAT mean/std/max/min; fwd and bwd IAT total/mean/std/max/min |
| Flags | 12 | Fwd/bwd PSH and URG flags; FIN, SYN, RST, PSH, ACK, URG, CWR, ECE counts |
| Speed/rate | 4 | Flow bytes/s, flow pkts/s, fwd/bwd pkts/s |
| Header length | 2 | Fwd/bwd header lengths |
| Subflow | 4 | Fwd/bwd subflow packets, fwd/bwd subflow bytes |
| Window | 2 | Init fwd/bwd win bytes |
| Bulk | 6 | Fwd/bwd bytes/bulk, packets/bulk, bulk rate |
| Segment / ratio | 6 | Pkt size avg, fwd/bwd seg size avg, fwd seg size min, fwd act data pkts, down/up ratio |
| Activity timing | 8 | Active/idle mean, std, max, min |

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

Extracted by `src/features/payload_analyzer.py`. Per-flow numeric features from up to `MAX_PAYLOAD_SAMPLES` samples of `PAYLOAD_SAMPLE_BYTES` (4096) bytes each.

| # | Feature |
|---|---------|
| 0–5 | Binary flags: `has_sqli`, `has_xss`, `has_cmdi`, `has_traversal`, `has_log4j`, `has_shellshock` |
| 6 | `pattern_match_count` |
| 7 | `max_payload_entropy` |
| 8 | `mean_payload_length` |
| 9 | `suspicious_char_ratio` |

### JA3 TLS Fingerprint

`src/features/ja3.py`: binary parse of TLS ClientHello (version, cipher suites, extensions, elliptic curves, point formats). GREASE values (RFC 8701 `0x?A?A` pattern) filtered before MD5 hash. Malicious hash list loaded from `MALICIOUS_JA3_FILE` on startup.

---

## Engine Details

### Supervised classifier — FT-Transformer (preferred)

- Files: `src/engines/ft_transformer_engine.py`, `src/models/ft_transformer.py`
- Model: PyTorch FT-Transformer (Gorishniy et al., NeurIPS 2021), Optuna-tuned
- Architecture: per-feature affine tokenizer → 3 Pre-LN encoder blocks → linear head; ~2.4M params
- Best config (from the ML-IDS Optuna sweep; not verifiable here: the checkpoint is gitignored, and the tracked `models/unified/unified_metadata.json` records `d_token=128` with test F1 macro 0.5446, i.e. the untuned default): `d_token=256, n_blocks=3, n_heads=8, ff_factor=2.0, dropout=0.0985, class_weight='sqrt_inverse'`
- Features: 76 CICFlowMeter flow features
- 10 output classes (UNSW-NB15): Benign, Analysis, Backdoor, DoS, Exploits, Fuzzers, Generic, Reconnaissance, Shellcode, Worms
- Test F1 macro: 0.6197 (XGBoost baseline 0.6095, default FT-T 0.5446)
- Model file: `models/unified/unified_ft_transformer.pt` + `unified_scaler.pkl` (gitignored)
- MLflow registry: `models:/ml-ids-unified-ft-transformer/<latest>`
- Architecture diagrams: see [`ML-IDS/docs/UNIFIED_MODEL_ARCHITECTURE.md`](https://github.com/RobertoDeLaCamara/ML-IDS/blob/main/docs/UNIFIED_MODEL_ARCHITECTURE.md)

### Random Forest (Supervised — fallback)

- File: `src/engines/supervised.py`
- Model: scikit-learn `RandomForestClassifier` trained on the CIC redistribution of UNSW-NB15
- Features: 76 flow features; optionally extended to 86 with payload features (via `scripts/retrain_with_payload.py`)
- Output classes: same 10 UNSW-NB15 labels as the FT-Transformer
- Model file: `models/rf_model.joblib` (gitignored) or bundled `models/rf_lite_model.joblib` (1.6 MB, committed)
- Selected automatically when no FT-Transformer checkpoint is present

### Isolation Forest (Unsupervised)

- File: `src/engines/isolation_forest.py`
- Model: scikit-learn `IsolationForest` + `StandardScaler`
- Detects volumetric/host-level anomalies without labels
- Score mapping: `1 / (1 + exp(5 * decision_function))` → [0,1] (negative decision values = anomalous)
- Model file: `models/isolation_forest.joblib` + `models/if_scaler.joblib`

### LSTM Autoencoder (Temporal)

- File: `src/engines/lstm_autoencoder.py`
- Framework: PyTorch (CPU by default)
- Architecture: 2-layer LSTM encoder → latent (32) → 2-layer LSTM decoder, hidden size 64, dropout 0.2 (from `models/lstm_config.json`)
- Input: per-IP sequence buffer (deque, maxlen = `sequence_length` from `lstm_config.json`, 20)
- Score: reconstruction MSE divided by the stored `reconstruction_threshold`, capped at 1.0; 0.0 until the buffer is full
- Eviction: when `MAX_TRACKED_IPS` reached, IP with shortest buffer evicted
- Model file: `models/lstm_autoencoder.pt` + `models/lstm_config.json`

### Rule-Based Engine

- File: `src/engines/rules.py`
- Heuristic thresholds (all configurable via env vars):

| Rule | Condition | Default Threshold |
|------|-----------|-------------------|
| `icmp_flood` | Forward ICMP packets in the flow | > 50 (`ICMP_FLOOD_THRESHOLD`) |
| `syn_scan` | SYN flag count (with < 5 forward packets) | > 20 (`PORT_SCAN_THRESHOLD`) |
| `large_payload` | Largest forward packet (bytes) | > 10 000 (`LARGE_PAYLOAD_BYTES`) |
| `asymmetric_upload` | Fwd/bwd byte ratio (> 10 forward packets) | > 50 (fixed) |
| `payload:*` | 6 regex signatures (SQLi, XSS, command injection, path traversal, Log4j, Shellshock) | — |
| `malicious_ja3` | JA3 hash in the known-bad list | — |

---

## Ensemble Scoring

File: `src/ensemble/scorer.py`

### Default Weights

| Engine | Weight | Env Variable |
|--------|--------|-------------|
| Supervised | 0.30 | `WEIGHT_SUPERVISED` |
| Isolation Forest | 0.20 | `WEIGHT_IFOREST` |
| LSTM | 0.10 | `WEIGHT_LSTM` |
| Rules | 0.25 | `WEIGHT_RULES` |
| Baseline | 0.15 | `WEIGHT_BASELINE` |

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
logit = log(score / (1 - score))          # score in (0, 1); 0 and 1 are returned unchanged
calibrated = sigmoid(logit / CALIBRATION_TEMPERATURE)
```

`CALIBRATION_TEMPERATURE` default 1.0 (no-op). Increase to soften scores, decrease to sharpen.

### Severity Thresholds

| Severity | Score Range |
|----------|------------|
| CRITICAL | ≥ 0.85 (≥ 0.70 for DoS / DDoS / Infiltration / Web Attack labels) |
| HIGH | ≥ 0.70 |
| MEDIUM | ≥ 0.55 (alert threshold) |
| (below threshold) | < 0.55 — discarded |

A rule in `CRITICAL_RULES` forces the score to 1.0 (critical). Threat-intel hits add +0.30 before calibration.

---

## Training Workflow

### 1a. Supervised (FT-Transformer — preferred)

The FT-Transformer is trained in the **ML-IDS** repo, not here, because it
shares a single artifact across both projects:

```bash
# In ML-IDS:
python notebooks/ft_transformer_optuna_sweep.py     # 25-trial sweep + retrain
# Outputs: ML-IDS/models/unified/unified_ft_transformer.pt + unified_scaler.pkl
# Registered in MLflow as ml-ids-unified-ft-transformer/1
```

To consume it from cnds:

```bash
mkdir -p models/unified
cp /path/to/ML-IDS/models/unified/unified_ft_transformer.pt  models/unified/
cp /path/to/ML-IDS/models/unified/unified_scaler.pkl         models/unified/
cp /path/to/ML-IDS/models/unified/unified_metadata.json      models/unified/
```

Or rely on MLflow auto-load by setting `MLFLOW_TRACKING_URI` and the S3
credentials. Validate end-to-end with:

```bash
python scripts/smoke_test_ft_unified.py --device cpu       # F1 macro on test split
pytest tests/test_ft_transformer_engine.py -v              # 7 tests; skipped without torch and the checkpoint
```

### 1b. Supervised (Random Forest — fallback)

```bash
# Train on the CIC redistribution of UNSW-NB15
# Dataset must be in data/CIC-UNSW-NB15/
python scripts/train_rf.py --data-dir /path/to/CIC-UNSW-NB15

# Optional: include payload features (86 features)
python scripts/retrain_with_payload.py
```

Output: `models/rf_model.joblib`

### 2–3. Isolation Forest + LSTM Autoencoder

There is no standalone training script. Both models are trained **automatically**
by the unsupervised baseline subsystem (`src/unsupervised/`): while the detector
runs, `BaselineCollector` buffers host feature vectors and, once the composite
trigger fires, `WindowTrainer` fits a new IsolationForest + LSTM Autoencoder and
logs them to MLflow. Enabled by default (`BASELINE_COLLECTION_ENABLED=true`).
See [Unsupervised Baseline Training](https://github.com/RobertoDeLaCamara/Cognitive-Intrusion-Detection-System/blob/master/doc/unsupervised.md).

```bash
# Let the detector observe normal traffic; training kicks in on its own
sudo python main.py
```

For a quick local start without a baseline, generate small synthetic demo models
(not for production):

```bash
python scripts/generate_demo_models.py --output-dir models
```

Output: `models/isolation_forest.joblib`, `models/if_scaler.joblib`, `models/lstm_autoencoder.pt`

### Offline Replay (for model evaluation)

```bash
python scripts/pcap_replay.py captures/attack.pcap
```

Replays a `.pcap` file through the full detection pipeline without live capture.

---

## Attack → MITRE ATT&CK Mapping

14 attack labels + 11 rule triggers are mapped to ATT&CK techniques (deduplicated by technique ID). The full tables are in [MITRE ATT&CK Mapping](MITRE-ATT&CK-Mapping.md); a sample:

| Attack / Rule | Technique ID | Name | Tactic |
|--------------|-------------|------|--------|
| DoS Hulk / GoldenEye / DDoS | T1498 | Network Denial of Service | Impact |
| DoS Slowhttptest / slowloris | T1498.001 | Direct Network Flood | Impact |
| PortScan | T1046 | Network Service Scanning | Discovery |
| SSH-Patator / FTP-Patator | T1110.001 | Password Guessing | Credential Access |
| Web Attack – Sql Injection / Heartbleed | T1190 | Exploit Public-Facing Application | Initial Access |
| Web Attack – XSS | T1059.007 | JavaScript | Execution |
| Infiltration | T1041, T1071 | Exfiltration Over C2 Channel, Application Layer Protocol | Exfiltration, C2 |
| Bot | T1071 | Application Layer Protocol | Command and Control |
| `syn_scan` rule | T1046 | Network Service Scanning | Discovery |
| `malicious_ja3` rule | T1071, T1573 | Application Layer Protocol, Encrypted Channel | Command and Control |
| `payload:sql_injection` rule | T1190 | Exploit Public-Facing Application | Initial Access |
| `payload:command_injection` rule | T1059 | Command and Scripting Interpreter | Execution |

The labels are CIC-IDS2017 style. The UNSW-NB15 classes emitted by the FT-Transformer / RF (`Exploits`, `Fuzzers`, `Reconnaissance`, `Generic`, `Worms`, `Backdoor`, `Shellcode`, `Analysis`) have no entry; `DoS` maps to T1498 through a partial match.
