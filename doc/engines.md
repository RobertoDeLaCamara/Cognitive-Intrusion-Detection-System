# CNDS — Detection Engines

## Engine Overview

CNDS uses five complementary detection engines (plus a threat-intelligence boost). Each engine observes a different signal, operates on a different feature representation, and detects a different category of threats. Their scores are fused by the ensemble scorer.

| Engine | Default Weight | Features | What it detects |
|---|---|---|---|
| Supervised (FT-Transformer or RF fallback) | 30% | 76 flow features | Named attack classes (10 types) |
| Isolation Forest | 20% | 18 host features | Volume/behavioral anomalies |
| LSTM Autoencoder | 10% | Temporal host sequences | Slow/drift behavioral changes |
| Rules Engine | 25% | All signals | High-confidence threshold and signature patterns |
| Baseline (unsupervised live pipeline) | 15% | 18 host features | Adaptive behavioral anomalies |

(Defaults from `src/config.py`. The shipped `.env.example` sets 40/10/0/20/30 (supervised/iforest/lstm/rules/baseline), and docker-compose loads it, so containers use those values unless `.env` overrides them.)

---

## 1. Supervised classifier (FT-Transformer preferred, Random Forest fallback)

The supervised slot has two interchangeable implementations. Both consume the
same 76 CICFlowMeter flow-feature vector and return `(label, confidence)` from
`predict()`. That is the only method the runtime calls: both the capture pipeline
(`_score_supervised()` in `src/pipeline.py`) and `POST /api/predict` set the
supervised score to `0.0` when the label is benign and to the confidence of the
predicted class otherwise. Each engine also has an `anomaly_score()` method
(`1 - P(Benign)`, zeroed below a threshold), but no runtime path calls it, so
`FT_SCORE_THRESHOLD` and `RF_SCORE_THRESHOLD` currently have no effect on alerts. The
registry picks **FT-Transformer when its checkpoint is present**, otherwise
falls back to the Random Forest pipeline.

### 1a. FT-Transformer (preferred)

**Files:** `src/engines/ft_transformer_engine.py`, `src/models/ft_transformer.py`

#### Purpose
Classify network flows into one of 10 attack categories using a tabular
Transformer trained jointly for ML-IDS and cnds. Provides higher per-class
F1 on minority attacks than the legacy RF and produces the named
`attack_type` label that appears on every alert.

#### Model
- **Algorithm:** FT-Transformer (Gorishniy et al., NeurIPS 2021) — per-feature affine tokenizer + 3 Pre-LN transformer encoder blocks + linear head. The shipped Optuna-tuned checkpoint uses `d_token=256`, 8 heads and has about 1.6M parameters.
- **Features:** 76 CICFlowMeter flow features (same order as `FlowExtractor`).
- **Training dataset:** UNSW-NB15 (CIC redistribution; ~447k labeled flows, 10 classes).
- **Test metric:** F1 macro **0.6197** (vs XGBoost baseline 0.6095, default FT-T 0.5446).
- **Class-weighting strategy:** `sqrt_inverse` — full inverse over-corrects on minorities, focal loss adds nothing over sqrt-weighted CE.
- **Score used by the ensemble:** confidence of the predicted class (softmax over logits divided by `FT_TEMPERATURE`, default `2.0`), or `0.0` when the class is `Benign`.
- **`anomaly_score()`:** `1 - P(Benign)`, zeroed below `FT_SCORE_THRESHOLD` (default `0.50`). Not called at runtime (see above).
- **Architecture diagrams:** see [`ML-IDS/docs/UNIFIED_MODEL_ARCHITECTURE.md`](https://github.com/RobertoDeLaCamara/ML-IDS/blob/main/docs/UNIFIED_MODEL_ARCHITECTURE.md).

#### Model load chain (priority order)

| Priority | Source | When available |
|---|---|---|
| 1 | MLflow registry | `MLFLOW_TRACKING_URI` is set; model `ml-ids-unified-ft-transformer/<MLFLOW_FT_STAGE>` exists |
| 2 | `models/unified/unified_ft_transformer.pt` + `unified_scaler.pkl` | Local checkpoint copied from ML-IDS |

If neither is available the engine self-disables and the registry falls
back to Random Forest below.

### 1b. Random Forest (fallback)

**File:** `src/engines/supervised.py`

### Purpose
Classify network flows into one of 9 known attack categories or `Benign`. This engine provides the highest precision for known attack types and produces the named `attack_type` label that appears on every alert.

### Model
- **Algorithm:** scikit-learn `Pipeline` (clip → log1p on skewed features → StandardScaler → RandomForestClassifier).
- **Features:** 76 CICFlowMeter flow features (see `FlowExtractor`).
- **Training dataset:** CIC-UNSW-NB15 — 447k labeled flows from the Canadian Institute for Cybersecurity / UNSW.
- **Score used by the ensemble:** confidence of the predicted class, or `0.0` when the class is `Benign`.
- **`anomaly_score()`:** `1 - P(Benign)`, zeroed below `RF_SCORE_THRESHOLD` (default `0.90`). Not called at runtime (see above).

### Model load chain (priority order)

| Priority | Source | When available |
|---|---|---|
| 1 | MLflow registry | `MLFLOW_TRACKING_URI` is set and model is registered |
| 2 | `models/rf_model.joblib` | Locally trained full model (gitignored, 124MB+) |
| 3 | `models/rf_lite_model.joblib` | **Bundled lite model — ships with the repo** |

The lite model (1.6MB, 91% accuracy on CIC-UNSW-NB15) provides functional detection out-of-the-box on a fresh `git clone`. The full model or MLflow version are used automatically when available.

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

# Train and register to MLflow
python scripts/train_rf.py --mlflow-uri http://your-mlflow-host:5050
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
- **Storage:** MLflow registry (`<MLFLOW_REGISTRY_NAME>-isolation_forest`, stage `Production`) when MLflow is configured, otherwise `models/isolation_forest.joblib`; the optional scaler is `models/if_scaler.joblib`. Neither file ships with the repo.
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
- **Entropy anomalies**: unusual average payload entropy for a host (`avg_payload_entropy`).

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
- Each tracked source IP maintains a FIFO buffer of its last `sequence_length` host feature vectors (20, read from `models/lstm_config.json`; there is no environment variable for it).
- The buffer gets one vector per completed flow of that source IP (not per packet).
- When the buffer is full, the full sequence is run through the autoencoder.
- When `MAX_TRACKED_IPS` (default 5000) buffers exist and a new IP arrives, the IP with the shortest buffer is evicted.

### Scoring
- Reconstruction error = Mean Squared Error (MSE) between input and reconstructed sequence.
- Normalized as `min(error / reconstruction_threshold, 1.0)`, with `reconstruction_threshold` read from `models/lstm_config.json` (0.1 if the key is missing).
- High reconstruction error → high anomaly score.

### What it catches
- **Slow scans**: Port scan over hours or days rather than seconds.
- **Low-and-slow exfiltration**: Gradual data transfer below rate-based thresholds.
- **Beaconing**: C2 check-ins at regular intervals (unusual IAT pattern).
- **Progressive brute force**: Authentication attempts spread over time.

### Cold-start behavior
The buffer must be full (20 completed flows from the same IP) before the LSTM produces a real score. Until then `anomaly_score()` returns `0.0`, and that zero enters the blend with the full LSTM weight: the weight is only redistributed when the engine itself is unavailable (no model loaded).

### Training requirements
- Needs normal-traffic host vectors; no labels.
- The repository has no standalone LSTM training script. `scripts/generate_demo_models.py` writes a demo `lstm_autoencoder.pt` and `lstm_config.json` from synthetic data, and the live baseline pipeline (`WindowTrainer`, see [unsupervised.md](unsupervised.md)) trains its own LSTM for the baseline engine.
- `models/lstm_config.json` ships with the repo; the weights file does not.

---

## 4. Rules Engine (Heuristic Detection)

**File:** `src/engines/rules.py`

### Purpose
Deterministic detection of well-understood attack patterns. Rules are evaluated once per completed flow and return a binary score: `1.0` when at least one rule fires, no probability estimation.

### Rules

#### Rule 1: ICMP Flood
```
protocol == ICMP AND forward packets in the flow > ICMP_FLOOD_THRESHOLD
```
- Detects ICMP ping floods.
- Threshold: `ICMP_FLOOD_THRESHOLD` (default: 50 packets).
- MITRE: T1498.001 (Direct Network Flood).

#### Rule 2: SYN Scan
```
flow_features[syn_flag_cnt] > PORT_SCAN_THRESHOLD
AND flow_features[fwd_act_data_pkts] < 5
```
- Detects TCP SYN-only port scans and SYN floods (nmap default mode).
- Few forward packets that carry data indicate the handshake never completes and no real data is exchanged. (Before #49 the condition was unreachable and the rule never fired.)
- Threshold: `PORT_SCAN_THRESHOLD` (default: 20 SYNs).
- `syn_scan` is in the default `CRITICAL_RULES` (#50), so a hit forces an alert regardless of the weighted blend.
- MITRE: T1046 (Network Service Scanning).

#### Rule 3: Large Payload
```
max(forward packet lengths in the flow) > LARGE_PAYLOAD_BYTES
```
- Detects unusually large payload packets potentially carrying exploits or exfiltration.
- Threshold: `LARGE_PAYLOAD_BYTES` (default: 10000 bytes).
- MITRE: T1030 (Data Transfer Size Limits).

#### Rule 4: Payload Signatures
```
for each pattern name returned by the payload analyzer: add "payload:<name>"
```
- Fires when any of the 6 payload patterns (SQLi, XSS, CMDi, traversal, Log4J, Shellshock) matches.
- Each matching pattern adds a separate triggered rule entry to the alert.
- Payloads that look encrypted or compressed are skipped (#68): a TLS record header at the start of the payload, or a sample of at least 256 bytes with Shannon entropy of 7.0 bits/byte or more (`looks_encrypted()` in `src/features/payload_analyzer.py`). Plaintext attacks sit well below that entropy, while chance regex matches inside bulk TLS or backup transfers used to surface as `CRITICAL_RULES` alerts.
- MITRE (`src/enrichment/mitre.py`): T1190 for `sql_injection`, `log4j` (plus T1203) and `shellshock`; T1059.007 for `xss`; T1059 for `command_injection`; T1083 for `path_traversal`.

#### Rule 5: Asymmetric Upload
```
forward packets > 10 AND backward packets > 0
AND sum(forward lengths) / sum(backward lengths) > 50
```
- Detects large upload-to-download ratios characteristic of data exfiltration.
- Flows with no backward packets are ignored.
- MITRE: T1041 (Exfiltration Over C2 Channel).

#### Rule 6: Malicious JA3
```
ja3_hash in malicious_ja3_set
```
- Fires when the TLS ClientHello fingerprint matches a known-malicious hash.
- Hash list loaded from `MALICIOUS_JA3_FILE` by `main.py` at startup (empty by default, so the rule cannot fire until a file is configured). Hashes fetched from `MALICIOUS_JA3_URL` belong to the threat-intel store instead and produce the separate `threat_intel_malicious_ja3` entry.
- MITRE: T1071 (Application Layer Protocol) and T1573 (Encrypted Channel).

### Scoring
- Rules return `1.0` when any rule fires, `0.0` otherwise.
- `triggered_rules` list contains the names of all fired rules.
- Multiple rules can fire for the same flow.
- Default `CRITICAL_RULES` (each forces an alert on its own): the six `payload:*` rules (`sql_injection`, `command_injection`, `log4j`, `shellshock`, `xss`, `path_traversal`), `malicious_ja3` and `syn_scan`.

---

## 5. Logwatch (log-based rules, outside the ensemble)

**Package:** `src/logwatch/`

### Purpose
Detects attacks on exposed services from their application logs, which the packet pipeline cannot see (sign-up floods, login brute force, admin access or token creation from unknown addresses). It is not one of the five scored engines: it has no weight, does not touch the ensemble and does not appear in `GET /api/engines`.

### Components

| File | Role |
|---|---|
| `gitea.py` | Parses Gitea HTTP access-log lines into `LogEvent`s (`parse_line`); other lines return `None` |
| `rules.py` | Loads and validates declarative YAML rules (`load_rules`, `RuleError`). A rule has `service`, `match` (`method`, `path` regex, `status`), `group_by` (`ip` or `user`), `threshold`, `window_secs`, `cooldown_secs`, `severity`, optional `untrusted_only` and `mitre` |
| `engine.py` | `LogRuleEngine.feed(event)` keeps a sliding window per (rule, key) and returns a `LogAlert` when the count reaches the threshold. Time comes from the events, not the wall clock. After firing, a (rule, key) stays silent for `cooldown_secs`. Memory is bounded (`MAX_WINDOW_EVENTS` 10,000 per key, `MAX_KEYS_PER_RULE` 50,000) |
| `rules/gitea.yaml` | Shipped rule set: sign-up flood/attempts/success, login brute force/failures, admin panel from an untrusted address, token/SSH key/webhook creation, scanning |
| `persist.py` | `persist_alert()` stores a `LogAlert` as an `Alert` with `source="logwatch"`, `engine_scores={"logwatch": <score>}` (severity mapped to 0.30/0.60/0.80/1.00), evidence in `payload_matches`, GeoIP and MITRE data, then calls `notify_alert()` (best effort) |
| `replay.py` | CLI to run log files through the rules without touching the database |

### Behaviour
- `untrusted_only` rules ignore sources inside the trusted networks given to `LogRuleEngine(trusted=...)`.
- The Guardian only acts on `GUARDIAN_ALERT_SOURCES` (default `detector`), so logwatch alerts never block anything.
- Replay example, to tune thresholds against real logs:

```bash
zcat gitea.log.*.gz | python -m src.logwatch.replay --service gitea --tz Europe/Madrid \
    --trusted 192.168.0.0/16,172.16.0.0/12 -
```

- Nothing in `main.py`, `src/pipeline.py` or the API starts a live log watcher, and no `LOGWATCH_*` environment variable is read. The `LOGWATCH_TRUSTED_CIDRS` name in the `rules/gitea.yaml` header comment is not implemented in this repository.

---

## Ensemble Scoring

**File:** `src/ensemble/scorer.py`

### Weight Configuration

Default weights in `src/config.py` (sum to 1.0):
```
WEIGHT_SUPERVISED = 0.30
WEIGHT_IFOREST    = 0.20
WEIGHT_LSTM       = 0.10
WEIGHT_RULES      = 0.25
WEIGHT_BASELINE   = 0.15
```

Override per attack type with `ATTACK_TYPE_WEIGHTS` JSON. The key must equal the label the supervised engine returns (for the shipped models: `DoS`, `Exploits`, `Reconnaissance`, ...), and the given engines replace the base weights while the others keep theirs:
```json
{
  "DoS":            {"supervised": 0.60, "rules": 0.20},
  "Reconnaissance": {"rules": 0.50}
}
```
The override weights are not validated to sum to 1.0; they are renormalised over the engines that produced a score.

### Dynamic Weight Redistribution
When an engine is unavailable (model missing), its weight is distributed proportionally to the remaining engines:

```
Example: LSTM unavailable (weight 0.10); an engine counts as unavailable when its score is `None`, not when it scores `0.0`
Before: supervised=0.30, iforest=0.20, lstm=0.10, rules=0.25, baseline=0.15
After:  supervised≈0.33, iforest≈0.22, lstm=0.00, rules≈0.28, baseline≈0.17
        (each remaining engine scales by 1/(1-0.10))
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

Tune `CALIBRATION_TEMPERATURE` after observing score distributions on your network. Calibration is applied after the threat-intel boost (+0.30) and the `CRITICAL_RULES` override (score forced to 1.0); scores of exactly 0 or 1 are left unchanged.

---

## Engine Availability and Graceful Degradation

```python
# From src/engines/registry.py
_ft_engine = FTTransformerEngine()
supervised = _ft_engine if _ft_engine.is_available else SupervisedEngine()
iforest    = IsolationForestEngine()   # is_available = False if no model
lstm       = LSTMAutoencoderEngine()   # is_available = False if no model
baseline   = BaselineEngine()          # is_available = False until a window is trained
rules      = RulesEngine()             # no model files, always on
```

The rules engine is always available and provides a minimum detection floor. In a fresh clone the bundled lite Random Forest also loads, so the supervised slot is active too. With no models at all, the system still detects ICMP floods, SYN scans, large payloads, payload injection patterns, asymmetric uploads, and known malicious JA3 hashes.

---

## Adding an Engine

`src/engines/registry.py` is the single place engines are instantiated; `GET /api/engines` and `/health` read from it. A new ML engine takes these steps:

1. **Implement the protocol** (`src/engines/protocol.py`): an `is_available` property and `anomaly_score(...) -> Optional[float]` returning a normalised `[0, 1]` score. Load models in `__init__` and degrade to `is_available = False` when files are missing.

   ```python
   class MyEngine:
       def __init__(self):
           self._model = None  # load here; leave None if the file is absent

       @property
       def is_available(self) -> bool:
           return self._model is not None

       def anomaly_score(self, host_features=None):
           if not self.is_available or host_features is None:
               return 0.0
           return float(self._model.score(host_features))
   ```

2. **Instantiate it in `registry.py`**, add an `assert isinstance(my_engine, DetectionEngine)` next to the others and an entry in `ENGINES`.
3. **Give it an ensemble slot**: add a field to `EngineScores` and a `WEIGHT_*` entry in `src/config.py` and `EnsembleScorer._BASE_WEIGHTS` (all weights must sum to 1.0 ± 0.01), and handle the field in `EnsembleScorer.score()`.
4. **Call it** from `on_flow_complete()` in `src/pipeline.py` (and `routers/predict.py` for the API path) and fill the field.
5. **Smoke test**: `tests/test_engines.py` shows the pattern: with the model file missing `is_available` is false and `anomaly_score` returns 0.0 without raising; with a model it stays inside `[0, 1]`.

Steps 3 and 4 are explicit wiring, not automatic discovery: the scorer still has one named field per engine.

---

## Engine Performance Characteristics

| Engine | Latency | Memory | CPU | False Positive Risk |
|---|---|---|---|---|
| FT-Transformer (primary) | ~3–8 ms | ~30 MB (model) | Medium (inference_mode, CPU) | Low (labeled training, 10 classes) |
| Random Forest (fallback) | ~1 ms | ~200 MB (full model; the bundled lite model is 1.6 MB on disk) | Medium (inference) | Low (labeled training) |
| Isolation Forest | ~0.1 ms | ~50 MB (model) | Low | Medium (topology changes) |
| LSTM Autoencoder | ~5 ms | ~100 MB (model) | High (GPU optional) | Low (sequence context) |
| Rules Engine | ~0.01 ms | Negligible | Very Low | Very Low (threshold-based) |

These figures are rough orders of magnitude, not measurements from this repository; no benchmark for them is checked in. Engines run once per completed flow.

---

## Model Retraining

### Random Forest
```bash
# Standard 76-feature model (see "Training" above for --lite and --mlflow-uri)
python scripts/train_rf.py --data-dir /path/to/CIC-UNSW-NB15

# Extended 86-feature model (adds 10 payload features)
python scripts/retrain_with_payload.py \
    --dataset data/labeled_flows.csv \
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

With `MODEL_INTEGRITY_MODE` enforcing a manifest, a hand-made model file also needs an entry (see `scripts/model_manifest.py`).

```bash
# Demo models from synthetic data (RF, Isolation Forest + scaler, LSTM), for trying the stack only
python scripts/generate_demo_models.py --output-dir models
```

### LSTM Autoencoder
There is no standalone training script (see section 3). The config file `models/lstm_config.json` must match the architecture of the weights; the shipped file is:
```json
{
  "sequence_length": 20,
  "hidden_dim": 64,
  "latent_dim": 32,
  "num_layers": 2,
  "dropout": 0.2,
  "n_features": 18,
  "reconstruction_threshold": 2.9730082154273987
}
```

### MLflow Integration
When `MLFLOW_TRACKING_URI` is set, models can be loaded from the registry:
`src/mlflow_registry.py` has no command-line interface: models are registered by the code that trains them (`scripts/train_rf.py --mlflow-uri ...` for the Random Forest, `WindowTrainer` for the baseline models, the ML-IDS sweep for the FT-Transformer).

The `src/mlflow_registry.py` module provides a unified interface for loading from registry or local path.
