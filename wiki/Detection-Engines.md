# Detection Engines

CNDS runs four detection engines in parallel. Each engine receives different feature inputs and specialises in different attack categories.

## Engine Summary

| Engine | Input | Model | Detects |
|---|---|---|---|
| Supervised | 76 CICFlowMeter flow features (+ 10 payload features if retrained) | Random Forest (sklearn Pipeline) | Named attacks: DoS, PortScan, Brute-force, Web attacks, Infiltration |
| Isolation Forest | 18 per-IP host features | IsolationForest + StandardScaler | Novel / zero-day volumetric anomalies |
| LSTM Autoencoder | 18-feature time-series per IP | PyTorch sequence autoencoder | Slow attacks, temporal behaviour drift |
| Rules | Flow metadata + payload bytes + JA3 hashes | Threshold rules | ICMP floods, SYN scans, SQLi, XSS, LFI, large payloads, asymmetric upload, malicious TLS fingerprints |

## Engine Protocol

All ML engines implement the `DetectionEngine` protocol defined in `src/engines/protocol.py`:

```python
@runtime_checkable
class DetectionEngine(Protocol):
    @property
    def is_available(self) -> bool: ...
    def anomaly_score(self, *args, **kwargs) -> float: ...
```

- `is_available` — returns `True` when the model file is loaded and the engine is ready.
- `anomaly_score` — returns a normalised score in `[0, 1]` where higher means more anomalous.

The Rules engine has a different interface (`evaluate`) and is handled separately.

## Supervised Engine

- **File:** `src/engines/supervised.py`
- **Model:** `models/rf_model.joblib` — a scikit-learn Pipeline containing preprocessing + Random Forest classifier.
- **Input:** 76 CICFlowMeter-compatible flow features (optionally 86 if retrained with payload features via `scripts/retrain_with_payload.py`).
- **Output:** attack type label + confidence score.
- **Detects:** DoS (Hulk, Slowloris, SlowHTTPTest, GoldenEye), PortScan, FTP/SSH Brute-force, Web attacks (XSS, SQL Injection, Brute Force), Infiltration, Heartbleed, Bot.

## Isolation Forest

- **File:** `src/engines/isolation_forest.py`
- **Models:** `models/isolation_forest.joblib` + `models/if_scaler.joblib`
- **Input:** 18 per-IP host features (packet rate, byte rate, port entropy, protocol distribution, etc.).
- **Output:** novelty score (higher = more anomalous).
- **Detects:** Zero-day volumetric anomalies, unusual traffic patterns that don't match any known attack signature.

## LSTM Autoencoder

- **File:** `src/engines/lstm_autoencoder.py`
- **Models:** `models/lstm_autoencoder.pt` + `models/lstm_config.json`
- **Input:** Time-series of 18 host features per IP, buffered over a sliding window.
- **Output:** Reconstruction error as anomaly score.
- **Detects:** Slow/low attacks, gradual behaviour drift, C2 beaconing, and other temporal anomalies that single-snapshot engines miss.

## Rules Engine

- **File:** `src/engines/rules.py`
- **Input:** Flow metadata, raw payload bytes, JA3 hashes.
- **Output:** List of triggered rule names + a combined score.
- **Rules include:**
  - `icmp_flood` — ICMP packet count exceeds `ICMP_FLOOD_THRESHOLD`
  - `syn_scan` — SYN packet count exceeds `PORT_SCAN_THRESHOLD`
  - `large_payload` — forward payload exceeds `LARGE_PAYLOAD_BYTES`
  - `asymmetric_upload` — forward/backward byte ratio anomaly
  - `rate_spike` — packet rate exceeds `RATE_SPIKE_MULTIPLIER` × baseline
  - `sqli` — SQL injection patterns in payload
  - `xss` — cross-site scripting patterns in payload
  - `lfi` — local file inclusion patterns in payload
  - `malicious_ja3` — JA3 hash matches known-malicious list

## Graceful Degradation

CNDS works with any subset of engines. If a model file is missing, the engine reports `is_available = False` and its ensemble weight is redistributed proportionally across the active engines. This means you can run CNDS with just the rules engine (no ML models at all) and still get basic detection.
