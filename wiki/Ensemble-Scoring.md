# Ensemble Scoring

**File:** `src/ensemble/scorer.py`

The ensemble scorer combines outputs from all four engines into a single `[0, 1]` confidence value using weighted fusion.

## Default Weights

| Engine | Weight |
|---|---|
| Supervised | 40% |
| Isolation Forest | 30% |
| LSTM Autoencoder | 20% |
| Rules | 10% |

Weights must sum to 1.0 — this is validated on startup. Invalid weights cause a `ConfigurationError`.

## Weight Redistribution

When an engine is unavailable (model not loaded) or has no data for a given flow, its weight is redistributed proportionally across the active engines. For example, if the LSTM engine is missing:

- Supervised: 40 / 80 × 100 = 50%
- Isolation Forest: 30 / 80 × 100 = 37.5%
- Rules: 10 / 80 × 100 = 12.5%

## Per-Attack-Type Overrides

The `ATTACK_TYPE_WEIGHTS` config (JSON) lets you override weights for specific attack types. For example, you might want to trust the supervised engine more for DoS detection:

```json
{
  "DoS Hulk": {"supervised": 0.6, "iforest": 0.2, "lstm": 0.1, "rules": 0.1}
}
```

## Confidence Calibration

`CALIBRATION_TEMPERATURE` (default 1.0) applies Platt scaling to the final score:
- Temperature > 1.0 → softer scores (fewer high-confidence alerts)
- Temperature < 1.0 → sharper scores (more decisive)

## Alert Threshold

An alert fires when the ensemble score exceeds `ENSEMBLE_THRESHOLD` (default 0.55). Severity is derived from the score:
- `critical` — score ≥ 0.9
- `high` — score ≥ 0.7
- `medium` — score ≥ 0.55
- `low` — below threshold (not typically alerted)

## Adaptive Weights

When `ADAPTIVE_WEIGHTS_ENABLED=true`, the system computes optimal engine weights from analyst feedback (true positive / false positive acknowledgements). Requires at least `ADAPTIVE_MIN_SAMPLES` (default 100) acknowledged alerts before adapting.

Query current adaptive weights: `GET /api/adaptive-weights`

## Confidence Decay

Repeat alerts from the same source IP have their score multiplied by `CONFIDENCE_DECAY_FACTOR` (default 0.9) for each repeat within `CONFIDENCE_DECAY_WINDOW` seconds (default 300). This reduces alert fatigue from persistent scanners without suppressing them entirely.

## Deduplication

Duplicate alerts from the same `(src_ip, attack_type)` pair are suppressed within `DEDUP_WINDOW_SECS` (default 300 seconds).
