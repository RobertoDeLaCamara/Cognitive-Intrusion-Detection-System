# Ensemble Scoring

**File:** `src/ensemble/scorer.py`

The ensemble scorer combines the outputs of the five engines (supervised, Isolation Forest, LSTM, rules, baseline) into a single `[0, 1]` confidence value using weighted fusion.

## Default Weights

| Engine | Weight |
|---|---|
| Supervised | 30% (`WEIGHT_SUPERVISED`) |
| Isolation Forest | 20% (`WEIGHT_IFOREST`) |
| LSTM Autoencoder | 10% (`WEIGHT_LSTM`) |
| Rules | 25% (`WEIGHT_RULES`) |
| Baseline | 15% (`WEIGHT_BASELINE`) |

The five weights must sum to 1.0 (±0.01) — this is validated on startup. Invalid weights cause a `ConfigurationError`. (`.env.example` ships a different, also valid, set — supervised 0.35, iforest 0.25, lstm 0.15, rules 0.05, baseline 0.20. `docker-compose.yml` loads `.env.example` before `.env`, so containers use those values unless `.env` overrides them; bare `main.py` / `uvicorn` runs use the code defaults above.)

## Weight Redistribution

When an engine is unavailable (model not loaded) or has no data for a given flow, its weight is redistributed proportionally across the active engines. For example, with the defaults and the LSTM and baseline engines missing:

- Supervised: 30 / 75 × 100 = 40%
- Isolation Forest: 20 / 75 × 100 ≈ 26.7%
- Rules: 25 / 75 × 100 ≈ 33.3%

## Per-Attack-Type Overrides

The `ATTACK_TYPE_WEIGHTS` config (JSON) lets you override weights for specific attack types. For example, you might want to trust the supervised engine more for DoS detection:

```json
{
  "DoS": {"supervised": 0.5, "isolation_forest": 0.2, "lstm": 0.05, "rules": 0.25}
}
```

Keys are the supervised label (exact match) and the engine names `supervised`, `isolation_forest`, `lstm`, `rules`, `baseline`. An override only replaces the listed engines; the result is renormalised over the active engines, so it does not have to sum to 1.0.

## Confidence Calibration

`CALIBRATION_TEMPERATURE` (default 1.0) applies Platt scaling to the final score:
- Temperature > 1.0 → softer scores (fewer high-confidence alerts)
- Temperature < 1.0 → sharper scores (more decisive)

## Alert Threshold

An alert fires when the calibrated ensemble score is at least `ENSEMBLE_THRESHOLD` (default 0.55), or when a rule listed in `CRITICAL_RULES` fired (those force the score to 1.0). Severity is derived from the score (`severity_from_score`):
- `critical` — score ≥ 0.85, or score ≥ 0.70 when the attack label contains `DDoS`, `DoS`, `Infiltration` or `Web Attack`
- `high` — score ≥ 0.70
- `medium` — score ≥ 0.55
- `low` — below 0.55 (not normally persisted)

## Threat-Intelligence Boost

If the flow's source/destination IP or its JA3 hash is in a threat-intel set, the combined score is increased by 0.30 (capped at 1.0) and `threat_intel_malicious_ip` / `threat_intel_malicious_ja3` is added to the triggered rules. Only the live-capture pipeline performs this lookup.

## Adaptive Weights

When `ADAPTIVE_WEIGHTS_ENABLED=true`, the system computes optimal engine weights from analyst feedback (true positive / false positive acknowledgements). Requires at least `ADAPTIVE_MIN_SAMPLES` (default 100) acknowledged alerts before adapting.

Query current adaptive weights: `GET /api/adaptive-weights` (informational: the result covers supervised / isolation_forest / lstm / rules and is not applied automatically).

## Confidence Decay

Repeat alerts from the same source IP have their score multiplied by `CONFIDENCE_DECAY_FACTOR ** n` (default 0.9), where `n` is the number of earlier hits inside `CONFIDENCE_DECAY_WINDOW` seconds (default 300). This reduces alert fatigue from persistent scanners without suppressing them entirely. Decay is applied on the `POST /api/predict` path only.

## Deduplication

Duplicate alerts from the same `(src_ip, attack_type)` pair are suppressed within `DEDUP_WINDOW_SECS` (default 300 seconds), by both the capture pipeline and `/api/predict`.
