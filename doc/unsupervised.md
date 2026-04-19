# Unsupervised Baseline Training

Developer reference for the `src/unsupervised/` subsystem.

---

## Overview

The unsupervised baseline training subsystem collects live network feature vectors from the CNDS detection pipeline and autonomously retrains anomaly baseline models — no labeled traffic, no human trigger. It runs as a passive observer alongside the four detection engines: every flow that produces a host feature vector is silently handed to `BaselineCollector.observe()`.

When the **composite trigger** decides that enough diverse traffic has been seen, `BaselineCollector` snapshots the buffer and dispatches a daemon thread that fits a new **IsolationForest** and **LSTM Autoencoder** on the window. Artifacts are logged to MLflow under a canonical layout and registered in the model registry. The live pipeline keeps running uninterrupted throughout.

Key design constraints:
- The `observe()` call is on the **hot path** of every completed flow. It must be O(1) with no I/O and negligible locking overhead.
- Training happens entirely off the hot path in a single daemon thread per window.
- Only one training run can be in flight at a time. Samples that arrive while training is running are dropped and counted.

---

## Architecture

### Component Map

```
main.py
  └─ pipeline.init_baseline_collector()
        │
        ├─ CompositeTrigger          (triggers.py)
        ├─ WindowTrainer             (window_trainer.py)
        └─ BaselineCollector         (collector.py)
              │
              │  observe(record, host_vec)   ← called per flow by on_flow_complete()
              │
              ├─ [buffer accumulates samples]
              │
              ├─ trigger.should_fire(TriggerState)?  OR  n >= HARD_CAP?
              │         │ yes
              │         ▼
              │  snapshot buffer → reset live state
              │         │
              │  ProvenanceMetadata.from_window()   (provenance.py)
              │         │
              │  threading.Thread → _run_training()
              │         │
              │         ▼
              │  WindowTrainer.train_window(samples, provenance)
              │         │
              │         ├─ StandardScaler + IsolationForest   (sklearn)
              │         ├─ LSTM Autoencoder                    (PyTorch)
              │         ├─ threshold = percentile(val recon error)
              │         │
              │         └─ mlflow.start_run()
              │               ├─ log_metrics / log_params
              │               ├─ log_artifacts  (artifact_schema.py constants)
              │               └─ register_model("cnds-unsupervised-baseline")
              │
              └─ [_training_in_flight = False; log dropped count if > 0]
```

### Data Flow

1. **`on_flow_complete()`** (`src/pipeline.py`) is called for every expired flow. When a `host_vec` is available and the collector is initialised, it calls `_baseline_collector.observe(record, host_vec)`.
2. **`BaselineCollector.observe()`** extracts `src_ip`, `dst_ip`, `dst_port`, `protocol`, and `ts_epoch` from the flow record, then acquires the lock for the minimum time needed to append to the buffer and check trigger state.
3. If the trigger fires (or the hard cap is reached), the lock section atomically:
   - captures the buffer snapshot
   - resets `_buffer`, `_src_ips`, `_dst_port_counts`, and `_window_start_ts`
   - sets `_training_in_flight = True`
4. **`ProvenanceMetadata.from_window()`** builds the window statistics outside the lock.
5. A daemon thread runs **`WindowTrainer.train_window()`**, which fits both models and logs to MLflow. On completion (success or exception) the `finally` block clears `_training_in_flight` and logs the drop count.

---

## Key Classes

### `BaselineCollector`

**File:** `src/unsupervised/collector.py`

Thread-safe, O(1) hot-path accumulator. Holds the live buffer and all trigger state. Dispatches training to a background thread.

**Constructor parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `trigger` | `CompositeTrigger` | — | Trigger instance that decides when to fire |
| `on_window_ready` | `Callable[[List[CollectedSample], ProvenanceMetadata], None]` | — | Called in the background thread with the snapshotted window |
| `enabled` | `bool` | `True` | When `False`, `observe()` is a no-op |

**Class constant:**

| Name | Value | Description |
|---|---|---|
| `HARD_CAP` | `500_000` | Maximum vectors before the window fires unconditionally |

**Public method:**

`observe(record, host_vec: np.ndarray) -> None`

Called by the pipeline on every completed flow. Extracts fields from `record` using `getattr` with fallbacks so that attribute-access errors produce a silent return, never an exception that could disrupt the detection path. If `host_vec` is `None` or the collector is disabled, returns immediately.

**Internal state (behind `_lock`):**

| Attribute | Description |
|---|---|
| `_buffer` | `List[CollectedSample]` — live accumulation window |
| `_src_ips` | `set` — distinct source IPs seen in the current window |
| `_dst_port_counts` | `Counter` — destination port frequency distribution |
| `_window_start_ts` | `float` — epoch timestamp of the first sample or last window reset |
| `_training_in_flight` | `bool` — True while a training thread is running |
| `_dropped_while_training` | `int` — samples dropped since training started |

**`CollectedSample` dataclass fields:**

| Field | Type | Source |
|---|---|---|
| `host_vec` | `np.ndarray` (float32) | The 18-feature host vector |
| `src_ip` | `str` | `record.src_ip` |
| `dst_ip` | `str` | `record.dst_ip` |
| `dst_port` | `int` | `record.key[3]` or `record.dst_port` |
| `protocol` | `str` | `record.key[4]` or `record.protocol` |
| `ts_epoch` | `float` | `record.last_time` (if present and not None), then `record.end_ts`, then `time.time()` — sentinel pattern, `0.0` is a valid timestamp |

**`fire_reason` values:**

| Value | Meaning |
|---|---|
| `"composite_trigger"` | All four `CompositeTrigger` conditions were met |
| `"hard_cap"` | Buffer reached `HARD_CAP` (500,000) before composite trigger fired |

---

### `CompositeTrigger`

**File:** `src/unsupervised/triggers.py`

A pure dataclass with a single predicate method. All four conditions must hold simultaneously for `should_fire()` to return `True`. The trigger is stateless — it receives a `TriggerState` snapshot on each call and does not modify anything.

**Constructor parameters / fields:**

| Parameter | Default | Description |
|---|---|---|
| `min_total_vectors` | `50_000` | Minimum samples in the current window |
| `min_distinct_src_ips` | `20` | Minimum unique source IP addresses observed |
| `min_elapsed_sec` | `1800.0` | Minimum seconds since the window started (30 minutes) |
| `min_dst_port_entropy_bits` | `2.5` | Minimum Shannon entropy of the destination port distribution |

**`should_fire(state: TriggerState) -> bool`**

Returns `True` only when all four conditions are satisfied. Short-circuits on the first failing condition. Negative or zero `elapsed_sec` values satisfy the elapsed check only if `min_elapsed_sec` is also zero.

**`TriggerState` fields:**

| Field | Type | Populated by |
|---|---|---|
| `n_total` | `int` | `len(collector._buffer)` |
| `n_distinct_src_ips` | `int` | `len(collector._src_ips)` |
| `elapsed_sec` | `float` | `max(0.0, ts_epoch - _window_start_ts)` |
| `dst_port_counts` | `Counter` | `collector._dst_port_counts` |

The `max(0.0, ...)` guard on `elapsed_sec` prevents negative values from out-of-order packet timestamps reaching the trigger.

**Port entropy:** `_shannon_entropy_bits(counts)` computes H = -∑ p·log₂(p) over the destination port distribution. A value below 2.5 bits means traffic is dominated by very few ports (e.g., pure HTTP on port 80), which is not representative enough for a useful baseline.

---

### `WindowTrainer`

**File:** `src/unsupervised/window_trainer.py`

Fits both models on a collected window and persists artifacts to MLflow. Called exclusively from the background daemon thread spawned by `BaselineCollector`.

**Constructor parameters:**

| Parameter | Default | Description |
|---|---|---|
| `experiment_name` | `"cnds-unsupervised-baseline"` | MLflow experiment name |
| `val_fraction` | `0.20` | Fraction of vectors held out for validation |
| `threshold_percentile` | `99.0` | Percentile of validation reconstruction errors used as LSTM anomaly threshold |
| `iforest_contamination` | `0.01` | Expected anomaly fraction (passed to `IsolationForest`) |
| `seq_len` | `20` | LSTM sequence length (sliding window over the scaled training vectors) |

**MLflow initialisation:** `mlflow_registry.init()` is called once at construction time (not per-window). This is intentional — `init()` strips proxy environment variables process-wide, and calling it from a background thread on every window would race with other threads that use the proxy for outbound connections.

**Public methods:**

| Method | Returns | Description |
|---|---|---|
| `train_window(samples, provenance)` | `None` | Fit models on a collected window (see below) |
| `get_history()` | `list` | Thread-safe copy of the last ≤20 trained-window entries (most recent last) |
| `get_windows_trained_total()` | `int` | Monotone counter of successfully trained windows since process start |

The `get_windows_trained_total()` counter is used by the Prometheus scrape thread to expose the `cnds_baseline_windows_trained` gauge, which unlike `get_history()` does not saturate at 20.

**`train_window(samples, provenance) -> None`**

Training pipeline, step by step:

1. Rejects windows with fewer than 1,000 samples (logs a warning and returns).
2. Stacks `host_vec` arrays into a single float32 matrix `X`.
3. **Drops any rows containing NaN or Inf** (logs a WARNING with the count). If fewer than 1,000 finite rows remain, skips training. This prevents `StandardScaler.fit_transform()` from silently producing a poisoned scaler with `NaN` mean/scale.
4. Splits `X` into train (80 %) and validation (20 %) sets with a fixed random seed.
4. Fits `StandardScaler` on the training split; applies to both splits.
5. Fits `IsolationForest` (200 estimators, `n_jobs=-1`) on the scaled training split.
6. Constructs sliding-window sequences of length `seq_len` from the scaled splits using `_to_sequences()`. Skips training if either split produces zero sequences.
7. Trains `LSTMAutoencoder` for 20 epochs (batch size 256, Adam lr=1e-3, MSE loss) on the training sequences. Uses CUDA if available, otherwise CPU.
8. Computes per-sequence MSE on the validation sequences; sets `threshold` = 99th percentile.
9. Writes `n_sequences`, `n_train`, `n_val` back to the `ProvenanceMetadata` object.
10. If MLflow is not enabled, logs a warning and returns without persisting.
11. Otherwise, opens an MLflow run named `"baseline-window"`, logs metrics and params, writes all five artifact files to a temp directory, calls `mlflow.log_artifacts()` under `ARTIFACT_ROOT`. The run is then **closed** (status → FINISHED) before `mlflow.register_model()` is called. This ensures the artifact set is immutable before the registry entry is created, preventing `BaselineEngine` from loading an incomplete artifact set.

**LSTM training (fixed hyperparameters):**

| Hyperparameter | Value |
|---|---|
| Epochs | 20 |
| Batch size | 256 |
| Optimizer | Adam, lr=1e-3 |
| Loss | MSELoss |
| Architecture | `LSTMAutoencoder` from `src/engines/lstm_model.py` |

Progress is logged at INFO level every 5 epochs.

---

### `ProvenanceMetadata`

**File:** `src/unsupervised/provenance.py`

A dataclass that describes the statistical properties of a training window. Constructed by `BaselineCollector` just before dispatching the training thread; `n_sequences`, `n_train`, and `n_val` are filled in by `WindowTrainer` after the train/val split.

**Fields:**

| Field | Type | Description |
|---|---|---|
| `window_start_iso` | `str` | UTC ISO-8601 timestamp of the first sample in the window |
| `window_end_iso` | `str` | UTC ISO-8601 timestamp of the triggering sample |
| `fire_reason` | `str` | `"composite_trigger"` or `"hard_cap"` |
| `n_sequences` | `int` | Total LSTM sequences (train + val); filled by `WindowTrainer` |
| `n_train` | `int` | Training sequences; filled by `WindowTrainer` |
| `n_val` | `int` | Validation sequences; filled by `WindowTrainer` |
| `distinct_src_ips` | `int` | Count of unique source IP addresses in the window |
| `distinct_dst_ports` | `int` | Count of unique destination ports in the window |
| `top_dst_ports` | `list` | Top-20 destination ports as `[port, count]` pairs |
| `dst_port_entropy_bits` | `float` | Shannon entropy of the destination port distribution |
| `hour_of_day_histogram` | `dict` | Count of samples per UTC hour (keys are string hour digits) |
| `protocol_histogram` | `dict` | Count of samples per protocol string |

`to_dict()` returns a fully JSON-serializable dict via `dataclasses.asdict`.

---

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `BASELINE_COLLECTION_ENABLED` | `true` | Set to `false` to disable the collector entirely. `init_baseline_collector()` is still called but creates a disabled instance. |

All other knobs (`min_total_vectors`, `val_fraction`, etc.) are constructor arguments on `CompositeTrigger` and `WindowTrainer`. To change them, modify `pipeline.init_baseline_collector()` — the factory function in `src/pipeline.py` that wires the three objects together.

---

## Artifact Schema

All artifacts are logged under the `unsupervised_baseline/` prefix in the MLflow run.

| File | Constant | Format | Description |
|---|---|---|---|
| `scaler.joblib` | `SCALER_FILE` | joblib | `StandardScaler` fitted on the training split |
| `iforest.joblib` | `IFOREST_FILE` | joblib | `IsolationForest` model |
| `lstm_autoencoder.pt` | `LSTM_FILE` | PyTorch state dict | LSTM Autoencoder weights. **Note:** this is a `.pt` file (PyTorch `state_dict`), not a Keras `.keras` file. Load with `model.load_state_dict(torch.load(...))`. |
| `threshold.txt` | `THRESHOLD_FILE` | JSON `{"threshold": float, "percentile": float}` | 99th-percentile reconstruction MSE from the validation split. A sequence whose MSE exceeds this value is anomalous. `BaselineEngine` accepts both the new JSON format and the legacy plain-float format for backward compatibility. |
| `provenance.json` | `PROVENANCE_FILE` | JSON | Full `ProvenanceMetadata` dict for the window that produced this model version. |

The registered model name is `"cnds-unsupervised-baseline"` (`MODEL_NAME` constant). The MLflow experiment is `"cnds-unsupervised-baseline"` (`experiment_name` default on `WindowTrainer`).

---

## Concurrency Model

Understanding the locking discipline is essential before modifying this subsystem.

### Lock scope

`BaselineCollector._lock` is a `threading.Lock` (not reentrant). It protects:
- `_buffer`, `_src_ips`, `_dst_port_counts`, `_window_start_ts`
- `_training_in_flight`, `_dropped_while_training`

The lock is held for the minimum time possible. FlowRecord attribute extraction happens **before** acquiring the lock. `ProvenanceMetadata.from_window()` and `threading.Thread.start()` happen **after** releasing the lock.

### Training-in-flight gate

When `_training_in_flight` is `True`:
- Every `observe()` call increments `_dropped_while_training` and returns immediately without appending to the buffer.
- The next window cannot start until the current training run completes and clears `_training_in_flight` in its `finally` block.

This guarantees that at most one training thread is alive at any time.

### `_training_in_flight` is always cleared

Three paths clear the flag (all in `finally` or explicit error handlers):
1. Normal training completion in `_run_training()`'s `finally` block.
2. `ProvenanceMetadata.from_window()` raises an exception — cleared before returning.
3. `threading.Thread.start()` raises an exception — cleared before returning.

If the flag were not cleared in any of these paths, the collector would permanently drop all future samples (the "thread freeze" bug covered by `TestThreadFreezeFix`).

### `init_baseline_collector()` concurrency

`pipeline.init_baseline_collector()` is protected by `_baseline_collector_lock`. The check-then-set pattern inside the lock prevents a TOCTOU race when multiple threads call it simultaneously on startup — only one `BaselineCollector` is ever constructed.

### Time-base invariant

`_window_start_ts` is always set to the `ts_epoch` of the packet that triggered the window (not `time.time()`). This keeps `elapsed_sec` on the same time base as the incoming packet timestamps, avoiding phantom long windows when wall-clock time drifts relative to packet timestamps (e.g., during PCAP replay). The guard `max(0.0, ts_epoch - _window_start_ts)` prevents negative elapsed values from out-of-order packets reaching `CompositeTrigger.should_fire()`.

---

## Testing

Tests live in `tests/unsupervised/test_collector.py`. Run with:

```bash
pytest tests/unsupervised/test_collector.py -v
```

All external dependencies (MLflow, PyTorch, scikit-learn, database) are fully mocked. The test file covers five bug-fix areas, each in its own class:

| Class | What it tests |
|---|---|
| `TestThreadFreezeFix` | `_training_in_flight` is always cleared, even when `Thread.start()` or `ProvenanceMetadata.from_window()` raises |
| `TestTimeBaseFix` | `_window_start_ts` uses packet time, not wall clock; `elapsed_sec` is never negative |
| `TestDropCounterFix` | Dropped-sample counter increments while training, resets to zero on completion, and produces a `WARNING` log |
| `TestInitBaselineCollectorLock` | Concurrent calls to `init_baseline_collector()` produce exactly one `BaselineCollector` instance |
| `TestCompositeTrigger` | Boundary conditions for each of the four trigger conditions, including entropy with empty or single-port counters |

Supplemental classes `TestShannonEntropy` and `TestObserveRobustness` cover the entropy helper and adversarial inputs to `observe()` respectively.

**Useful test helpers** (defined at module level):

- `_make_trigger(**kwargs)` — returns a `CompositeTrigger` with low thresholds suitable for unit tests.
- `_make_record(**kwargs)` — returns a `SimpleNamespace` that satisfies `BaselineCollector.observe()`.
- `_build_collector(**kwargs)` — assembles a `BaselineCollector` wired to a no-op callback.

---

## Operational Notes

### Drop rate

A non-zero drop count in the `WARNING` log after training means that the training duration exceeded the time needed to accumulate the next window. Strategies to reduce drops:

- Lower `min_total_vectors` on `CompositeTrigger` so windows are smaller and training completes faster.
- Reduce `epochs` or `n_estimators` in `WindowTrainer` (requires code change, not an env var).
- Move the training workload off the detection host entirely by consuming the MLflow artifacts from a separate process.

There is no mechanism to recover dropped samples. This is intentional — baseline training tolerates data loss without correctness impact.

### Time-base alignment

The window's elapsed time is measured in packet time, not wall-clock time. On a quiet network (few flows per minute) or during PCAP replay at non-realtime speed, the composite trigger's `min_elapsed_sec` condition measures traffic-time, not calendar time. A 30-minute `min_elapsed_sec` on a 10× speed PCAP replay fires after 3 calendar minutes.

### MLflow initialisation side effect

`WindowTrainer.__init__()` calls `mlflow_registry.init()` once. This call strips proxy-related environment variables from the process. Instantiate `WindowTrainer` before starting any threads that require those variables for outbound HTTP connections.

### Minimum window size

`WindowTrainer.train_window()` silently skips windows with fewer than 1,000 samples (logs a `WARNING`). This guards against degenerate windows produced by very short captures or replay sessions. The composite trigger's `min_total_vectors=50_000` default makes this path unreachable in normal operation; it is a safety net for non-default configurations.
