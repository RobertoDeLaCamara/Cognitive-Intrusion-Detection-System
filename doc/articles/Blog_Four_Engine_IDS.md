# Building a Production-Grade Four-Engine Network IDS: Why One ML Model Is Never Enough

*Originally written for The New Stack / Towards Data Science style*

---

Network intrusion detection is one of those problems where a single clever algorithm reliably disappoints you in production. You train a Random Forest on CIC-IDS2017, hit 97% accuracy on the test set, deploy it — and within a week you're drowning in false positives from a legitimate vulnerability scanner while missing a slow-and-low credential-stuffing campaign running right through your network.

The problem is not the algorithm. It is the assumption that a single model can capture every threat vector simultaneously. CNDS (Cognitive Network Defense System) takes a different approach: four independent engines, each optimized for a different detection paradigm, fused by a weighted ensemble with calibrated confidence scores and automatic weight redistribution when any engine is unavailable.

This post walks through the architecture, the reasoning behind each design choice, and the non-obvious implementation details that make it work in production.

---

## The Four Engines and What They Each Catch

### Engine 1 — Random Forest (40% weight)

The Random Forest is trained on the CIC-IDS2017 dataset using 76 CICFlowMeter-compatible flow features: inter-arrival times, packet lengths, TCP flag counts, byte rates, and so on. It's the only supervised engine, which means it requires labeled training data and is strongest on known attack patterns.

What it catches well: DoS variants (Hulk, GoldenEye, slowloris), DDoS, PortScan, FTP/SSH brute force, web attacks (XSS, SQL injection).

What it misses: novel attack patterns not in the training data, slow-and-low campaigns that blend into baseline traffic statistics, and host-level behavioral anomalies.

One practical extension in CNDS is a `retrain_with_payload.py` script that augments the feature vector with 10 additional payload-derived features (entropy, pattern match counts, character distributions), bringing the total to 86. This improves SQL injection and command injection detection rates meaningfully.

### Engine 2 — Isolation Forest (30% weight)

The Isolation Forest operates on 18 per-IP host features computed from a sliding window of the last 100 packets per source: packets/sec, bytes/sec, TCP/UDP/ICMP ratios, unique destination port count, Shannon entropy, burst rate, and session duration.

It is trained on normal traffic — no attack labels needed. This makes it the right tool for detecting *deviation from baseline*, regardless of what the deviation is caused by.

What it catches well: volumetric anomalies, unusual scanning patterns, protocol ratio shifts (a device suddenly sending 90% ICMP), and post-compromise exfiltration behavior that has no labeled equivalent in training data.

What it misses: attacks that deliberately mimic normal traffic statistics — some advanced APT techniques are specifically designed to avoid volumetric detection.

The StandardScaler is fitted during training and must be saved alongside the model (`models/isolation_forest.joblib` + `models/if_scaler.joblib`). The decision function output is sigmoid-mapped to [0,1] to make it ensemble-compatible.

### Engine 3 — LSTM Autoencoder (20% weight)

The LSTM Autoencoder maintains a per-source-IP sequence buffer (default length 20). Each new host feature vector from that IP is appended to the buffer. When the buffer is full, the autoencoder reconstructs the sequence and measures the reconstruction error. High error = anomalous behavior.

The critical difference from the Isolation Forest is *temporal sensitivity*. A device that normally sends 50 packets/sec and then suddenly sends 5000 for two minutes will have high reconstruction error even if the Isolation Forest's sliding window has already normalized around the new rate. The LSTM "remembers" the sequence of states.

Implementation detail: per-IP sequence buffers are lazily created on first encounter. When `MAX_TRACKED_IPS` (default 5000) is reached, the IP with the shortest buffer is evicted — effectively discarding the IP with the least information about its behavior. This is a deliberate choice over LRU eviction (least recently seen), which would discard potentially anomalous IPs that have gone quiet.

### Engine 4 — Rule-Based (10% weight)

Rules fire immediately on individual packets without waiting for flow expiry. They cover:

- **ICMP flood**: packet count in window > threshold
- **SYN scan**: SYN flag count without matching SYN-ACK
- **Large payload**: single payload > 10,000 bytes
- **Malicious JA3**: TLS ClientHello MD5 hash matches known-bad list

The JA3 fingerprinting deserves special mention. The TLS ClientHello contains the client's supported cipher suites, extensions, elliptic curves, and point formats — a surprisingly stable fingerprint for a given tool or malware family. GREASE values (RFC 8701) are filtered before hashing. A blocklist of malicious JA3 hashes (Cobalt Strike beacons, specific RATs) provides immediate, low-false-positive detection of known C2 tooling.

Rules carry only 10% of the ensemble weight because they are high-precision but low-recall — they miss everything they don't have a rule for.

---

## Ensemble Fusion and Weight Redistribution

The four scores are combined as:

```
score = 0.40 × RF + 0.30 × IF + 0.20 × LSTM + 0.10 × Rules
```

But in practice, engines are not always available. The LSTM needs `seq_len` packets before it produces a score. A freshly captured flow from a new IP has no LSTM score yet. The RF model may not be loaded (if CIC-IDS2017 wasn't available for training).

CNDS handles this by redistributing unavailable engine weights proportionally:

```python
active = {e: w for e, w in weights.items() if score[e] is not None}
total = sum(active.values())
adjusted = {e: w / total for e, w in active.items()}
```

This means the system degrades gracefully rather than crashing or silently producing incorrect scores.

After fusion, a Platt-style temperature scaling step calibrates the final score:

```python
calibrated = sigmoid(logit(score) / temperature)
```

With `CALIBRATION_TEMPERATURE=1.0` this is a no-op. Increasing the temperature spreads scores toward 0.5 (softer, fewer high-severity alerts); decreasing it sharpens the distribution (more decisive). This is calibrated once after training against a validation set with known ground truth.

---

## The Feature Extraction Pipeline

Three extractors run concurrently on every packet:

**FlowExtractor** maintains a 5-tuple map (src_ip, dst_ip, src_port, dst_port, protocol) of in-flight flows. For each packet it accumulates directional stats (fwd vs bwd), timestamps, flag counts, and payload samples. When a flow expires (idle > 120s), it computes the 76-feature vector and triggers the detection callback. This bidirectionality is critical — many flow features (e.g., forward/backward packet ratio) are meaningless on unidirectional data.

**HostExtractor** maintains per-IP sliding windows of the last 100 packets. It computes the 18 host features on demand when the detection callback runs.

**PayloadAnalyzer** runs 6 compiled regex patterns against each packet payload, bounded to 4KB per sample. This input size limit is the primary ReDoS protection: without it, a carefully crafted packet can trigger catastrophic backtracking in a regex engine, blocking the entire detection pipeline. A pre-screening regex filters obviously benign payloads before the per-pattern matching.

---

## Deduplication and Alert Fatigue

A single scanning IP can generate thousands of flows per minute. Without deduplication, each flow would produce an alert, flooding the database and overwhelming analysts.

CNDS implements an in-memory LRU cache keyed on `(src_ip, attack_type)`. If the same combination was alerted within `DEDUP_WINDOW_SECS` (default 300 seconds), subsequent alerts are silently dropped. This is separate from the alert *cooldown* (`ALERT_COOLDOWN_SECS`, default 60s), which is a harder per-IP rate limit applied before even consulting the cache.

The incident correlation system provides the complementary view: if 5+ alerts from the same IP arrive within 300 seconds, an Incident record is auto-created, giving analysts a single investigation unit rather than hundreds of individual alerts.

---

## MITRE ATT&CK Enrichment

Every alert is automatically enriched with ATT&CK technique IDs derived from both the RF attack type and any triggered rule names. The mapping is stored in `src/enrichment/mitre.py` and is deduplicated by technique ID (a DoS alert that also triggers the syn_scan rule should not produce two T1046 entries).

This enrichment serves a practical purpose: it allows SOC workflows that pivot on ATT&CK tactics (e.g., "show me all alerts with Impact-tactic techniques") to work directly on CNDS data without custom parsing.

---

## SIEM Integration in Practice

CNDS ships with ready-to-use integration templates for Splunk HEC, Elastic/Logstash, and Syslog-CEF. The CEF forwarder (`siem/syslog/forwarder.py`) emits standard CEF over UDP/TCP to port 514, compatible with QRadar, ArcSight, and any CEF-aware SIEM.

The Splunk `savedsearches.conf` includes pre-built correlation searches for each attack class, so you get useful dashboards out of the box rather than starting from a blank search bar.

---

## What We Learned

A few takeaways from building and operating this system:

1. **The ensemble weight split matters less than you think, but calibration matters a lot.** Moving from 40/30/20/10 to 35/35/20/10 had minimal impact on aggregate precision/recall. But a miscalibrated temperature produced a bimodal score distribution that made it impossible to set a useful threshold.

2. **Trusted-outbound filtering is essential in any real network.** A NAS scanning its own subnet generates hundreds of "anomalous" host feature vectors per hour. Adding it to `TRUSTED_OUTBOUND` eliminates this noise without weakening detection elsewhere.

3. **The LSTM's value is in the edge cases.** On the CIC-IDS2017 benchmark, the LSTM adds ~2% to precision. In production, it caught three slow-and-low exfiltration events that the RF and IF both missed. The 20% weight understates its operational importance.

4. **SQLite will fail you at scale.** The async writer never blocks packet processing, but SQLite's single-writer limitation means alert persistence slows down as alert volume grows. Switch to PostgreSQL (`DATABASE_URL=postgresql+asyncpg://...`) before production deployment.

---

## Getting Started

```bash
cp .env.example .env
# Train models (see Development Guide)
docker-compose up
```

The full source is available at the repository linked below, with a Development Guide covering model training, environment configuration, and extending the rule engine with custom heuristics.
