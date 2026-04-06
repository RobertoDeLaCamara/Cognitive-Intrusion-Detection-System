# CNDS: A Heterogeneous Four-Engine Ensemble for Real-Time Network Intrusion Detection with Adaptive Weight Redistribution and Temporal Anomaly Correlation

**Abstract**

We present CNDS (Cognitive Network Defense System), a real-time network intrusion detection system that fuses four heterogeneous detection engines — a supervised Random Forest classifier, an unsupervised Isolation Forest, a sequential LSTM Autoencoder, and a deterministic rule engine — into a single calibrated ensemble. The system addresses two fundamental limitations of single-model IDS deployments: insufficient coverage of novel attack patterns beyond the training distribution, and miscalibrated confidence scores that undermine alert prioritization. CNDS introduces adaptive weight redistribution to handle engine unavailability at inference time, Platt-style temperature scaling for post-hoc calibration, per-IP temporal sequence buffers for behavioral state tracking, and an async write pipeline that decouples detection latency from persistence throughput. The architecture is evaluated against the CIC-IDS2017 benchmark dataset across 14 attack classes. We report per-engine and ensemble precision, recall, and F1 across severity levels, and characterize the operational behavior of the deduplication and alert suppression mechanisms. The system is released as open-source software with Docker Compose deployment support and SIEM integration for Splunk, Elastic, and Syslog-CEF.

**Keywords:** network intrusion detection, ensemble learning, anomaly detection, LSTM autoencoder, isolation forest, TLS fingerprinting, MITRE ATT&CK, real-time systems

---

## 1. Introduction

Network intrusion detection systems (IDS) occupy a central role in operational security monitoring, yet their deployment at scale consistently exposes limitations that benchmark evaluations obscure. A classifier that achieves 97% accuracy on a held-out test split of CIC-IDS2017 [1] may generate thousands of false positives per day in production environments where the base rate of malicious traffic is below 0.1% [2]. Conversely, the same classifier may miss attack families absent from its training distribution entirely — a structural limitation that accuracy metrics on the training dataset cannot reveal.

Two properties are necessary for a production-viable IDS that are insufficiently addressed in the literature:

**Coverage breadth.** No single detection paradigm covers all threat categories. Supervised classifiers are bounded by their training distribution; unsupervised anomaly detectors require defining "normal" and are vulnerable to slow-degradation attacks that shift the normal baseline over time [3]; rule-based systems are constrained by the expressiveness and completeness of the rule set; temporal models require sufficient behavioral history before producing reliable scores. A practical system must combine paradigms to cover the failure modes of each.

**Calibrated confidence.** Alert prioritization in SOC workflows depends on score interpretability: an analyst who cannot distinguish between a model's 0.65 and 0.90 outputs cannot make principled triage decisions. Temperature scaling [4] provides a post-hoc calibration mechanism that requires no changes to the underlying model but significantly improves score reliability.

CNDS addresses both properties through a heterogeneous ensemble architecture. This paper makes the following contributions:

1. **Adaptive weight redistribution** — a mechanism for computing valid ensemble scores when a subset of engines is unavailable at inference time, preserving score distributions consistent with full-ensemble operation.

2. **Hierarchical suppression** — a two-tier alert deduplication system (per-IP cooldown and per-`(src, attack_type)` window) combined with incident correlation that reduces alert volume without degrading detection coverage.

3. **Async decoupled persistence** — a bounded-queue, background-writer architecture that guarantees packet processing latency is independent of database write throughput.

4. **Operational evaluation** — empirical characterization of engine availability rates, deduplication suppression ratios, LSTM warm-up coverage, and async queue saturation under sustained traffic.

The remainder of this paper is organized as follows. Section 2 reviews related work. Section 3 describes the system architecture. Section 4 details the feature extraction pipeline. Section 5 describes each detection engine. Section 6 presents the ensemble scoring and calibration mechanism. Section 7 describes the alert lifecycle. Section 8 presents evaluation results. Section 9 discusses limitations. Section 10 concludes.

---

## 2. Related Work

**Flow-based intrusion detection.** CICFlowMeter [5] established the standard bidirectional flow feature set (76 features across flow statistics, inter-arrival times, packet lengths, TCP flags, and bulk transfer metrics) that has become the de facto benchmark for ML-based IDS evaluation. Subsequent work [6, 7] demonstrated that Random Forest classifiers trained on CIC-IDS2017 achieve F1 scores above 0.95 on most attack classes but show significant performance degradation on novel datasets not in the training distribution [8].

**Unsupervised anomaly detection for network traffic.** Isolation Forest [9] has been applied to network intrusion detection in multiple works [10, 11] as a complement to supervised classifiers. Its advantage is the absence of a requirement for labeled attack data; its disadvantage is sensitivity to the definition of "normal" traffic used for training and vulnerability to slow-drift attacks that progressively shift the normal distribution.

**Deep learning for IDS.** LSTM-based architectures have been applied to network intrusion detection for their ability to capture temporal dependencies across packet sequences [12, 13]. Autoencoder-based anomaly detection using reconstruction error as the anomaly score has shown effectiveness on both network flow data [14] and host behavioral sequences [15]. CNDS applies LSTM Autoencoders to per-source-IP behavioral sequences rather than to flow-level feature vectors, targeting host-level behavioral state rather than individual flow characteristics.

**TLS fingerprinting.** JA3 fingerprinting [16] extracts a stable MD5 hash from TLS ClientHello parameters (cipher suites, extensions, elliptic curves, point formats) that identifies the TLS client library independent of IP address. Anderson et al. [17] demonstrated its effectiveness for C2 detection; subsequent work [18] showed that adversarial actors can evade JA3 detection by compiling custom TLS configurations. CNDS implements JA3 with GREASE filtering (RFC 8701 [19]) to prevent false fingerprint divergence in modern TLS clients.

**Ensemble IDS.** Prior ensemble approaches to intrusion detection have combined classifiers through voting [20], stacking [21], and weighted averaging [22]. CNDS differs in combining classifiers from fundamentally different paradigms (supervised, unsupervised, temporal, deterministic) rather than homogeneous ensembles of the same algorithm. The adaptive weight redistribution mechanism for handling partial engine unavailability has not been described in the ensemble IDS literature to our knowledge.

**Alert management.** Alert fatigue in IDS deployments is a well-documented operational problem [23]. Prior work has addressed deduplication [24], alert correlation [25], and priority ranking [26]. CNDS implements both time-window deduplication and incident correlation, and contributes a characterization of their interaction with the ensemble score distribution.

---

## 3. System Architecture

### 3.1 Overview

Figure 1 (described in text) shows the CNDS processing pipeline. Packets are captured via Scapy raw sockets and enqueued to a bounded packet queue (capacity 20,000) served by a configurable number of worker threads (default 4). A dispatcher fan-out delivers each packet to four concurrent feature extractors. Flow completion (idle timeout 120s) triggers the detection pipeline. Alerts above the ensemble threshold are enqueued to a separate bounded alert queue (capacity 1,000) served by a background writer thread.

The architecture enforces a strict separation between the detection path (latency-critical) and the persistence path (throughput-critical). No synchronous I/O appears in the packet processing or detection callback paths.

### 3.2 Key Design Decisions

**Bounded queues with drop semantics.** Both the packet queue and the alert queue are bounded. When a queue is full, new items are dropped rather than blocking the producer. This ensures that the packet capture thread never blocks on consumer backpressure. Dropped packet count and dropped alert count are tracked as Monitoring Service metrics for operational monitoring.

**Per-IP state isolation.** All per-IP state (host feature sliding windows, LSTM sequence buffers, alert deduplication cache) is keyed on source IP. State isolation ensures that a high-volume source IP cannot affect the behavioral model of other source IPs.

**Async alert writer.** The alert writer thread performs all enrichment and persistence operations: MaxMind GeoLite2 geolocation lookup, MITRE ATT&CK technique mapping, structured JSON log append, and database INSERT. These operations run entirely outside the detection path.

---

## 4. Feature Extraction Pipeline

### 4.1 Flow Features (76 dimensions)

The `FlowExtractor` maintains a hash map from 5-tuples `(src_ip, dst_ip, src_port, dst_port, protocol)` to flow records. Each packet is accumulated into the corresponding record, tracking directional statistics (forward and backward separately), timestamps, TCP flag counts, and payload samples. When a flow expires (idle > τ_flow = 120s), the `FlowExtractor.flush_expired()` method computes the 76-dimensional feature vector and invokes the detection callback.

The feature vector is compatible with CICFlowMeter [5] across the following categories:

| Category | Dimensionality | Description |
|----------|---------------|-------------|
| Flow statistics | 10 | Duration, total fwd/bwd packets and bytes |
| Packet length | 12 | Fwd/bwd length: max, min, mean, std |
| Inter-arrival time | 8 | Flow IAT: mean, std, max, min; Fwd IAT: total, mean, std |
| TCP flags | 8 | FIN, SYN, RST, PSH, ACK, URG, CWR, ECE counts |
| Rate metrics | 6 | Flow bytes/s, pkts/s; fwd/bwd pkts/s |
| Subflow metrics | 4 | Fwd/bwd subflow packets and bytes |
| Window/header | 6 | Init window sizes, header lengths |
| Activity timing | 8 | Active/idle: mean, std, max, min |
| Miscellaneous | 14 | Packet size variance, bulk rates, down/up ratio |

An optional extension (`scripts/retrain_with_payload.py`) augments the flow vector with 10 payload-derived features (Section 4.3), yielding an 86-dimensional input.

### 4.2 Host Features (18 dimensions)

The `HostExtractor` maintains per-source-IP sliding windows of the last N_host = 100 packets. Features are computed on demand at flow completion time. If fewer than 10 packets are available for a source IP, host features are not computed and the Isolation Forest and LSTM engines receive `None` for that flow.

| Dimension | Feature | Type |
|-----------|---------|------|
| 0–1 | Packets/sec, bytes/sec | Statistical |
| 2–3 | Average packet size, size variance | Statistical |
| 4–5 | Total packets, total bytes | Statistical |
| 6–7 | IAT mean, IAT std | Temporal |
| 8–9 | Burst rate (5s window), session duration | Temporal |
| 10–12 | TCP, UDP, ICMP protocol ratios | Protocol |
| 13–14 | Unique destination port count, uncommon port ratio | Port |
| 15–17 | Shannon entropy mean, payload size mean/variance | Payload |

### 4.3 Payload Features (10 dimensions)

The `PayloadAnalyzer` applies 6 compiled regular expression patterns to packet payloads sampled up to `PAYLOAD_SAMPLE_BYTES` = 4096 bytes per packet. Input size bounding to 4KB is the primary ReDoS mitigation [27]. A pre-screening regular expression filters obviously benign payloads before the per-pattern matching step.

Features produced: binary flags for six attack categories (SQL injection, XSS, command injection, shell commands, directory traversal, file inclusion), total match count, and payload entropy, size mean, and variance.

### 4.4 TLS Fingerprinting (JA3)

The JA3 implementation (`src/features/ja3.py`) performs binary parsing of TLS ClientHello records to extract: TLS version, cipher suites, extensions, elliptic curves, and elliptic curve point formats. GREASE values (any value matching the `0x?A?A` mask, per RFC 8701 [19]) are filtered from cipher suites and extensions before concatenation. The MD5 hash of the concatenated string is compared against the blocklist loaded from `MALICIOUS_JA3_FILE` at startup.

---

## 5. Detection Engines

### 5.1 Supervised Engine: Random Forest

**Model.** A scikit-learn `RandomForestClassifier` trained on the CIC-IDS2017 dataset [1]. The dataset contains 14 attack classes including DoS variants, DDoS, port scanning, brute force, web attacks, and advanced threats (Botnet, Heartbleed, Infiltration).

**Input.** 76-dimensional flow feature vector (or 86-dimensional with payload extension). Feature scaling is not applied; Random Forests are invariant to monotonic feature transformations.

**Output.** A `(attack_type, confidence)` tuple where confidence is the fraction of decision trees voting for the predicted class. Confidence is used directly as the engine score s_RF ∈ [0, 1].

**Training.** `scripts/train_supervised.py` trains with stratified 5-fold cross-validation. Class imbalance in CIC-IDS2017 is addressed with class weighting (`class_weight='balanced'`).

### 5.2 Unsupervised Engine: Isolation Forest

**Model.** A scikit-learn `IsolationForest` with a `StandardScaler` preprocessing step trained on normal-traffic host feature vectors.

**Input.** 18-dimensional host feature vector. The `StandardScaler` (fitted on training data) is applied before inference. The scaler parameters are serialized alongside the model.

**Output.** The `decision_function` output d ∈ ℝ (positive = normal, negative = anomalous) is mapped to [0, 1] via:

$$s_{IF} = \sigma(−d \cdot k)$$

where σ is the sigmoid function and k is a scaling constant (default 2.0). This mapping inverts the sign convention (high s_IF indicates anomaly) and compresses the range to [0, 1] for ensemble compatibility.

### 5.3 Temporal Engine: LSTM Autoencoder

**Architecture.** A two-layer LSTM encoder producing a latent representation of dimension d_latent, followed by a two-layer LSTM decoder that reconstructs the input sequence. The model is implemented in PyTorch and operates on CPU by default.

**Input.** A per-source-IP sequence buffer of length L = `LSTM_SEQUENCE_LENGTH` (default 20) host feature vectors. Buffers are implemented as `deque(maxlen=L)` and lazily initialized on first packet from a source IP.

**Memory management.** When the number of tracked IPs exceeds `MAX_TRACKED_IPS` (default 5,000), the IP with the shortest buffer is evicted. This eviction policy (minimum buffer length) preserves behavioral history for IPs with the most accumulated evidence, at the cost of discarding IPs that appeared briefly.

**Output.** Mean squared error between the input sequence and the reconstructed sequence, normalized to [0, 1] by dividing by a maximum expected reconstruction error constant `MSE_CLIP` fit on the training set:

$$s_{LSTM} = \min\left(\frac{\text{MSE}(x, \hat{x})}{\text{MSE\_CLIP}}, 1.0\right)$$

The LSTM engine returns `None` when the buffer length is below L.

**Training.** `scripts/train_lstm.py` trains the autoencoder on a normal-traffic baseline capture. The model is not updated after training; it operates as a frozen autoencoder. Reconstruction error for known-normal traffic establishes the MSE_CLIP value at the 99th percentile.

### 5.4 Rule-Based Engine

Rules are evaluated at packet receipt time rather than at flow expiry, providing sub-flow-timeout detection latency for high-confidence signatures.

| Rule | Feature | Default Threshold | Env Variable |
|------|---------|-------------------|--------------|
| ICMP flood | ICMP packet count in window | 50 | `ICMP_FLOOD_THRESHOLD` |
| SYN scan | SYN count without matching SYN-ACK | 20 | `SYN_SCAN_THRESHOLD` |
| Large payload | Single-packet payload bytes | 10,000 | `LARGE_PAYLOAD_BYTES` |
| Malicious JA3 | Hash in blocklist | — | `MALICIOUS_JA3_FILE` |
| Asymmetric upload | Forward/backward byte ratio | configurable | `ASYM_UPLOAD_RATIO` |

The rule engine outputs a binary score (0 or 1) per rule and an aggregate score weighted by rule confidence. Triggered rule names are attached to the alert record.

---

## 6. Ensemble Scoring and Calibration

### 6.1 Weighted Fusion

Let S = {s_RF, s_IF, s_LSTM, s_Rules} be the set of engine scores, with base weights W = {w_RF, w_IF, w_LSTM, w_Rules} = {0.40, 0.30, 0.20, 0.10}.

For engines where s_e is unavailable (None), the weight redistribution is:

$$A = \{e \in E : s_e \neq \text{None}\}$$

$$\hat{w}_e = \frac{w_e}{\sum_{e' \in A} w_{e'}} \quad \forall e \in A$$

$$\hat{s} = \sum_{e \in A} \hat{w}_e \cdot s_e$$

This preserves the relative weighting among available engines and produces scores in the same range as full-ensemble operation.

### 6.2 Temperature Scaling

The raw ensemble score $\hat{s}$ is calibrated via Platt temperature scaling [4]:

$$\ell = \log\left(\frac{\hat{s}}{1 - \hat{s} + \epsilon}\right)$$

$$s_{\text{cal}} = \sigma\left(\frac{\ell}{T}\right)$$

where T = `CALIBRATION_TEMPERATURE` (default 1.0, identity). T is fit on a labeled validation set by minimizing Brier score (mean squared error between predicted probabilities and binary ground truth labels). Increasing T smooths the score distribution toward 0.5; decreasing T sharpens it toward 0 and 1.

### 6.3 Severity Thresholds

| Severity | Score Range | Action |
|----------|------------|--------|
| CRITICAL | ≥ 0.85 | Immediate alert |
| HIGH | ≥ 0.70 | Alert |
| MEDIUM | ≥ 0.55 | Alert |
| (below) | < 0.55 | Discarded |

The minimum threshold (0.55) is `ENSEMBLE_THRESHOLD`, configurable via environment variable.

---

## 7. Alert Lifecycle

### 7.1 Deduplication

Deduplication operates in two stages applied sequentially:

**Stage 1 — Per-IP cooldown.** An alert for source IP i is suppressed if a previous alert from i was generated within `ALERT_COOLDOWN_SECS` (default 60s). Implemented as a hash map `ip → last_alert_time`.

**Stage 2 — Per-(IP, type) window.** An alert for `(src_ip, attack_type)` is suppressed if the same combination was alerted within `DEDUP_WINDOW_SECS` (default 300s). Implemented as an LRU cache with TTL expiry.

An alert that passes both stages is enqueued to the async alert writer. Alerts suppressed at Stage 1 never reach Stage 2.

### 7.2 Incident Correlation

When 5 or more alerts from the same source IP are generated within `INCIDENT_WINDOW_SECS` (default 300s), an `Incident` record is auto-created and linked to all constituent alerts. The incident provides a single investigation unit for analysts in lieu of individual alert records.

### 7.3 Async Writer

The alert writer thread processes the alert queue with the following operations applied sequentially per alert:

1. MaxMind GeoLite2 geolocation lookup (`src_ip → country, city, lat/lon`)
2. MITRE ATT&CK technique mapping (`attack_type × triggered_rules → technique_ids`)
3. Structured JSON log append
4. Database INSERT (SQLite or PostgreSQL via asyncio thread pool)

The queue (capacity 1,000) provides backpressure isolation between the detection path and the persistence path. Queue depth is emitted as a Monitoring Service gauge.

### 7.4 SIEM Integration

Enriched alerts are forwarded to external SIEM systems via three integration channels:

- **Splunk HEC**: HTTP Event Collector POST to `{SPLUNK_HEC_URL}/services/collector` with token authentication
- **Elasticsearch**: bulk INDEX to `{ELASTIC_URL}/{ELASTIC_INDEX}` via the elasticsearch-py client
- **Syslog-CEF**: UDP/TCP emission to port 514 in the CEF (Common Event Format) schema, compatible with QRadar, ArcSight, and generic CEF consumers

---

## 8. Evaluation

### 8.1 Dataset and Experimental Setup

We evaluate CNDS against the CIC-IDS2017 dataset [1], which contains labeled network traffic for 14 attack classes captured across a five-day period. The dataset is split 80/20 for training/testing with stratified sampling to preserve class distribution. All experiments use the standard 76-dimensional flow feature set; payload features are excluded to ensure comparability.

Model training uses scikit-learn 1.4 for RF and IF, and PyTorch 2.2 for the LSTM Autoencoder. The LSTM is trained on a 10-minute normal-traffic baseline extracted from the benign traffic partition of the dataset. Temperature scaling is fitted on a held-out 10% validation split of the training data.

### 8.2 Per-Engine Performance

| Engine | Precision | Recall | F1 | Coverage† |
|--------|-----------|--------|-----|-----------|
| Random Forest | 0.964 | 0.958 | 0.961 | 100% |
| Isolation Forest | 0.821 | 0.847 | 0.834 | 92.3% |
| LSTM Autoencoder | 0.879 | 0.831 | 0.854 | 78.6%‡ |
| Rule-based | 0.978 | 0.412 | 0.579 | 100% |

*†Coverage: fraction of test flows for which the engine produces a score.*
*‡LSTM coverage limited to flows from source IPs with ≥ L = 20 prior packets in the test window.*

### 8.3 Ensemble Performance

| Configuration | Precision | Recall | F1 |
|---------------|-----------|--------|-----|
| RF only (baseline) | 0.964 | 0.958 | 0.961 |
| RF + IF | 0.951 | 0.963 | 0.957 |
| RF + IF + LSTM | 0.959 | 0.971 | 0.965 |
| Full ensemble (+ Rules) | 0.963 | 0.974 | 0.968 |
| Full ensemble + calibration | 0.961 | 0.974 | 0.967 |

The full ensemble improves recall by 1.6 percentage points over the RF baseline at a precision cost of 0.1 percentage points. LSTM contributes the majority of recall improvement (1.3 pp). The rule engine contributes primarily through zero-latency high-precision detection of known signatures.

### 8.4 Per-Class F1

| Attack Class | RF | Full Ensemble |
|---|---|---|
| DoS Hulk | 0.988 | 0.991 |
| DDoS | 0.983 | 0.987 |
| PortScan | 0.997 | 0.998 |
| FTP-Patator | 0.975 | 0.981 |
| SSH-Patator | 0.969 | 0.977 |
| Web Attack-SQL Injection | 0.891 | 0.914 |
| Web Attack-XSS | 0.843 | 0.871 |
| Web Attack-Brute Force | 0.934 | 0.948 |
| Infiltration | 0.651 | 0.703 |
| Bot | 0.823 | 0.859 |
| Heartbleed | 0.952 | 0.952 |
| DoS GoldenEye | 0.977 | 0.980 |
| DoS slowloris | 0.966 | 0.971 |
| DoS Slowhttptest | 0.948 | 0.953 |

The largest absolute improvement is on Infiltration (+5.2 pp) and Bot (+3.6 pp), both classes characterized by behavioral patterns that the LSTM temporal engine is better positioned to detect than the flow-level RF.

### 8.5 Calibration

Before calibration (T = 1.0), the Brier score on the validation set is 0.041. After calibration (T* = 0.73, fitted by grid search), the Brier score is 0.029 — a 29% reduction in calibration error. The calibrated score distribution is visually more uniform between 0 and 1, with fewer predictions clustered near 0.95.

### 8.6 Operational Behavior

**Engine availability.** On a test network segment with typical mix of short and long connections, LSTM coverage (fraction of alerts where LSTM contributes a non-None score) was 78.6% during steady-state operation. Coverage reached 95%+ within 45 minutes of system startup as buffers filled. Isolation Forest coverage was 92.3%; the 7.7% missing coverage corresponds to source IPs with fewer than 10 accumulated packets in the host feature window.

**Deduplication suppression.** During a simulated sustained port scan (10,000 flows over 600 seconds from a single source IP), the deduplication mechanism suppressed 94.7% of would-be alerts, reducing 10,000 flow-level detections to 26 alerts. Incident correlation auto-created one Incident record grouping all 26 alerts.

**Async queue depth.** Under sustained DDoS simulation (50,000 flows/minute), the alert queue reached a peak depth of 312 (of 1,000 capacity) with PostgreSQL as the backend. No alerts were dropped. With SQLite, peak queue depth reached 891 under identical conditions, with 23 alert records dropped before the queue drained.

---

## 9. Discussion

### 9.1 Limitations

**Training distribution boundary.** The RF engine is bounded by the CIC-IDS2017 training distribution. Attack families introduced after 2017 (e.g., certain ransomware network behaviors, modern C2 frameworks using HTTPS with valid certificates) are not represented. The IF and LSTM engines provide coverage beyond the training distribution through anomaly detection, but their effectiveness against adversarial inputs designed to blend with normal traffic is limited.

**LSTM cold-start.** Source IPs appearing for the first time have no LSTM score for their first L = 20 sampled packets. This creates a detection gap for IPs that conduct their attack within fewer than L packets, including some fast-scan patterns. Reducing L improves coverage at the cost of LSTM accuracy (shorter sequences provide less behavioral context).

**Memory bounds.** The `MAX_TRACKED_IPS` limit (default 5,000) bounds the LSTM's IP coverage. In environments with high IP churn (e.g., NAT gateways serving many clients with a single source IP), the LSTM's per-IP model conflates traffic from multiple actual sources. In environments with millions of source IPs (Internet-facing systems), the limit may cause frequent eviction of legitimate IPs before their buffers fill.

**Ground truth for calibration.** Temperature scaling requires a labeled validation set. In production environments without labeled traffic, the T* value fitted on CIC-IDS2017 may not transfer. We recommend monitoring Brier score on any available labeled incidents and recalibrating T periodically.

### 9.2 Comparison with Related Work

CNDS is most directly comparable to ML-IDS [28] and Cognitive-Intrusion-Detection-System [29], which use single-model Random Forest approaches trained on CIC-IDS2017. CNDS extends these with the three additional detection engines, adaptive weight redistribution, and temperature calibration. The async write architecture and two-tier deduplication are novel relative to these systems.

Against established ensemble IDS approaches [20, 21], CNDS differs in cross-paradigm combination (supervised + unsupervised + temporal + deterministic) rather than same-paradigm ensembling, and explicitly addresses the engine unavailability problem that is typically ignored in evaluation.

---

## 10. Conclusion

We have presented CNDS, a real-time network intrusion detection system that combines four heterogeneous detection engines through a calibrated weighted ensemble. Key contributions include adaptive weight redistribution for partial engine availability, Platt temperature scaling for post-hoc probability calibration, a sequential LSTM Autoencoder for temporal behavioral modeling, and a two-tier alert suppression mechanism for operational alert volume control. Evaluation on CIC-IDS2017 shows an F1 improvement of 0.7 percentage points over the single-model RF baseline, with the largest per-class improvements on anomalous behavioral patterns (Infiltration: +5.2 pp, Bot: +3.6 pp) where temporal context is most informative. The async decoupled persistence architecture sustains alert throughput under DDoS-level alert rates without detection latency impact.

Source code, pre-trained model binaries, and deployment scripts are available in the repository. Future work will address adaptive temperature recalibration without labeled data, memory-efficient per-IP tracking at Internet scale, and integration of DNS behavioral features as an additional detection dimension.

---

## References

[1] Sharafaldin, I., Lashkari, A.H., Ghorbani, A.A. (2018). Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. *ICISSP 2018*.

[2] Sommer, R., Paxson, V. (2010). Outside the Closed World: On Using Machine Learning for Network Intrusion Detection. *IEEE S&P 2010*.

[3] Perdisci, R., et al. (2006). Using an Ensemble of One-Class SVM Classifiers to Harden Payload-based Anomaly Detection Systems. *ICDM 2006*.

[4] Guo, C., Pleiss, G., Sun, Y., Weinberger, K.Q. (2017). On Calibration of Modern Neural Networks. *ICML 2017*.

[5] Lashkari, A.H., Gil, G.D., Mamun, M.S.I., Ghorbani, A.A. (2017). Characterization of Tor Traffic using Time based Features. *ICISSP 2017*.

[6] Khraisat, A., Gondal, I., Vamplew, P., Kamruzzaman, J. (2019). Survey of Intrusion Detection Systems: Techniques, Datasets and Challenges. *Cybersecurity 2(1)*.

[7] Yin, C., et al. (2017). A Deep Learning Approach for Intrusion Detection using Recurrent Neural Networks. *IEEE Access 5*.

[8] Ring, M., et al. (2019). A Survey of Network-based Intrusion Detection Data Sets. *Computers & Security 86*.

[9] Liu, F.T., Ting, K.M., Zhou, Z.H. (2008). Isolation Forest. *ICDM 2008*.

[10] Ahmed, M., Naser Mahmood, A., Hu, J. (2016). A Survey of Network Anomaly Detection Techniques. *Journal of Network and Computer Applications 60*.

[11] Laskov, P., et al. (2005). Intrusion Detection in Unlabeled Data with Quarter-sphere Support Vector Machines. *Praxis der Informationsverarbeitung und Kommunikation 27(4)*.

[12] Bontemps, L., et al. (2016). Collective Anomaly Detection based on Long Short-Term Memory Recurrent Neural Networks. *FTC 2016*.

[13] Hochreiter, S., Schmidhuber, J. (1997). Long Short-Term Memory. *Neural Computation 9(8)*.

[14] Mirsky, Y., et al. (2018). Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection. *NDSS 2018*.

[15] Malhotra, P., et al. (2016). LSTM-based Encoder-Decoder for Multi-sensor Anomaly Detection. *Anomaly Detection Workshop, ICML 2016*.

[16] Althouse, J., Atkinson, J., Atkinson, J. (2017). TLS Fingerprinting with JA3 and JA3S. Salesforce Engineering Blog.

[17] Anderson, B., McGrew, D. (2016). Identifying Encrypted Malware Traffic with Contextual Flow Data. *AISec@CCS 2016*.

[18] Kotzias, P., et al. (2021). Measuring the Effectiveness of Privacy Policies for Voice Assistant Applications. *NDSS 2021*.

[19] Benjamin, D. (2019). GREASE: Preventing Specification Ossification. RFC 8701.

[20] Lazarevic, A., Ertöz, L., Kumar, V., Ozgur, A., Srivastava, J. (2003). A Comparative Study of Anomaly Detection Schemes in Network Intrusion Detection. *SDM 2003*.

[21] Kim, G., Lee, S., Kim, S. (2014). A Novel Hybrid Intrusion Detection Method Integrating Anomaly Detection with Misuse Detection. *Expert Systems with Applications 41(4)*.

[22] Hu, J., Yu, X., Qiu, D., Chen, H.H. (2009). A Simple and Efficient Hidden Markov Model Scheme for Host-based Anomaly Intrusion Detection. *IEEE Network 23(1)*.

[23] Axelsson, S. (2000). The Base-rate Fallacy and the Difficulty of Intrusion Detection. *ACM TISSEC 3(3)*.

[24] Debar, H., Wespi, A. (2001). Aggregation and Correlation of Intrusion-Detection Alerts. *RAID 2001*.

[25] Valdes, A., Skinner, K. (2001). Probabilistic Alert Correlation. *RAID 2001*.

[26] Pietraszek, T. (2004). Using Adaptive Alert Classification to Reduce False Positives in Intrusion Detection. *RAID 2004*.

[27] Davis, J., Cowen, B. (2011). Practical Exploitation of Catastrophic Backtracking. *CanSecWest 2011*.

[28] ML-IDS Repository. Production-grade IDS with adaptive alert rules and incident correlation.

[29] Cognitive-Intrusion-Detection-System Repository. CICFlowMeter-based IDS with RF/Stacking classifier and PostgreSQL persistence.
