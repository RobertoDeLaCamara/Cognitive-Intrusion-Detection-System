# CNDS: A Four-Engine Weighted Ensemble System for Real-Time Network Intrusion Detection with MITRE ATT&CK Attribution

**Abstract** — We present CNDS (Cognitive Network Defense System), a real-time network intrusion detection system that fuses four complementary detection engines — a supervised Random Forest classifier, an unsupervised Isolation Forest, an LSTM Autoencoder, and a rule-based heuristic engine — through a weighted ensemble with dynamic weight redistribution and Platt temperature calibration. The system extracts 76 CICFlowMeter-compatible flow features, 18 per-IP host behavioral features, and 10 payload-derived features from live Scapy packet capture through an asynchronous worker queue. Detected threats are automatically enriched with MITRE ATT&CK technique mappings and exported to SIEM platforms via Splunk HEC, Elastic, and Syslog-CEF. We describe the system architecture, feature engineering pipeline, ensemble scoring mechanism, deduplication strategy, and SIEM integration approach. The system is deployed as a three-container Docker Compose stack and exposed via a FastAPI REST interface with WebSocket streaming, JWT/RBAC authentication, and Prometheus metrics.

---

## 1. Introduction

Network intrusion detection systems (IDS) face a fundamental tension between recall (detecting all attacks) and precision (minimizing false positives). Single-model approaches trained on labeled datasets such as CIC-IDS2017 [1] achieve high accuracy on known attack patterns but fail to generalize to novel threats, slow-and-low campaigns, or behavioral anomalies that have no labeled equivalent. Rule-based systems offer high precision on known signatures but require continuous manual maintenance and cannot detect unknown attack variants.

We propose a multi-engine ensemble architecture that addresses these limitations by combining supervised, unsupervised, temporal, and heuristic detection paradigms in a single coherent pipeline. Each engine captures a different signal dimension: the supervised Random Forest detects known attack patterns; the Isolation Forest detects deviation from normal host behavior regardless of attack type; the LSTM Autoencoder detects temporal behavioral shifts; and the rule-based engine provides immediate, high-precision detection of specific known-bad indicators such as malicious TLS fingerprints.

The key contributions of this paper are:

1. A four-engine weighted ensemble architecture for real-time network IDS with dynamic weight redistribution when engines are unavailable.
2. A three-dimensional feature extraction pipeline combining 76 flow features, 18 host behavioral features, and 10 payload-derived features extracted concurrently from raw packet capture.
3. An asynchronous alert persistence architecture that guarantees detection pipeline throughput is never constrained by database write latency.
4. An automated MITRE ATT&CK enrichment mechanism that maps detected attack types and triggered rules to technique IDs without requiring analyst involvement.
5. A production-ready deployment with REST API, WebSocket streaming, RBAC authentication, and multi-platform SIEM integration.

---

## 2. Related Work

Intrusion detection using machine learning has been studied extensively. Tavallaee et al. [2] demonstrated the effectiveness of Random Forest classifiers on the KDD Cup 1999 dataset. Sharafaldin et al. [1] introduced CIC-IDS2017, a more realistic dataset with 80 network traffic features. Mirsky et al. [3] proposed Kitsune, an online anomaly detection system using an ensemble of autoencoders. Our work differs in combining supervised and unsupervised approaches with temporal modeling in a single weighted ensemble, and in targeting operational deployment with SIEM integration rather than offline evaluation.

The use of LSTM autoencoders for anomaly detection was explored in [4] for time-series anomaly detection. We apply this approach per-source-IP rather than globally, enabling detection of individual host behavioral shifts without contamination from network-wide traffic patterns.

JA3 TLS fingerprinting was introduced by Althouse et al. [5] as a method for identifying TLS client implementations, including malicious ones. CNDS incorporates JA3 fingerprinting into the rule-based engine with GREASE filtering per RFC 8701 [6].

---

## 3. System Architecture

### 3.1 Overview

CNDS operates as a three-container Docker Compose stack: a detector container running the full detection pipeline, an API container exposing the FastAPI REST interface and writing to the database, and a Streamlit dashboard container. The detector uses host networking for raw socket access; the API and dashboard communicate over the Docker bridge network.

```
Network → PacketCapture (Scapy) → PacketProcessor (queue + workers)
       → Dispatcher → {FlowExtractor, HostExtractor, PayloadAnalyzer, JA3}
       → on_flow_complete() → [RF, IF, LSTM, Rules] → EnsembleScorer
       → [dedup check] → async writer queue → DB + GeoIP + MITRE + log
       → FastAPI :8000 + WebSocket + SIEM
```

### 3.2 Packet Capture and Queuing

Raw packets are captured via Scapy's `sniff()` function. Captured packets are enqueued to a bounded queue (capacity configurable, default 20,000). A configurable number of worker threads (default 4) consume from the queue and invoke the dispatcher. Queue overflow is tracked but does not block capture; packets are dropped with a warning log. This design ensures that processing backpressure never stalls packet ingestion.

### 3.3 Feature Extraction Dispatcher

The dispatcher invokes all four extractors on each packet:

- **FlowExtractor** (`src/features/flow_extractor.py`): Maintains a bidirectional flow table keyed on 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol). Accumulates per-direction statistics until flow expiry (idle > τ_flow, default 120s) or explicit flush.

- **HostExtractor** (`src/features/host_extractor.py`): Maintains per-IP sliding windows of the last W packets (default W=100). Computes 18 behavioral features on demand.

- **PayloadAnalyzer** (`src/features/payload_analyzer.py`): Runs 30+ regex patterns against packet payloads in daemon threads with per-pattern timeout t_regex=1s (ReDoS protection). Returns triggered rule names and 10 numeric features.

- **JA3** (`src/features/ja3.py`): Parses TLS ClientHello records; filters GREASE values; computes MD5 hash; checks against configurable blocklist.

---

## 4. Feature Engineering

### 4.1 Flow Features (76 dimensions)

Flow features are computed after flow expiry and are compatible with the CICFlowMeter feature set. They encompass statistical summaries of forward and backward packet streams:

**Packet length statistics**: minimum, maximum, mean, and standard deviation for both forward and backward directions.

**Inter-arrival times (IAT)**: mean, standard deviation, maximum, and minimum for both flow-level and per-direction IAT sequences.

**TCP flag counts**: FIN, SYN, RST, PSH, ACK, URG, CWR, ECE flag counts for both directions.

**Rate features**: flow bytes per second, flow packets per second, forward and backward packets per second.

**Subflow features**: forward and backward subflow packet and byte counts.

**Activity timing**: active and idle time statistics (mean, std, max, min) computed from the sequence of inter-arrival transitions.

**Window and header features**: initial forward and backward window sizes, forward header length.

### 4.2 Host Behavioral Features (18 dimensions)

Host features capture per-source-IP behavioral patterns independent of any specific flow:

```
h = [pkt/s, bytes/s, avg_pkt_size, pkt_size_var, total_pkts, total_bytes,
     iat_mean, iat_std, burst_rate_5s, session_duration,
     tcp_ratio, udp_ratio, icmp_ratio,
     unique_dst_ports, uncommon_port_ratio,
     avg_entropy, avg_payload_size, payload_size_var]
```

The 60-second temporal window and 100-packet sliding window are independently configurable.

### 4.3 Payload Features (10 dimensions)

Ten numeric features are extracted from payload samples: six binary flags indicating pattern match hits (SQL injection, XSS, command injection, web shell, directory traversal, file inclusion), total match count, average Shannon entropy, average payload size, and payload size variance.

---

## 5. Detection Engines

### 5.1 Supervised Random Forest

The Random Forest classifier is trained on the CIC-IDS2017 dataset [1] using 76 flow features. Class imbalance is addressed through class-weight balancing during training. The model outputs both a predicted attack class and a probability estimate, which is used as the engine confidence score.

Optionally, the feature vector can be extended to 86 dimensions by concatenating the 10 payload features, improving detection of injection-class attacks.

**Attack classes**: BENIGN, DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest, DDoS, PortScan, FTP-Patator, SSH-Patator, Web Attack-Brute Force, Web Attack-XSS, Web Attack-SQL Injection, Infiltration, Bot, Heartbleed.

### 5.2 Isolation Forest

The Isolation Forest [7] operates on 18-dimensional host feature vectors. It is trained on baseline normal traffic without attack labels. The decision function output d ∈ ℝ is mapped to a normalized score:

```
score_IF = sigmoid(−d)  ∈ [0, 1]
```

Negative decision function values correspond to anomalous observations. The scaler and model are serialized jointly to ensure inference-time normalization is consistent with training.

### 5.3 LSTM Autoencoder

Each source IP maintains an independent sequence buffer of length L (default L=20). The LSTM Autoencoder architecture follows:

- Encoder: 2-layer LSTM, hidden dimension H=64
- Latent layer: dense projection to dimension Z=32
- Decoder: 2-layer LSTM, hidden dimension H=64, dropout p=0.2

The anomaly score for IP i at time t is:

```
score_LSTM(i,t) = MSE(h_{t-L:t}, Decoder(Encoder(h_{t-L:t})))
                 normalized to [0,1] via max observed MSE
```

The buffer is only considered when it contains exactly L observations. Until then, the LSTM engine returns `None` and its weight is redistributed to active engines.

### 5.4 Rule-Based Engine

The rule-based engine evaluates five heuristic conditions:

1. ICMP flood: ICMP packet count in window > θ_icmp (default 50)
2. SYN scan: SYN flag count > θ_syn (default 20) without corresponding ACK
3. Large payload: payload size > θ_payload (default 10,000 bytes)
4. Asymmetric upload ratio: forward/backward byte ratio > θ_asym
5. Malicious JA3: computed MD5 hash ∈ blocklist

The rules engine returns a binary score (0 or 1) and the list of triggered rule names.

---

## 6. Ensemble Scoring

### 6.1 Weighted Fusion

The ensemble score is computed as:

```
E = w_RF × s_RF + w_IF × s_IF + w_LSTM × s_LSTM + w_Rules × s_Rules
```

with default weights w_RF=0.40, w_IF=0.30, w_LSTM=0.20, w_Rules=0.10.

When engine i returns `None`, its weight is redistributed proportionally across active engines:

```
W_active = Σ_{j ≠ i} w_j
w'_j = w_j / W_active  for j ≠ i
```

This ensures the total weight always sums to 1.0.

### 6.2 Temperature Calibration

A Platt-style temperature scaling step calibrates the raw ensemble score:

```
E_cal = σ(logit(E) / τ)
```

where τ is the calibration temperature (default τ=1.0). The parameter τ can also be tuned per-attack-type using the `ATTACK_TYPE_WEIGHTS` environment variable.

### 6.3 Alert Threshold

An alert is generated when E_cal ≥ θ_ensemble (default 0.55). Severity is assigned by:

| Severity | Threshold |
|----------|-----------|
| CRITICAL | E_cal ≥ 0.85 |
| HIGH | E_cal ≥ 0.70 |
| MEDIUM | E_cal ≥ 0.55 |

---

## 7. Post-Detection Pipeline

### 7.1 Deduplication

To avoid alert flooding, a bounded in-memory cache keyed on (src_ip, attack_type) with TTL = τ_dedup (default 300s) suppresses duplicate alerts within the window.

### 7.2 Async Alert Persistence

Alerts are never written synchronously during detection. Instead, they are enqueued to a bounded queue (capacity 1,000) consumed by a background writer thread. This ensures detection throughput is decoupled from database write latency. Queue overflow is tracked as a metric.

### 7.3 GeoIP Enrichment

Source IP addresses are resolved to geographic coordinates via the MaxMind GeoLite2 database, adding country, city, latitude, and longitude fields to each alert.

### 7.4 MITRE ATT&CK Attribution

Each alert is attributed to one or more MITRE ATT&CK techniques based on a deterministic mapping table in `src/enrichment/mitre.py`. Both the RF-predicted attack type and any triggered rule names contribute to the technique set. Duplicate technique IDs (e.g., when both the attack type and a rule map to T1046) are deduplicated. The resulting technique array is stored as a JSON column in the alert record.

### 7.5 Incident Correlation

When N_corr (default 5) alerts from the same source IP arrive within τ_corr (default 300s), an Incident record is automatically created and linked to all contributing alerts. This provides analysts with a single investigation unit for coordinated or persistent campaigns.

---

## 8. System Interface

### 8.1 REST API

The FastAPI REST API (`src/api/main.py`) exposes:

- `POST /api/predict`: manual prediction with arbitrary feature vectors
- `GET /api/alerts`: paginated alert retrieval with severity/IP/type filters
- `GET /api/alerts/export`: bulk CSV/JSON export
- `GET /api/alerts/trends`: time-bucketed alert counts
- `PATCH /api/alerts/{id}`: acknowledge and annotate
- `GET|POST /api/incidents`: incident management
- `POST /api/suppression-rules`: maintenance window suppression
- `GET /api/adaptive-weights`: feedback-driven weight computation

### 8.2 WebSocket Streaming

Real-time alert streaming is exposed at `WS /ws/alerts`. Alert JSON is broadcast to all connected clients on every new alert, enabling live dashboard updates without polling.

### 8.3 Authentication and Authorization

Two authentication mechanisms are supported:

- **API key**: static key via `X-API-Key` header, controlled by `API_KEY` environment variable
- **JWT**: token-based with RBAC (admin/analyst/viewer roles), enabled by `JWT_SECRET`

### 8.4 Observability

Prometheus metrics are exposed at `GET /metrics`:

| Metric | Type | Labels |
|--------|------|--------|
| cnds_alerts_total | Counter | severity, attack_type |
| cnds_packets_processed_total | Counter | — |
| cnds_packets_dropped_total | Counter | — |
| cnds_active_flows | Gauge | — |
| cnds_ensemble_score | Histogram | — |

OpenTelemetry distributed traces are exported to a configurable OTLP endpoint.

---

## 9. SIEM Integration

CNDS ships with integration templates for three SIEM platforms:

**Splunk**: HEC input configuration, sourcetype definition, and pre-built correlation searches in `siem/splunk/`.

**Elastic / OpenSearch**: Index template with field mappings and Logstash pipeline configuration in `siem/elastic/`.

**Syslog-CEF**: A standalone forwarder script (`siem/syslog/forwarder.py`) emits Common Event Format messages over UDP/TCP to port 514, compatible with QRadar, ArcSight, and any CEF-capable SIEM.

---

## 10. Discussion and Limitations

**Model staleness**: The supervised RF model is trained on a fixed dataset (CIC-IDS2017, 2017). Attack patterns evolve, and the model will not detect attack variants that differ significantly from its training distribution. The Isolation Forest and LSTM provide coverage for novel patterns, but neither can identify attack types specifically.

**LSTM cold start**: The LSTM engine requires L=20 consecutive host feature observations before producing a score. For IPs seen infrequently, this delay means the LSTM never activates. Short-lived scanner IPs may never be scored by the temporal engine.

**SQLite concurrency**: The default SQLite backend does not support concurrent writers. Under high alert volume, the async writer queue may back up. Production deployments should use PostgreSQL.

**Trusted outbound filtering**: The current implementation relies on DNS reverse lookups with a 1-hour TTL cache. DNS spoofing could bypass trusted-outbound filtering. A static IP-based allowlist (`IP_ALLOWLIST`) is a more robust alternative.

---

## 11. Conclusion

We have presented CNDS, a four-engine weighted ensemble network IDS that combines supervised, unsupervised, temporal, and heuristic detection in a production-ready deployment. The dynamic weight redistribution mechanism ensures graceful degradation when any engine is unavailable, while Platt temperature calibration produces well-calibrated confidence scores suitable for threshold-based alerting. Automated MITRE ATT&CK attribution and multi-platform SIEM integration reduce manual analyst workload and enable immediate integration into existing security workflows.

Future work includes online learning for the supervised engine to adapt to novel attack patterns, per-IP calibration of the LSTM anomaly threshold, and integration with active response mechanisms (firewall rule generation, traffic shaping) based on alert severity.

---

## References

[1] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization," in *Proc. ICISSP*, 2018.

[2] M. Tavallaee, E. Bagheri, W. Lu, and A. A. Ghorbani, "A Detailed Analysis of the KDD CUP 99 Data Set," in *Proc. IEEE Symp. Computational Intelligence for Security and Defense Applications*, 2009.

[3] Y. Mirsky, T. Doitshman, Y. Elovici, and A. Shabtai, "Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection," in *Proc. NDSS*, 2018.

[4] M. Malhotra, P. Vig, G. Shroff, and P. Agarwal, "Long Short Term Memory Networks for Anomaly Detection in Time Series," in *Proc. ESANN*, 2015.

[5] J. Althouse, J. Atkinson, and J. Smith, "TLS Fingerprinting with JA3 and JA3S," Salesforce Engineering Blog, 2019.

[6] D. Benjamin, "Applying Generate Random Extensions And Sustain Extensibility (GREASE) to TLS Extensibility," RFC 8701, IETF, 2020.

[7] F. T. Liu, K. M. Ting, and Z. H. Zhou, "Isolation Forest," in *Proc. ICDM*, 2008.

---

*Keywords*: network intrusion detection, ensemble learning, anomaly detection, LSTM autoencoder, Isolation Forest, MITRE ATT&CK, JA3 fingerprinting, real-time detection, SIEM integration
