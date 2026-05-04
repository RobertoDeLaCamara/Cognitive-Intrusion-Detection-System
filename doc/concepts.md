# CNDS — Key Concepts

This document explains the security, networking, and machine learning concepts referenced throughout the CNDS documentation. Each concept is explained on its own terms first, then grounded in how CNDS specifically uses it.

---

## Table of Contents

1. [Network Intrusion Detection Systems (IDS)](#1-network-intrusion-detection-systems-ids)
2. [MITRE ATT&CK Framework](#2-mitre-attck-framework)
3. [Network Flows and the 5-Tuple](#3-network-flows-and-the-5-tuple)
4. [CICFlowMeter and the CIC-IDS2017 Dataset](#4-cicflowmeter-and-the-cic-ids2017-dataset)
5. [JA3 TLS Fingerprinting](#5-ja3-tls-fingerprinting)
6. [Supervised engine — FT-Transformer (preferred) and Random Forest (fallback)](#6-the-supervised-engine--ft-transformer-preferred-and-random-forest-fallback)
7. [Isolation Forest](#7-isolation-forest)
8. [LSTM Autoencoder](#8-lstm-autoencoder)
9. [Ensemble Methods](#9-ensemble-methods)
10. [Confidence Calibration and Temperature Scaling](#10-confidence-calibration-and-temperature-scaling)
11. [Shannon Entropy](#11-shannon-entropy)
12. [SIEM Systems](#12-siem-systems)
13. [CEF — Common Event Format](#13-cef--common-event-format)
14. [JWT and RBAC](#14-jwt-and-rbac)
15. [Monitoring Service and OpenTelemetry](#15-Monitoring Service-and-opentelemetry)
16. [TCP Flags](#16-tcp-flags)
17. [Scapy](#17-scapy)
18. [Alembic and Database Migrations](#18-alembic-and-database-migrations)
19. [ML Tracking](#19-ML Tracking)
20. [Glossary of Attack Types](#20-glossary-of-attack-types)

---

## 1. Network Intrusion Detection Systems (IDS)

### What it is

An Intrusion Detection System monitors network traffic or host activity and raises alerts when it observes behavior that matches known attacks or deviates from a learned baseline. It is a **passive observer** — it reads traffic but does not block it. An Intrusion *Prevention* System (IPS) actively blocks or redirects suspicious traffic.

There are two fundamental detection approaches:

| Approach | How it works | Strength | Weakness |
|---|---|---|---|
| **Signature-based** | Match traffic against a database of known attack patterns | Extremely low false positives on known threats | Blind to anything not in the signature database |
| **Anomaly-based** | Learn what "normal" looks like; flag deviations | Can detect novel and zero-day attacks | Requires a good baseline; susceptible to false positives |

Most production IDS tools use one or the other. CNDS uses **both simultaneously**, combining a supervised classifier trained on labeled attack data (signature-like) with two unsupervised anomaly detectors (anomaly-based), and fusing the results into a single score.

### Network vs Host IDS

- **Network IDS (NIDS):** Monitors packets flowing across a network segment. Requires access to raw traffic — typically via a port mirror (SPAN port) or a network TAP. No software needs to be installed on monitored machines. CNDS is a NIDS.
- **Host IDS (HIDS):** Monitors activity on a single machine (file changes, process launches, log entries). Requires an agent installed on each host.

### Where CNDS fits

CNDS is a **network IDS** with an **ensemble of four engines** — two supervised (FT-Transformer with Random Forest fallback, plus Rules), two unsupervised (Isolation Forest, LSTM). This combination addresses the main failure modes of each approach in isolation: the supervised engines are precise on known attacks, while the unsupervised engines catch novel behaviors that have no signature.

---

## 2. MITRE ATT&CK Framework

### What it is

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a globally recognized knowledge base of adversary behavior maintained by the non-profit MITRE Corporation. It catalogs the **tactics** (the "why") and **techniques** (the "how") that real-world threat actors use across the attack lifecycle.

Think of it as a universal language for describing cyberattacks. Instead of saying "the attacker scanned the network," you say **T1046 — Network Service Scanning**, and every SOC analyst, threat hunter, and security tool in the world understands exactly what that means.

### Structure

ATT&CK is organized as a matrix:

```
Tactic (column)       → the goal of the adversary at this stage
  └── Technique (T####)  → a specific method to achieve the goal
        └── Sub-technique (T####.###) → a more specific variant
```

**The 14 tactics in ATT&CK for Enterprise:**

| Tactic | What the adversary is trying to do |
|---|---|
| Reconnaissance | Gather information before the attack |
| Resource Development | Build infrastructure for the attack |
| Initial Access | Get a foothold into the network |
| Execution | Run malicious code |
| Persistence | Maintain access across reboots and credentials changes |
| Privilege Escalation | Gain higher permissions |
| Defense Evasion | Avoid detection |
| Credential Access | Steal passwords and credentials |
| Discovery | Map the environment |
| Lateral Movement | Move through the network |
| Collection | Gather data of interest |
| Command and Control (C2) | Communicate with compromised systems |
| Exfiltration | Steal data out of the network |
| Impact | Disrupt, destroy, or ransom |

### Techniques relevant to CNDS detections

| MITRE ID | Name | Tactic | Detected by CNDS via |
|---|---|---|---|
| T1046 | Network Service Scanning | Discovery | Rules (syn_scan), RF (PortScan label) |
| T1110 | Brute Force | Credential Access | RF (FTP-Patator, SSH-Patator labels) |
| T1110.001 | Password Guessing | Credential Access | RF (Web Attack – Brute Force) |
| T1190 | Exploit Public-Facing Application | Initial Access | RF (Infiltration, Web Attack – SQL Injection) |
| T1059.007 | JavaScript (XSS) | Execution | Payload pattern match, RF label |
| T1071 | Application Layer Protocol | C2 | RF (Bot label) |
| T1071.001 | Web Protocols | C2 | Malicious JA3 rule |
| T1203 | Exploitation for Client Execution | Execution | RF (Heartbleed label) |
| T1498 | Network Denial of Service | Impact | Rules (icmp_flood), RF (DoS labels) |
| T1499 | Endpoint Denial of Service | Impact | RF (DoS Slowloris, Slowhttptest) |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration | Rules (asymmetric_upload), IF |
| T1030 | Data Transfer Size Limits | Exfiltration | Rules (large_payload) |

### How CNDS uses ATT&CK

Every alert fired by CNDS is automatically **enriched with MITRE technique IDs and tactic names** before being stored. The mapping lives in `src/enrichment/mitre.py` and works in two directions:

1. **From supervised label** — "DoS Hulk" → T1498 (Network Denial of Service)
2. **From triggered rules** — "payload:sql_injection" → T1190 (Exploit Public-Facing Application)

This enrichment has two practical effects:
- **Analyst context:** An analyst sees not just "anomaly" but "T1046 — Network Service Scanning, Discovery tactic" — they know what stage of the attack lifecycle they are looking at.
- **Compliance reporting:** Security frameworks (PCI DSS, NIST CSF, ISO 27001) increasingly require mapping controls to threat frameworks. CNDS provides this mapping automatically.

---

## 3. Network Flows and the 5-Tuple

### What a flow is

In networking, a **flow** is a sequence of packets that share the same set of identifying properties — the **5-tuple**:

```
(source IP, destination IP, source port, destination port, protocol)
```

All packets matching a given 5-tuple, from first packet to last, constitute one flow. Flows are bidirectional: packets from client to server are the "forward" direction; packets from server to client are "backward."

**Example:**
```
[CLIENT_IP]:54321 → 10.0.0.5:443 TCP  ← one flow
10.0.0.5:443 → [CLIENT_IP]:54321 TCP  ← same flow, backward direction
```

### Why flows matter for ML

Individual packets carry very little information. A single SYN packet from a random IP tells you almost nothing. But the **statistical properties of a flow** — how many packets it has, how fast they arrive, how large they are, which TCP flags appear, how symmetric the forward/backward traffic is — are highly discriminative for attack classification.

A DoS flood has thousands of short packets with near-zero inter-arrival time. A port scan has many flows each lasting milliseconds with only a SYN and no response. An SSH brute force has many flows to port 22 with identical small sizes. Random Forest learns these patterns from labeled flow data.

### Flow state in CNDS

CNDS maintains a `FlowRecord` object per 5-tuple. Each incoming packet updates the record:

- Forward/backward packet lengths are appended to lists.
- TCP flags are accumulated as counters.
- Timestamps are recorded for inter-arrival time (IAT) calculation.
- Active and idle periods are tracked.
- Forward payload bytes are sampled (up to 50 samples × 4 KB).

When a flow expires (no packet for `FLOW_TIMEOUT` seconds, default 120s), the record is flushed to compute the 76-feature vector and sent to the detection engines.

### Inter-Arrival Time (IAT)

IAT is the time between consecutive packets in a flow. It is one of the most informative features for anomaly detection:

- **DoS floods** have IAT approaching zero (packets arrive as fast as the network allows).
- **Slow HTTP attacks** (Slowloris) have IAT in the range of several seconds (deliberate pacing to keep connections open without completing them).
- **Beaconing C2** has highly regular IAT (e.g., every 60 seconds exactly), which looks anomalous when compared to human-driven web browsing.

CNDS computes IAT statistics (mean, std, max, min) both globally across the flow and separately per direction.

---

## 4. CICFlowMeter and the CIC-IDS2017 Dataset

### CICFlowMeter

CICFlowMeter is an open-source network traffic flow generator and analyzer developed by the **Canadian Institute for Cybersecurity (CIC)**. It takes PCAP files as input and outputs CSV files where each row is a flow described by ~80 statistical features — packet lengths, IATs, TCP flags, active/idle periods, etc.

CICFlowMeter defines a specific set of feature names and calculation methods. These definitions are the standard used by the CIC-IDS2017 dataset, and by extension, by CNDS's Random Forest.

The 76 features in `FLOW_FEATURE_NAMES` are a direct subset of the CICFlowMeter output, enabling CNDS to be trained on publicly available labeled data without custom feature engineering.

### CIC-IDS2017 Dataset

The CIC-IDS2017 dataset is the training corpus for CNDS's Random Forest. It was created by the Canadian Institute for Cybersecurity in 2017 by:

1. Building a realistic network with real end-user behavior (web browsing, email, streaming).
2. Running known attacks against the network over five days while capturing all traffic.
3. Processing the PCAPs with CICFlowMeter to produce labeled CSVs.

**Scale:**
- ~2.8 million labeled flow records
- 14 distinct classes (BENIGN + 13 attack types)
- Captures spread across Monday–Friday to include diurnal variation

**Why use CIC-IDS2017?**

Most network traffic datasets have one of two problems: they are either too old (the KDD Cup 1999 dataset, still widely used, was generated on hardware and protocols from 26 years ago) or they are proprietary. CIC-IDS2017 is publicly available, uses modern protocols, and includes a diverse set of attack types generated with real tools (nmap, Hydra, HULK, Slowloris, etc.).

**Known limitations:**

- The dataset is from 2017. It does not include attack traffic for techniques that emerged after that year.
- It is heavily imbalanced: BENIGN traffic constitutes ~80% of samples, which skews classifiers toward the majority class unless corrected.
- Some attack types are underrepresented (Infiltration has very few samples).
- The feature distributions may not match your specific network — a Random Forest trained on CIC-IDS2017 will perform differently on a university network versus an industrial control network.

These limitations are why CNDS uses three additional engines (Isolation Forest, LSTM, Rules) alongside the Random Forest — they compensate for the RF's blind spots.

---

## 5. JA3 TLS Fingerprinting

### TLS and the ClientHello

When a client initiates a TLS connection (the protocol underlying HTTPS), it sends a **ClientHello** message. This message contains a list of capabilities the client supports:

- **Protocol versions** it can speak (TLS 1.0, 1.1, 1.2, 1.3)
- **Cipher suites** it accepts (algorithms for key exchange, encryption, and MAC)
- **Extensions** it wants to use (SNI, ALPN, session tickets, etc.)
- **Elliptic curves** it supports for key exchange
- **EC point formats**

### The JA3 fingerprint

Different TLS client implementations (Chrome, Firefox, curl, Python requests, Go's net/http, OpenSSL, Metasploit, Cobalt Strike) send slightly different ClientHello messages — different cipher suite lists, different extension types, different ordering. These differences are consistent and characteristic of each implementation.

**JA3** (named after its creators John Althouse, Jeff Atkinson, and Josh Atkins) is a method to fingerprint TLS clients by:

1. Extracting five fields from the ClientHello: TLS version, cipher suites, extensions, elliptic curves, EC point formats.
2. Filtering out **GREASE** values (RFC 8701 — random values Chrome injects to test server flexibility).
3. Concatenating them into a comma-separated string.
4. Computing the **MD5 hash** of that string.

The resulting 32-character hex string is the JA3 fingerprint. It is the same for every connection made by the same client implementation, regardless of the destination server.

**Example:**
```
TLS ClientHello fields → "771,49195-49199-49196-49200,...,0-23-65281,..."
                       → MD5 → "a0e9f5d64349fb13191bc781f81f42e1"
```

### Why it matters for detection

Malware families tend to use specific TLS libraries in specific configurations. Cobalt Strike's default malleable C2 profile produces a distinctive JA3 hash. Metasploit's meterpreter has its own. Many commodity malware families use embedded TLS stacks with static configurations.

This means that even when traffic is encrypted (CNDS cannot read the payload), the JA3 hash can identify a known-malicious TLS client just from the handshake metadata.

**CNDS's JA3 implementation:**
- Parses raw TLS record bytes from captured packets.
- Filters GREASE values before computing the hash.
- Stores `ja3_hash` and `ja3_string` on every alert.
- Compares against a user-provided blocklist file (`MALICIOUS_JA3_FILE`).
- The Rules Engine fires `malicious_ja3` when a hash matches the blocklist.

### Limitations

JA3 can be evaded by randomizing the ClientHello field order or values. Newer evasion techniques (JA3N, JA4) address some of these limitations. The CNDS JA3 implementation follows the original spec; updating to JA4 would require modifications to `src/features/ja3.py`.

---

## 6. The supervised engine — FT-Transformer (preferred) and Random Forest (fallback)

The supervised slot in CNDS has two interchangeable models. Both consume
the same 76 CICFlowMeter flow-feature vector and return a `(label,
confidence)` pair. The registry picks **FT-Transformer when its
checkpoint is present** and falls back to Random Forest otherwise. They
are described in turn below.

### FT-Transformer (preferred)

A **tabular Transformer**: every numeric feature is projected to a 256-dim
embedding by its own learned affine map (one `W_j, b_j` per feature),
producing 76 token vectors. A learnable `[CLS]` token is prepended,
yielding a sequence of length 77. Three Pre-LayerNorm Transformer encoder
blocks let every token attend to every other token via 8-head
self-attention (head_dim = 32). The `[CLS]` output position is then
passed through a final LayerNorm and a `Linear(256 → 10)` head to produce
the 10-class logits.

Why a Transformer for tabular data? Decision-tree splits decompose the
feature space along single-feature thresholds at a time; SYN-flood
detection happens to need the *combination* of high `Flow Packets/s` AND
high `SYN Flag Count` AND zero `ACK Flag Count`. Multi-head attention
weighs subsets of features simultaneously instead of approximating the
combination via successive splits, which is why the FT-Transformer beats
the gradient-boosted baseline on minority attack classes (Worms,
Backdoor, Generic).

The model is **Optuna-tuned** (25 trials, TPESampler + MedianPruner) over
architecture, regularisation, optimisation, and class-imbalance
strategies. The winning configuration uses `class_weight='sqrt_inverse'`
(`w_j = sqrt(N / (n_classes * count_j))`) — the full inverse weighting
over-corrects on minorities and hurts overall macro F1; focal loss adds
nothing over sqrt-weighted CE. Test F1 macro: **0.6197** (XGBoost
baseline 0.6095, default FT-T 0.5446).

For the full architecture diagrams (data flow, tokenizer, encoder block,
parameter budget, attention example) see
[`ML-IDS/docs/UNIFIED_MODEL_ARCHITECTURE.md`](../../ML-IDS/docs/UNIFIED_MODEL_ARCHITECTURE.md).

### Random Forest (fallback)

When no FT-Transformer checkpoint is on disk and no MLflow registry is
configured, the registry falls back to the legacy Random Forest pipeline.
This keeps the system functional out of the box (`models/rf_lite_model.joblib`
ships with the repo). The same 76-feature vector goes in and the same
`(label, confidence)` interface comes out, so the rest of CNDS does not
need to know which model is active.

### Decision trees

A decision tree is a classification model that asks a series of yes/no questions about the input features, branching at each question, until it reaches a leaf node that returns a class label. Each question splits the data: "Is `syn_flag_cnt > 50`?" splits flows into potential port scans and everything else.

The problem with a single decision tree is that it **overfits** — it learns the training data too precisely and generalizes poorly to new data.

### Random Forest

A Random Forest solves overfitting by building many decision trees (100 in CNDS by default) and having them vote:

1. For each tree, a random **subset of training samples** is selected (bootstrap sampling).
2. At each split, only a random **subset of features** is considered (`max_features='sqrt'` by default — the square root of the total number of features).
3. Each tree grows independently to its full depth.
4. At inference time, all trees vote and the majority class wins.

The randomness in both sample selection and feature selection ensures that the trees are **decorrelated** — they make different errors, and those errors cancel out when averaged.

### `predict_proba` and confidence

`predict_proba()` returns the fraction of trees in the forest that voted for each class. If 88 out of 100 trees vote "PortScan," the confidence is 0.88. This is a natural measure of certainty that CNDS uses as the supervised engine's contribution to the ensemble score.

### Feature importance

Random Forests implicitly compute feature importance: features that produce the cleanest splits (highest reduction in impurity) across all trees get higher scores. This can be used to identify which of the 76 flow features are most discriminative for your specific network. Inspect with `model.named_steps['rf'].feature_importances_` after loading the model.

### In CNDS

The RF is trained on the CIC redistribution of UNSW-NB15 (~447k labeled flows, 10 classes — the dataset folder is named `CIC-IDS2017/` for historical reasons but the labels are UNSW-NB15). At inference, a 76-element (or 86-element with payload) flow feature vector is fed in, and the model returns the predicted attack class and its confidence. If the class is `Benign`, the engine contributes a score of 0.0 to the ensemble. Any attack class contributes its confidence score (or `1 - P(Benign)` if scoring through `anomaly_score()`). This RF code path only runs when no FT-Transformer checkpoint is available.

---

## 7. Isolation Forest

### The core insight

Most anomaly detection algorithms learn what "normal" looks like and flag deviations. Isolation Forest takes the opposite approach: instead of profiling normal, it asks **how easy is it to isolate this point from the rest?**

Anomalous points tend to be few and different from the bulk of the data. In a feature space, they occupy sparse regions. A random axis-aligned split is more likely to separate an anomaly from everything else in just a few cuts.

### How it works

1. Build an **isolation tree** by randomly selecting a feature, then randomly selecting a split value between that feature's min and max. Recurse on each side until each point is isolated or a depth limit is reached.
2. Build `n_estimators` (100 in CNDS) such trees.
3. For each data point, record the **average path length** to isolation across all trees.
4. Normal points are deep in the trees (hard to isolate); anomalous points are near the root (easy to isolate).

The **anomaly score** is derived from the average path length: shorter path = more anomalous.

### `decision_function`

scikit-learn's `decision_function()` returns the negative of the anomaly score shifted by the expected path length of a random point. Values close to 0 are ambiguous; **negative values are anomalies**; positive values are inliers.

CNDS maps this to [0, 1] using a sigmoid:
```
score = 1 / (1 + exp(5 × raw))
```
The steepness of 5 makes the transition sharp around the decision boundary (raw ≈ 0), which means scores are decisive rather than hovering around 0.5.

### What it detects in CNDS

The IF operates on **18 per-IP host features** (packet rate, byte rate, port diversity, entropy, etc.), not on individual flows. It answers the question: "Does this IP's overall behavior deviate significantly from baseline?"

This makes it effective at detecting:
- Volumetric attacks (flood traffic makes `packets_per_sec` and `bytes_per_sec` explode).
- Port scans (high `unique_ports`, `uncommon_port_ratio`).
- High-entropy exfiltration (encrypted data has entropy near 8 bits/byte; normal HTTP is ~5).

### Training requirement

The IF requires a **clean baseline** of normal traffic — it is entirely unsupervised. The quality of the baseline determines the quality of the model. A baseline captured during an active incident will teach the model that attack traffic is "normal."

---

## 8. LSTM Autoencoder

### Long Short-Term Memory (LSTM)

An LSTM is a type of **recurrent neural network (RNN)** designed to learn patterns in sequential data. Unlike regular neural networks that treat each input independently, an LSTM maintains a **hidden state** that carries information from previous time steps.

LSTMs solve the "vanishing gradient" problem that made early RNNs unable to learn long-range dependencies. They do this through three gating mechanisms:

- **Forget gate:** Decides what to discard from the hidden state.
- **Input gate:** Decides what new information to add.
- **Output gate:** Decides what to output from the hidden state.

This architecture makes LSTMs well-suited to sequences where the relationship between a current observation and an observation 10 or 20 steps back matters — exactly the case with network behavioral patterns over time.

### Autoencoders

An autoencoder is a neural network trained to **reconstruct its input**:

```
Input → Encoder → Latent representation (bottleneck) → Decoder → Reconstructed input
```

The bottleneck forces the network to learn a compressed representation that captures the most important structure in the data. After training on normal data, the autoencoder learns to reconstruct normal patterns well. When it encounters anomalous input, the reconstruction is poor — the **reconstruction error** (MSE between input and output) is high.

### LSTM Autoencoder for anomaly detection

Combining LSTM with an autoencoder creates a model that:
1. Learns the **normal temporal evolution** of host behavior (sequence-to-sequence).
2. Reconstructs input sequences with low error during normal operation.
3. Fails to reconstruct (high error) when behavior deviates from learned normal patterns.

In CNDS, the model processes sequences of 20 consecutive host feature vectors per IP. The architecture:

```
Encoder LSTM (input=18, hidden=64, layers=2, dropout=0.2)
    → latent projection (linear, 64→32)
    → Decoder LSTM (input=32, hidden=64, layers=2, dropout=0.2)
    → output projection (linear, 64→18)
```

### What it detects in CNDS

The LSTM's temporal view gives it unique sensitivity to:
- **Beaconing:** C2 malware that contacts a server at regular intervals. The periodic pattern in inter-arrival time and consistent packet sizes are anomalous compared to bursty human web traffic.
- **Slow exfiltration:** Gradual data transfer over hours that stays below any rate threshold. The sustained directional asymmetry in the sequence is anomalous.
- **Progressive brute force:** Authentication attempts spread thinly over time. The gradual increase in `unique_ports=1` (all to port 22) and consistent small packet sizes forms an anomalous temporal signature.
- **Behavioral drift:** When a host that normally does HTTP suddenly starts doing something different (high-entropy transfers, unusual protocols), the sequence diverges from learned patterns.

### Threshold

The `threshold` in `lstm_config.json` (1.1037 in production) is the 99th percentile of reconstruction error observed on the validation set during training. An error equal to the threshold maps to a score of 1.0; errors below it map to scores in (0, 1). This calibration step is critical — setting the threshold too low causes constant false positives; too high causes missed detections.

---

## 9. Ensemble Methods

### The wisdom of crowds

An ensemble combines multiple models to produce a better prediction than any single model alone. The intuition: if three independent experts each make different mistakes, and you average their opinions, the mistakes tend to cancel out.

For this to work, the models must be **diverse** — they should make errors on different samples. If all models fail on the same inputs, averaging does nothing.

### Why CNDS uses four engines

The four CNDS engines are diverse by design — they use **completely different feature representations and algorithms**:

| Engine | Features | Algorithm type | Error profile |
|---|---|---|---|
| Supervised (FT-Transformer or RF) | 76 flow features (per flow) | Supervised classification | Misses novel attacks not in training data |
| Isolation Forest | 18 host features (per IP) | Unsupervised anomaly | False positives on unusual-but-benign traffic |
| LSTM Autoencoder | Temporal sequences (per IP) | Unsupervised temporal | Cold-start gap; misses single-packet attacks |
| Rules Engine | All features (threshold) | Deterministic heuristics | Misses attacks below threshold; rigid |

A slow exfiltration attack will score low on the Rules Engine (below rate thresholds), moderate on the RF (no labeled pattern), but high on the IF (asymmetric bytes) and LSTM (persistent directional drift). Their disagreement is informative: the ensemble score will be moderate, which might still cross the alert threshold, and the per-engine breakdown tells the analyst which signals are driving the detection.

### Weighted average

CNDS fuses engine scores with a weighted average:

```
ensemble_score = Σ(weight_i × score_i) / Σ(weight_i)
```

Weights reflect the relative trustworthiness of each engine on the specific network:
- Supervised RF gets the highest weight (40%) because it is the most precise on known attacks.
- IF gets 30% — reliable for volumetric anomalies.
- LSTM gets 20% — valuable for temporal patterns but has cold-start issues.
- Rules get 10% — high precision but very low recall.

When an engine is unavailable, its weight is redistributed proportionally to the remaining engines.

### Dynamic weight redistribution

```
Example: LSTM unavailable
Before: RF=0.40, IF=0.30, LSTM=0.20, Rules=0.10  (sum=1.0)
After:  RF = 0.40/(0.40+0.30+0.10) = 0.50
        IF = 0.30/0.80 = 0.375
        Rules = 0.10/0.80 = 0.125              (sum=1.0)
```

This guarantees the ensemble always produces a score in [0, 1] regardless of which engines are running.

---

## 10. Confidence Calibration and Temperature Scaling

### The calibration problem

A classifier is **well-calibrated** if its predicted probability matches the empirical frequency of the event. If a Random Forest says "80% probability of PortScan" on 1,000 flows, roughly 800 of them should actually be port scans.

In practice, ensemble classifiers like Random Forests tend to be **overconfident** — they push probabilities toward 0 and 1 more than reality justifies. This is a problem for the CNDS ensemble: if the RF is systematically overconfident, it will dominate the weighted average even when other engines disagree.

### Platt scaling / temperature scaling

Temperature scaling applies a simple transformation to the logit (log-odds) of the raw score:

```
logit(p) = log(p / (1 - p))      ← convert probability to log-odds
scaled   = logit(p) / T          ← divide by temperature T
calibrated = sigmoid(scaled)      ← convert back to probability
```

- **T = 1.0 (no-op):** Score is unchanged.
- **T > 1.0 (softer):** The logit is divided by a number greater than 1, shrinking it toward 0, which pushes the sigmoid output toward 0.5. The model becomes less confident.
- **T < 1.0 (sharper):** The logit grows, pushing the sigmoid output toward 0 or 1. The model becomes more decisive.

In CNDS, `CALIBRATION_TEMPERATURE` is set per-deployment. The default is 1.0. If you observe that the ensemble score distribution is clustered near 0.9–1.0 even for borderline detections (overconfidence), raising the temperature toward 1.5–2.0 will spread the scores out and make the threshold more meaningful.

### How to calibrate empirically

1. Run CNDS on a known-labeled traffic set (e.g., a portion of CIC-IDS2017 replayed through `pcap_replay.py`).
2. Plot the histogram of ensemble scores for true positives and true negatives separately.
3. If the true negative scores have a long tail above 0.5, increase temperature.
4. If true positives cluster too close to the threshold (0.55), decrease temperature.

---

## 11. Shannon Entropy

### What it measures

Shannon entropy quantifies the **information content** or **unpredictability** of a sequence of symbols. For a byte sequence, it measures how uniformly distributed the byte values are, on a scale of 0 to 8 bits per byte:

```
H = -Σ p(x) × log₂(p(x))
```

where `p(x)` is the probability of each byte value (0–255).

| Entropy range | What it typically indicates |
|---|---|
| 0.0 – 2.0 | Highly repetitive data (padding, null bytes) |
| 3.0 – 5.0 | Human-readable text (HTML, JSON, plaintext) |
| 5.0 – 7.0 | Structured binary data (executables, some image formats) |
| 7.5 – 8.0 | Encrypted, compressed, or random data |

### Why it matters for network detection

- **Encrypted exfiltration:** Data encrypted with AES or compressed with gzip has entropy near 8.0. If a flow's payload entropy is consistently near 8.0 but the connection is not to a known HTTPS endpoint, it may be exfiltrating data over a non-standard channel.
- **Obfuscated payloads:** Attackers sometimes encode payloads in Base64 or XOR-obfuscate shellcode to evade pattern matching. These encodings raise the entropy above typical plaintext levels.
- **Normal TLS traffic:** HTTPS traffic also has high entropy (the payload is encrypted). The Isolation Forest learns that certain IPs legitimately have high entropy (they communicate over HTTPS), so this alone is not anomalous — it is the *combination* with other features (new IP, unusual port, unusual time) that drives the IF score.

CNDS uses entropy in two places:
1. **`avg_payload_entropy`** (host feature index 15) — mean entropy of recent payloads per IP, fed to IF and LSTM.
2. **`max_payload_entropy`** (payload feature index 7) — maximum entropy across forward payload samples of a flow, fed to the RF (in 86-feature mode) and used by the rules engine.

---

## 12. SIEM Systems

### What a SIEM is

A **Security Information and Event Management (SIEM)** system aggregates, normalizes, correlates, and stores security events from across an organization's infrastructure — firewalls, IDS, endpoints, applications, cloud services — into a single searchable platform. The two primary functions are:

- **Log management:** Long-term storage and search of security events.
- **Correlation:** Writing rules that detect attack patterns spanning multiple sources (e.g., "the same IP that triggered a port scan alert just failed 50 SSH logins").

Major SIEM platforms:

| Platform | Vendor | Notes |
|---|---|---|
| Splunk Enterprise Security | Splunk | Market leader; proprietary; very powerful query language (SPL) |
| Elastic SIEM / Security | Elastic | Open-source core (ELK stack); Elastic Security adds SIEM layer |
| Microsoft Sentinel | Microsoft | Cloud-native; tight Azure integration |
| IBM QRadar | IBM | Enterprise-focused; complex but feature-rich |
| ArcSight | Micro Focus | CEF originator; common in large enterprises |

### CNDS SIEM integration

CNDS integrates with SIEM platforms in two ways:

**Push (real-time):** When `WEBHOOK_URLS` is configured, every alert is POSTed as JSON to the configured endpoints immediately after enrichment. Splunk HEC and Elastic support JSON ingestion natively.

**Pull (batch):** The `GET /api/alerts/export` endpoint streams alerts as JSON or CSV. SIEM tools can poll this endpoint periodically or a scheduled job can push the export.

Pre-built configuration templates in the `siem/` directory handle field mappings and index definitions for Splunk, Elastic, and CEF Syslog.

---

## 13. CEF — Common Event Format

### What it is

CEF (Common Event Format) is a text-based standard for security event messages, originally developed by ArcSight (now Micro Focus). It is the de facto standard for syslog-based SIEM integration and is natively supported by QRadar, ArcSight Logger, and Microsoft Sentinel.

### Format

A CEF message is a single syslog line:

```
<syslog header> CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions
```

**Example from CNDS:**
```
<134>Mar 29 14:22:01 cnds CEF:0|CNDS|Cognitive Network Defense System|1.0.3|PortScan|Network Service Scanning Detected|7|src=[CLIENT_IP] dst=10.0.0.5 proto=TCP cs1=T1046 cs1Label=MITRETechnique cn1=0.85 cn1Label=EnsembleScore
```

**Fields:**
- `Version`: CEF format version (0)
- `Device Vendor/Product/Version`: Source system identification
- `Signature ID`: Machine-readable event code (the attack type)
- `Name`: Human-readable event name
- `Severity`: 0–10 scale (CNDS maps: low→3, medium→5, high→7, critical→10)
- `Extensions`: Key-value pairs with event details

### Why it matters

CEF decouples the event source from the SIEM. Any SIEM that accepts syslog can receive CNDS alerts without a custom integration — they just need to know how to parse CEF, which is universal. This makes CNDS compatible with legacy SIEM infrastructure that predates JSON-based APIs.

---

## 14. JWT and RBAC

### JSON Web Tokens (JWT)

A JWT is a compact, self-contained way to transmit claims between two parties as a JSON object, cryptographically signed to prevent tampering.

Structure:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9   ← Header (algorithm + type, Base64-encoded)
.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJhbmFseXN0IiwiZXhwIjoxNzQzMjc5OTIxfQ  ← Payload (claims, Base64-encoded)
.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c   ← Signature (HMAC-SHA256 of header+payload)
```

The payload contains **claims** — assertions about the user:
```json
{
  "sub": "alice",
  "role": "analyst",
  "exp": 1743279921
}
```

The server signs the token with `JWT_SECRET`. Anyone can decode the payload (it is just Base64), but cannot forge a valid signature without the secret. The server verifies the signature on every request — no session state needed.

**Expiry:** Tokens contain an `exp` (expiration) timestamp. After `JWT_EXPIRE_MINUTES` (default: 60), the token is invalid and the user must re-authenticate.

### Role-Based Access Control (RBAC)

RBAC restricts system access based on the **role** assigned to each user, rather than individual permissions. CNDS has three roles:

| Role | Who | What they can do |
|---|---|---|
| `viewer` | Read-only consumers (dashboards, reports) | Read alerts, incidents, stats |
| `analyst` | SOC tier-1/tier-2 | All viewer + acknowledge alerts, create incidents, manage suppression rules |
| `admin` | System administrators | All analyst + create/delete users, delete suppression rules |

Role is embedded in the JWT payload. FastAPI dependency functions check the role on each protected endpoint — an `analyst` trying to delete a user receives HTTP 403 Forbidden.

---

## 15. Monitoring Service and OpenTelemetry

### Monitoring Service

Monitoring Service is an open-source monitoring and alerting toolkit. It works on a **pull model**: Monitoring Service scrapes an HTTP endpoint (`/metrics`) at a configured interval and stores the time-series data in its own database.

Metrics are exposed in a simple text format:

```
# HELP cnds_alerts_total Total alerts fired by severity
# TYPE cnds_alerts_total counter
cnds_alerts_total{severity="high",attack_type="PortScan"} 42
cnds_alerts_total{severity="critical",attack_type="DoS Hulk"} 7
```

Three metric types:
- **Counter:** Monotonically increasing value (total packets processed, total alerts fired).
- **Gauge:** A value that can go up or down (current active flows, queue size).
- **Histogram:** Distribution of values (request latency, ensemble score distribution).

CNDS exposes a Monitoring Service endpoint at `/metrics` (when `Monitoring Service_ENABLED=true`). Monitoring Service scrapes it and Visualization Service visualizes it.

### OpenTelemetry (OTel)

OpenTelemetry is an observability framework that standardizes the collection of **traces**, **metrics**, and **logs** across distributed systems. A trace follows a single request through all the services it touches, measuring latency at each step.

In CNDS, OTel traces can track the path of a single packet from capture → feature extraction → engine inference → ensemble → storage, with timing at each stage. This enables identifying which engine is slow or which packet patterns cause excessive processing time.

OTel is configured via `OTEL_EXPORTER_OTLP_ENDPOINT` — point it at a collector (Jaeger, Tempo, etc.) to start receiving traces.

---

## 16. TCP Flags

TCP flags are control bits in the TCP header that indicate the purpose of a packet. Understanding them is essential for interpreting the flow features and rules in CNDS.

| Flag | Bit | Meaning | Attack relevance |
|---|---|---|---|
| **SYN** | 0x02 | Initiate connection | SYN flood (DoS), SYN scan (port scan) |
| **ACK** | 0x10 | Acknowledge data or connection | ACK scan (firewall evasion) |
| **FIN** | 0x01 | Gracefully close connection | FIN scan |
| **RST** | 0x04 | Abruptly reset connection | Port closed response; RST injection |
| **PSH** | 0x08 | Deliver data to application immediately | High PSH count → many small data packets |
| **URG** | 0x20 | Urgent pointer is valid | Rarely used legitimately; flag in malicious traffic |
| **CWR** | 0x80 | Congestion Window Reduced | Congestion control |
| **ECE** | 0x40 | ECN Echo | Congestion notification |

### In CNDS

CNDS counts cumulative TCP flags across all packets of a flow and includes them as features. The most detection-relevant combinations:

**SYN scan pattern:**
- `syn_flag_cnt` is high (many connection attempts)
- `ack_flag_cnt` is near zero (connections never complete — server is not responding or RSTs immediately)
- `tot_fwd_pkts` is very low (only SYN sent, never continued)

This pattern is exactly what `PORT_SCAN_THRESHOLD` targets in the Rules Engine: `syn_flag_cnt > 20 AND tot_fwd_pkts < 5`.

**Normal HTTP connection:**
- SYN (client initiates) → SYN-ACK (server responds) → ACK (client completes)
- PSH+ACK (client sends request) → PSH+ACK (server sends response)
- FIN+ACK → ACK (graceful close)
- `ack_flag_cnt` dominates; `syn_flag_cnt = 1`; `fin_flag_cnt = 1`

---

## 17. Scapy

### What it is

Scapy is a powerful Python library for crafting, sending, capturing, and dissecting network packets. It operates at the raw socket level, giving full access to every byte of every packet including headers that higher-level libraries abstract away.

Scapy's packet model is a stack of **layers**, each representing a protocol:

```python
from scapy.all import IP, TCP, Raw

pkt = IP(src="[INTERNAL_IP]", dst="10.0.0.5") / TCP(sport=54321, dport=443, flags="S") / Raw(b"payload")
```

Each layer (`/`) stacks on top of the previous, and Scapy automatically fills in fields like checksums and lengths.

### In CNDS

CNDS uses Scapy in two ways:

**Live capture:** `scapy.sniff()` captures raw packets from the network interface. This is why CNDS requires `root` or `CAP_NET_RAW` — raw socket access is a privileged operation.

```python
from scapy.all import sniff
sniff(iface="eth0", prn=callback, store=False)
```

**Demo traffic generation:** `demo/generate_traffic.py` uses Scapy to construct synthetic packets with specific properties (source/destination IPs, ports, flags, payloads) and write them to PCAP files. This is how the digital twin creates realistic-looking attack traffic without a real attacker.

### Why raw sockets require root

Normal applications use the kernel's network stack — they send data through a socket, the kernel adds IP and TCP headers. Raw sockets bypass this: the application reads packets before the kernel processes them (for capture) or writes complete packets including headers (for injection). This is powerful enough to be dangerous, hence the privilege requirement.

---

## 18. Alembic and Database Migrations

### The schema evolution problem

A database schema (the definition of tables, columns, types, and constraints) needs to evolve as the application evolves. The problem: if you just `ALTER TABLE` in production manually, there is no record of what changed, no way to roll back, and no way to apply the same change to staging or a colleague's development environment.

### Database migrations

A migration is a versioned, reversible description of a schema change. Each migration has:
- An **upgrade** function (apply the change)
- A **downgrade** function (undo the change)
- A unique revision ID
- A parent revision ID (forming a chain)

### Alembic

Alembic is the standard migration tool for SQLAlchemy (the Python ORM used by CNDS). Migration files live in `alembic/versions/`. Each file is named with its revision ID and a human-readable description.

**CNDS's two migrations:**

```
72da55e575e8_initial_schema.py      ← creates alerts, incidents, suppression_rules, users
a1b2c3d4e5f6_add_mitre_techniques.py ← adds mitre_techniques JSON column to alerts
```

**Common commands:**

```bash
alembic upgrade head       # apply all pending migrations (run at deployment)
alembic downgrade -1       # roll back one migration
alembic current            # show current schema version
alembic history            # show migration chain
alembic revision --autogenerate -m "add_new_column"  # generate new migration from model diff
```

Alembic runs automatically at CNDS startup (in `src/api/database.py`), so fresh deployments and upgrades self-migrate without manual intervention.

---

## 19. ML Tracking

### What it is

ML Tracking is an open-source platform for managing the machine learning lifecycle. It has four main components:

- **Tracking:** Log parameters, metrics, artifacts, and code version for every training run.
- **Projects:** Package ML code for reproducible execution.
- **Models:** Store models in a standardized format with their dependencies.
- **Registry:** Version control for production models, with stage transitions (None → Staging → Production → Archived).

### Why it matters for CNDS

CNDS uses three ML models — the supervised classifier (FT-Transformer or Random Forest fallback), Isolation Forest, and LSTM Autoencoder. Without version control, you end up with files named `rf_model_v2_final_REAL.joblib` and no reliable way to know which version is in production, what metrics it achieved, or how to roll back if a new model regresses.

ML Tracking solves this:
- Every training run logs its hyperparameters, training metrics (accuracy, F1, threshold), and the model artifact.
- The Registry provides a promotion workflow: train → register → test in Staging → promote to Production.
- CNDS's engine loaders check ML Tracking first (`load_latest("supervised")`) and fall back to local files if ML Tracking is not configured.

### Model lifecycle in CNDS

```
Training run
    │ joblib.dump() / torch.save()
    │ ML Tracking_registry.log_model()
    ▼
ML Tracking Registry
    │ Stage: "None"  ← just registered
    │
    │ (validate with pcap_replay.py)
    │ ML Tracking models transition
    ▼
    │ Stage: "Staging"  ← under test
    │
    │ (A/B comparison, analyst review)
    │ ML Tracking models transition
    ▼
    │ Stage: "Production"  ← CNDS loads this on restart
    │
    │ (after next model iteration)
    ▼
    │ Stage: "Archived"
```

When `ML Tracking_TRACKING_URI` is empty, the entire registry layer is skipped silently and models are loaded from local files — useful for development and air-gapped environments.

---

## 20. Glossary of Attack Types

The following attack types appear in CNDS alerts as the `attack_type` field, sourced from the UNSW-NB15 label space (10 classes) used by the supervised classifier — the FT-Transformer in production, or the Random Forest fallback when no FT checkpoint is present.

### Denial of Service (DoS)

DoS attacks overwhelm a target with traffic to exhaust its resources (CPU, memory, bandwidth, connection table) and make it unavailable to legitimate users.

| Label | Tool / Technique | Mechanism |
|---|---|---|
| **DoS Hulk** | HULK tool | Generates unique HTTP requests with random headers to bypass caching and exhaust the web server's thread pool |
| **DoS GoldenEye** | GoldenEye tool | HTTP KeepAlive + cache control headers to keep connections open |
| **DoS Slowloris** | Slowloris tool | Opens many HTTP connections and sends headers slowly (one byte at a time) to hold the connection slots without completing requests |
| **DoS Slowhttptest** | Slowhttptest | Similar to Slowloris but targets POST body transmission |

**Why four DoS types instead of one?** They have distinct flow signatures. Hulk generates high packet rates with variable sizes. Slowloris generates very low packet rates with tiny packets and very long durations. The RF learns these patterns separately.

### Port Scanning

| Label | Technique |
|---|---|
| **PortScan** | TCP SYN scan (nmap -sS) — sends SYN to each port; if RST received, port is closed; if no response, port is filtered; if SYN-ACK, port is open (RST is immediately sent to not complete the handshake) |

### Brute Force

| Label | Target | Tool |
|---|---|---|
| **FTP-Patator** | FTP authentication | Patator tool |
| **SSH-Patator** | SSH authentication | Patator tool |
| **Web Attack – Brute Force** | HTTP login forms | Custom scripts |

### Web Application Attacks

| Label | Attack | Description |
|---|---|---|
| **Web Attack – SQL Injection** | SQLi | Injecting SQL code into HTTP parameters to manipulate the database (e.g., `' OR '1'='1`) |
| **Web Attack – XSS** | Cross-Site Scripting | Injecting JavaScript into web pages to execute in victims' browsers (e.g., `<script>alert(1)</script>`) |

### Advanced / Persistent

| Label | Description |
|---|---|
| **Bot** | Botnet command-and-control traffic — the compromised machine periodically contacts the C2 server for instructions. Characterized by regular small HTTP/HTTPS flows to unusual destinations |
| **Infiltration** | Network infiltration — the attacker has already gained access and is using the network for lateral movement or data staging. Generates diverse anomalous internal traffic |
| **Heartbleed** | CVE-2014-0160 — a vulnerability in OpenSSL's heartbeat extension that allows reading up to 64 KB of server memory per malicious request, leaking private keys, passwords, and session tokens |

### Common Indicators in Flow Features

| Attack | Key flow features |
|---|---|
| DoS Hulk | `flow_pkts_s` very high, `flow_iat_mean` near zero, `fwd_pkt_len_mean` variable |
| Slowloris | `flow_duration` very long (hours), `fwd_pkts_s` very low, `init_fwd_win_byts` small |
| PortScan | `syn_flag_cnt` high, `tot_fwd_pkts` < 3, `flow_duration` very short |
| SSH Brute Force | `dst_port = 22`, many short flows with identical byte sizes, high `flow_pkts_s` |
| SQLi / XSS | Payload pattern match flags, `fwd_pkt_len_mean` elevated (longer HTTP request) |
| Bot (C2) | Regular `flow_iat_mean`, `bot_ratio` (unusual ratio), consistent small sizes |
