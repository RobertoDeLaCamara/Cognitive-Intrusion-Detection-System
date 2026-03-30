# When Your IDS Lies to You: Designing for Calibration, Not Just Accuracy

*ACM Queue / IEEE Security & Privacy practitioner style*

---

Every network security team has lived through the same scenario. The detection model hits 97% accuracy on the benchmark dataset. It goes to production. Within days, the alert queue is thousands of entries deep, the on-call engineer is drowning, and the slow credential-stuffing attack that started four days ago is buried under a wall of false positives from a legitimate internal vulnerability scanner.

The problem is not accuracy. The problem is **calibration** — the gap between what a model thinks it knows and how certain it actually is. And the second problem is **coverage**: a single model trained on one dataset cannot, by construction, detect attack patterns that weren't in that dataset.

CNDS (Cognitive Network Defense System) was designed around these two constraints. This article focuses on the architectural decisions that address them: how the four-engine ensemble handles calibration, how graceful degradation prevents coverage gaps at runtime, and what the system gets wrong that practitioners should know about before deploying it.

---

## Calibration Is Not Accuracy

A classifier is well-calibrated if, among all samples where it predicts 70% probability of an attack, approximately 70% of those samples are actually attacks. Most trained classifiers are not well-calibrated — they tend to be overconfident.

This matters for two operational reasons:

**Threshold setting.** In a production IDS, you need to pick a threshold above which an alert fires. If your model is miscalibrated and clusters predictions near 0.95 regardless of actual confidence, you cannot distinguish between "probably an attack" and "almost certainly an attack." You end up with a binary classifier in disguise — everything above 0.5 fires equally, and you cannot tune the precision/recall tradeoff.

**Alert prioritization.** If an analyst can trust that a score of 0.90 means something qualitatively different from 0.65, they can prioritize their queue. If the scores are meaningless as probabilities, the queue is first-in-first-out with no prioritization signal.

CNDS applies temperature scaling after ensemble fusion:

```
calibrated_score = sigmoid(logit(raw_score) / T)
```

where `T` is `CALIBRATION_TEMPERATURE`, default 1.0 (identity). Temperature is fitted once against a held-out validation set with ground-truth labels using the Brier score as the objective. The result is a score distribution where the values carry probabilistic meaning — or at least are significantly better calibrated than the raw ensemble output.

The catch: temperature scaling requires labeled validation data with known attack ground truth. If you are deploying in an environment where you do not have labeled traffic (which is most production environments), you must either use the CIC-IDS2017 calibration estimate (which may not transfer) or set T=1.0 and treat scores as ordinal rankings rather than probabilities.

---

## The Four-Engine Coverage Model

The ensemble covers four distinct detection paradigms, each targeting threats that the others cannot see.

**Supervised classification (40%)** catches what it was trained to catch: the 14 attack classes in CIC-IDS2017. Its strength is precision — when it fires on a pattern it recognizes, it fires with high confidence and names the attack type. Its weakness is a hard boundary at the training distribution: anything novel is a blind spot.

**Isolation Forest (30%)** catches statistical deviations from the normal traffic baseline, regardless of attack type. No labels required, which means it generalizes beyond the training distribution by definition. Its weakness is that adversarial attackers who understand the feature space (packets/sec, protocol ratios, entropy) can craft traffic that blends into the baseline. Low-and-slow attacks that stay within normal feature ranges escape it.

**LSTM Autoencoder (20%)** catches temporal anomalies — behavioral state changes over time. A device that normally sends 20 packets/sec and then sustains 5000/sec for three minutes has high reconstruction error even if the sustained rate is "normal" in absolute terms for some other host. The Isolation Forest, which normalizes its sliding window, may not catch this. The LSTM's per-IP sequence buffer (20 steps by default) provides temporal memory that the other engines lack.

**Rule-based (10%)** catches known signatures immediately, at packet time, without waiting for flow expiry. The JA3 TLS fingerprinting is the operationally most valuable rule: matching a ClientHello against a blocklist of Cobalt Strike beacon fingerprints provides zero-latency, high-confidence C2 detection that no ML engine can replicate without similar training data.

The weights (40/30/20/10) are not derived from optimization — they encode a judgment about which failure modes matter more. Supervised gets the most weight because it provides the most actionable output (named attack types). IF gets the second-most because its coverage of unknown threats compensates for RF's training distribution limitation. LSTM gets less because it requires N samples per IP before it produces any score, making it unavailable for new or rare source IPs. Rules get the least because their recall is fundamentally bounded by what a human explicitly wrote a rule for.

---

## Graceful Degradation: The Part Most Systems Get Wrong

In any production environment, engines will be unavailable. The LSTM score is unavailable for source IPs with fewer than `LSTM_SEQUENCE_LENGTH` (default 20) samples in the buffer — which means every new IP that appears for the first time produces no LSTM score. The RF model may not be loaded if the binary file is absent. The Isolation Forest score is unavailable if host features cannot be extracted (e.g., too few packets in the window).

A naive implementation sets missing scores to zero. This silently down-weights the remaining engines — a three-engine result where LSTM is unavailable gets scored as `0.40*RF + 0.30*IF + 0.20*0 + 0.10*Rules`, producing scores systematically lower than a four-engine result on identical traffic. The threshold becomes asymmetric: new source IPs are harder to trigger alerts on than established ones.

CNDS redistributes unavailable engine weights proportionally:

```python
active = {e: w for e, w in weights.items() if scores[e] is not None}
total = sum(active.values())
adjusted = {e: w / total for e, w in active.items()}
final_score = sum(scores[e] * adjusted[e] for e in active)
```

When only RF and IF are available (e.g., a new IP on its first flow), the effective weights become 0.57 and 0.43 — preserving the relative proportion of available evidence. A 0.70 RF score from RF+IF+Rules produces the same severity classification as a 0.70 RF score from all four engines.

---

## Alert Fatigue: Two Independent Suppressors

CNDS addresses alert fatigue with two independent mechanisms operating at different granularities.

**Per-IP cooldown** (`ALERT_COOLDOWN_SECS`, default 60s) is a hard rate limit: once an alert fires for a source IP, subsequent alerts from the same IP are suppressed for 60 seconds regardless of severity or attack type. This prevents a single scanning IP from generating more than one alert per minute. The cooldown is not conditional on the alert type — it applies across all attack types from that IP.

**Deduplication window** (`DEDUP_WINDOW_SECS`, default 300s) is more granular: it deduplicates on `(src_ip, attack_type)` pairs over a 5-minute window. The same IP can generate alerts for different attack types — a host running both a port scan and an HTTP brute force generates separate PortScan and Brute-Force alerts. But the second PortScan alert from the same IP within 5 minutes is suppressed.

The two mechanisms interact in a specific order: cooldown check first (fast, O(1) hash lookup), deduplication check second (LRU cache lookup). Both happen before the GeoIP and MITRE enrichment, which are the expensive operations.

**Incident correlation** provides the aggregate view: if 5 or more alerts from the same source IP arrive within 300 seconds, an `Incident` record is created that groups them. Analysts see one investigation unit per attacker, not hundreds of individual flows.

The tradeoff in both suppressors is that a slow-and-low campaign that generates exactly one alert per 300-second window per attack type evades deduplication entirely — by design. The system is tuned for precision (analyst productivity) at the cost of recall on campaigns that deliberately operate below the deduplication threshold.

---

## The Async Write Boundary

One system design decision that affects operational behavior in ways that are not obvious: all alert persistence is asynchronous.

The detection pipeline runs in the packet capture thread. When a detection callback fires, it enqueues the alert to a bounded queue (capacity 1000) and returns immediately. A separate background writer thread drains the queue, performs GeoIP lookup, MITRE enrichment, and database write.

The operational consequence: **under sustained attack, alerts can be delayed or dropped**. If the writer thread cannot drain the queue as fast as detection fires (database saturation, GeoIP API timeout), the queue fills and new alerts are dropped — they never reach the database. The queue capacity (1000) gives approximately 1000 dropped alerts before the queue is re-drained.

The design priority here is explicit: packet processing must never block on I/O. Losing alert records is preferable to degrading detection latency. In practice, the bottleneck is almost always the database write under PostgreSQL, and increasing `ALERT_DB_POOL_SIZE` resolves it before the queue fills. But operators should monitor queue depth as an alert-in-itself.

---

## What the JA3 Engine Actually Does

The JA3 implementation is worth examining in detail because TLS fingerprinting is widely misunderstood.

A TLS ClientHello contains four fields that, when concatenated and MD5-hashed, produce the JA3 fingerprint: TLS version, cipher suites, extensions, elliptic curves, and point formats. These fields are stable for a given TLS client library version — a Cobalt Strike beacon compiled against a specific version of OpenSSL will produce the same JA3 hash regardless of what it is communicating with or from what IP.

CNDS implements the full JA3 specification:
1. Binary parse of the TLS record (not regex — exact byte offsets)
2. GREASE value filtering: values matching `0x?A?A` (per RFC 8701) are removed before hashing
3. MD5 hash of the concatenated string
4. Lookup against `MALICIOUS_JA3_FILE` (configurable blocklist)

The GREASE filtering is critical. Without it, GREASE-aware TLS clients (modern Chrome, Firefox) produce different fingerprints across connections because GREASE values are randomized. Filtering GREASE stabilizes fingerprints for benign clients while preserving stable fingerprints for malicious tools that do not implement GREASE.

The limitation: JA3 fingerprints for widely-used tools (Cobalt Strike, Metasploit) are public and well-known. Sophisticated actors have been rotating JA3 fingerprints for years by compiling custom OpenSSL configurations. The rule engine provides high-confidence detection of unsophisticated or commodity tooling; it should not be relied upon for detecting targeted actors.

---

## MITRE ATT&CK Enrichment: Operational Reality

Every alert in CNDS is enriched with ATT&CK technique IDs at write time. The enrichment maps RF attack types and triggered rule names to technique IDs and tactics.

The operational value is specific: SOC teams that have playbooks organized by ATT&CK tactic (Initial Access, Lateral Movement, Impact) can use ATT&CK IDs from CNDS alerts to trigger those playbooks directly. The Splunk `savedsearches.conf` included with CNDS provides pre-built correlation rules organized by tactic.

The limitation is equally specific: the mapping is static and does not capture the full ATT&CK technique hierarchy. A single attack can involve multiple sub-techniques; CNDS maps to the parent technique ID. This is intentional — sub-technique granularity requires behavioral data that flow-level detection cannot provide.

---

## What To Watch In Production

Three metrics that indicate the system is not performing correctly:

**Queue depth consistently above 500.** The async writer is falling behind. Database writes are the most common cause. Check PostgreSQL connection pool size and write latency before increasing queue capacity.

**LSTM coverage below 60% of alerts.** More than 40% of alerts are firing on source IPs with fewer than 20 packets in their buffer — the LSTM is not contributing to most detections. This usually means the network has a lot of short-lived connections. Reduce `LSTM_SEQUENCE_LENGTH` or accept that the LSTM engine provides only partial coverage on this network.

**Deduplication suppression rate above 80%.** The system is suppressing 80% of would-be alerts. Either the network has sustained scanning from a small set of sources (expected, working as designed), or `DEDUP_WINDOW_SECS` is too high and is suppressing legitimate alerts. Check whether the suppressed events are from repeat sources or from diverse IPs generating the same attack type.

---

## A Note on SQLite vs PostgreSQL

The default database backend is SQLite. The async writer serializes writes through an asyncio thread pool, which prevents write blocking from degrading the packet capture loop. But SQLite's single-writer model means that concurrent API reads during high-alert periods create lock contention that slows writes.

Switch to PostgreSQL before production:

```
DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/cnds
```

The schema migration is handled by Alembic. The async writer does not change — only the database URL. Under PostgreSQL, concurrent reads and writes are fully independent, and the connection pool can sustain hundreds of writes per second without contention.

---

*Full source available in the CNDS repository. See the Development Guide for model training instructions and the Enrichment-and-SIEM wiki page for SIEM integration configuration.*
