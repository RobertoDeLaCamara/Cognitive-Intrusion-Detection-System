# CNDS — Product & Commercial Overview

## What is CNDS?

**Cognitive Network Defense System (CNDS)** is an open-source network intrusion detection system (IDS), at home-lab maturity, that fuses machine learning and rule-based analysis into a single platform. It passively monitors network traffic, scores every flow when it ends (after `FLOW_TIMEOUT` seconds without packets, 120 by default), enriches every alert with MITRE ATT&CK context, and exposes the results through a modern REST API and live dashboard.

CNDS is designed for home labs and small networks that want transparent, self-hosted threat detection, and for security engineers who want full transparency into how detections work.

---

## Problem Statement

Traditional network IDS tools suffer from one or more of these limitations:

| Problem | Traditional IDS | CNDS |
|---|---|---|
| High false-positive rates | Signature-only engines fire on every variation | Ensemble scoring filters weak signals |
| Blind spots for novel attacks | No ML component | Unsupervised engines detect zero-days |
| Slow/drift attacks missed | Stateless rules | LSTM sequences behavior over time |
| Opaque decisions | Black-box alerts | Per-engine scores, MITRE IDs, confidence |
| SOC alert fatigue | Raw counts with no context | Incident grouping, suppression, severity |
| No SIEM integration | Manual export | Splunk and Elastic configuration templates, a CEF syslog forwarder and a JSON/CSV export endpoint |
| Hard to customize | Vendor lock-in | Config-driven, open source, extendable |
| Detection without response | Analyst must act manually, even for obvious threats | Optional Guardian module auto-mitigates critical alerts with a whitelist and automatic rollback |

---

## Value Proposition

### For Security Operations Centers (SOC)
- **Fewer false positives**: Up to five detection signals are fused; a flow must register abnormally across several engines to generate a high-severity alert, unless it matches one of the signatures listed in `CRITICAL_RULES`, which always alert.
- **Faster triage**: Every alert includes attack type, MITRE technique IDs, geographic origin, TLS fingerprint, and engine-level confidence scores — analysts have context before they open the first ticket.
- **Incident correlation**: Alerts from the same source IP within a configurable window are automatically grouped into incidents. This applies to alerts submitted through `POST /api/predict`; alerts from the live detector are deduplicated per source and attack type but not grouped automatically.
- **Optional automated response**: The Guardian module (opt-in) can mitigate a critical alert the moment it fires — no analyst has to be awake at 3am for the obvious cases — with a device whitelist, a circuit breaker against alert storms, and a timed automatic rollback so a false positive is never a permanent lockout.

### For Security Architects
- **Defense-in-depth at the network layer**: Supervised classification, unsupervised anomaly detection, and temporal behavioral analysis cover different parts of the threat landscape without overlap.
- **MITRE ATT&CK alignment**: Every detection is tagged with technique IDs, enabling direct mapping to your organization's threat model and compliance frameworks.
- **Feedback-based weight suggestions**: Analyst feedback (TP/FP labels) feeds a suggested set of engine weights (`GET /api/adaptive-weights`). Applying them is a manual configuration change.

### For Engineering Teams
- **Modular architecture**: Each detection engine is a Python class implementing a typed `DetectionEngine` protocol — new engines can be added without touching other components.
- **Observability**: Prometheus metrics, OpenTelemetry tracing of the API, structured JSON logs, and a `/health` endpoint make CNDS a first-class citizen in modern infrastructure.
- **Database choice**: SQLite for development and testing; drop-in PostgreSQL support for production concurrent-writer workloads.

---

## Target Markets

### Primary

**Small-to-medium enterprises (SME)** without a dedicated network security team. CNDS starts with a single `docker-compose up`.

**Managed Security Service Providers (MSSP)** looking for a white-labelable, API-driven detection engine they can embed into their SOC platform.

**Security researchers and academic institutions** studying network traffic analysis, anomaly detection, or MITRE ATT&CK coverage — the modular design and full feature transparency make CNDS an ideal research platform.

### Secondary

**Critical infrastructure operators** (OT/ICS environments) that need passive monitoring without agents. CNDS needs no endpoint software: it captures from an interface that sees the traffic (a mirror port or TAP for traffic between other hosts). It has no OT/ICS protocol awareness.

**DevSecOps teams** embedding network inspection into CI/CD pipelines via the REST API. The `/api/predict` endpoint accepts pre-computed feature vectors, enabling integration into test environments.

**Red team / blue team exercises** using the digital twin demo to validate detection coverage against known attack scenarios before production deployment.

---

## Competitive Positioning

| Feature | Snort/Suricata | Zeek | Commercial NDR | CNDS |
|---|---|---|---|---|
| ML-based detection | Limited | Partial | Yes | Yes (one supervised model; the unsupervised engines are demo or experimental) |
| Signature-based rules | Yes | No | Yes | Yes |
| Temporal/behavioral analysis | No | Partial | Yes | Experimental (baseline engine) |
| MITRE ATT&CK enrichment | No | No | Yes | Yes |
| JA3 TLS fingerprinting | Plugins | Yes | Yes | Yes |
| REST API | No | No | Yes | Yes |
| Open source | Yes | Yes | No | Yes |
| Self-hosted | Yes | Yes | No | Yes |
| SIEM integration | Yes | Yes | Yes | Yes |
| Adaptive learning from feedback | No | No | Yes | Partial (analyst labels are collected; retraining is manual) |
| Digital twin / offline demo | No | No | No | Yes |
| Per-engine score transparency | No | No | No | Yes |
| Automated response (optional) | No | No | Yes (enterprise tier) | Yes |

The other columns are generalisations from public product documentation, not a benchmark, and no head-to-head detection test has been run. CNDS sits between free signature-based tools (Snort/Suricata) and commercial NDR platforms (Darktrace, ExtraHop, Vectra): it adds ML scoring, per-engine score transparency and open-source extensibility to a rules engine, at home-lab maturity. Its unsupervised baseline is experimental and the Isolation Forest / LSTM models bundled for demos are synthetic.

---

## Deployment Models

### On-Premises (Primary)
Standard deployment on a Linux server with a port mirror or TAP. No cloud dependency. All data stays on-site.

### Docker / Kubernetes
`docker-compose.yml` ships with PostgreSQL, the API, the detector and the dashboard (plus an optional `demo-seed` service). No Kubernetes manifests are provided.

### API-Only (Hybrid)
Organizations with existing capture infrastructure (Zeek, Arkime, NetFlow) can deploy CNDS in API-only mode and POST pre-extracted features to `/api/predict` for ensemble scoring without running the capture pipeline.

### Offline / Air-Gapped
The PCAP replay script (`scripts/pcap_replay.py`) and digital twin demo (`demo/`) run without network access or root privileges — suitable for air-gapped environments.

---

## Compliance and Standards Alignment

| Framework | Coverage |
|---|---|
| MITRE ATT&CK | Native — every alert includes technique IDs and tactics |
| NIST CSF | Detect (DE.CM): Continuous network monitoring. Respond (RS.MI): optional automated mitigation via the Guardian module |
| SOC 2 Type II | Supporting evidence only: alert history, incident tracking and the Guardian's `mitigation_actions` audit table. API user actions are not audit-logged |
| ISO 27001 | A.12.4 (logging), A.13.1 (network security management) |
| PCI DSS | Requirement 10 (log monitoring), 11.4 (intrusion detection) |
| GDPR | On-premises deployment keeps all traffic data within the organization |

These rows say which controls CNDS can contribute evidence to. CNDS has not been assessed or certified against any of these frameworks.

---

## Roadmap

Planned features, enhancements, and security improvements are tracked as GitHub Issues:
[github.com/RobertoDeLaCamara/Cognitive-Intrusion-Detection-System/issues](https://github.com/RobertoDeLaCamara/Cognitive-Intrusion-Detection-System/issues)

Milestones map to minor releases (v2.0, v3.0). MoSCoW priority labels are used to communicate delivery intent.

---

## Licensing and Deployment Rights

CNDS is an open-source portfolio project released under the GNU Affero General Public License v3 (see `LICENSE`). You may deploy and modify it; if you offer a modified version to users over a network, the AGPL requires you to make its source available to them. Of the ML models, only the small Random Forest (`models/rf_lite_model.joblib`) ships with the source; the FT-Transformer checkpoint and the Isolation Forest / LSTM weights must be trained or provided separately.
