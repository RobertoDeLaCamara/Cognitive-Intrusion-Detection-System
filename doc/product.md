# CNDS — Product & Commercial Overview

## What is CNDS?

**Cognitive Network Defense System (CNDS)** is an open-source, production-ready network intrusion detection system (IDS) that fuses machine learning and rule-based analysis into a single real-time platform. It passively monitors network traffic, classifies threats with millisecond latency, enriches every alert with MITRE ATT&CK context, and exposes the results through a modern REST API and live dashboard.

CNDS is designed for organizations that need enterprise-grade threat detection without the enterprise price tag, and for security engineers who want full transparency into how detections work.

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
| No SIEM integration | Manual export | Splunk HEC, Elastic, CEF out of the box |
| Hard to customize | Vendor lock-in | Config-driven, open source, extendable |

---

## Value Proposition

### For Security Operations Centers (SOC)
- **Fewer false positives**: Four independent detection signals are fused; a packet must register abnormally across multiple engines to generate a high-severity alert.
- **Faster triage**: Every alert includes attack type, MITRE technique IDs, geographic origin, TLS fingerprint, and engine-level confidence scores — analysts have context before they open the first ticket.
- **Incident correlation**: Alerts from the same source IP within a configurable window are automatically grouped into incidents, preventing alert storms from the same attacker.

### For Security Architects
- **Defense-in-depth at the network layer**: Supervised classification, unsupervised anomaly detection, and temporal behavioral analysis cover different parts of the threat landscape without overlap.
- **MITRE ATT&CK alignment**: Every detection is tagged with technique IDs, enabling direct mapping to your organization's threat model and compliance frameworks.
- **Adaptive learning**: Analyst feedback (TP/FP labels) flows back into ensemble weight adjustments, so the system improves over time on your specific network.

### For Engineering Teams
- **Modular architecture**: Each detection engine is a Python class implementing a typed `DetectionEngine` protocol — new engines can be added without touching other components.
- **Full observability**: Monitoring Service metrics, OpenTelemetry tracing, structured JSON logs, and a `/health` endpoint make CNDS a first-class citizen in modern infrastructure.
- **Database choice**: SQLite for development and testing; drop-in PostgreSQL support for production concurrent-writer workloads.

---

## Target Markets

### Primary

**Small-to-medium enterprises (SME)** without a dedicated network security team. CNDS provides professional-grade visibility with a single `docker-compose up`.

**Managed Security Service Providers (MSSP)** looking for a white-labelable, API-driven detection engine they can embed into their SOC platform.

**Security researchers and academic institutions** studying network traffic analysis, anomaly detection, or MITRE ATT&CK coverage — the modular design and full feature transparency make CNDS an ideal research platform.

### Secondary

**Critical infrastructure operators** (OT/ICS environments) that need passive monitoring without agents. CNDS requires only raw socket access — no endpoint software, no network taps.

**DevSecOps teams** embedding network inspection into CI/CD pipelines via the REST API. The `/api/predict` endpoint accepts pre-computed feature vectors, enabling integration into test environments.

**Red team / blue team exercises** using the digital twin demo to validate detection coverage against known attack scenarios before production deployment.

---

## Competitive Positioning

| Feature | Snort/Suricata | Zeek | Commercial NDR | CNDS |
|---|---|---|---|---|
| ML-based detection | No | Partial | Yes | Yes |
| Signature-based rules | Yes | No | Yes | Yes |
| Temporal/behavioral analysis | No | Partial | Yes | Yes |
| MITRE ATT&CK enrichment | No | No | Yes | Yes |
| JA3 TLS fingerprinting | Plugins | Yes | Yes | Yes |
| REST API | No | No | Yes | Yes |
| Open source | Yes | Yes | No | Yes |
| Self-hosted | Yes | Yes | No | Yes |
| SIEM integration | Yes | Yes | Yes | Yes |
| Adaptive learning from feedback | No | No | Yes | Yes |
| Digital twin / offline demo | No | No | No | Yes |
| Per-engine score transparency | No | No | No | Yes |

CNDS occupies the space between free signature-based tools (Snort/Suricata) and expensive commercial NDR platforms (Darktrace, ExtraHop, Vectra). It delivers ML-grade detection with the transparency and extensibility of open-source tooling.

---

## Deployment Models

### On-Premises (Primary)
Standard deployment on a Linux server with a port mirror or TAP. No cloud dependency. All data stays on-site.

### Docker / Kubernetes
`docker-compose.yml` ships with three services (detector, API, dashboard). Kubernetes deployment follows the same three-container pattern with a shared volume for model files.

### API-Only (Hybrid)
Organizations with existing capture infrastructure (Zeek, Arkime, NetFlow) can deploy CNDS in API-only mode and POST pre-extracted features to `/api/predict` for ensemble scoring without running the capture pipeline.

### Offline / Air-Gapped
The PCAP replay script (`scripts/pcap_replay.py`) and digital twin demo (`demo/`) run without network access or root privileges — suitable for air-gapped environments and classified networks.

---

## Compliance and Standards Alignment

| Framework | Coverage |
|---|---|
| MITRE ATT&CK | Native — every alert includes technique IDs and tactics |
| NIST CSF | Detect (DE.CM): Continuous network monitoring |
| SOC 2 Type II | Audit trail via alert history, user actions, incident tracking |
| ISO 27001 | A.12.4 (logging), A.13.1 (network security management) |
| PCI DSS | Requirement 10 (log monitoring), 11.4 (intrusion detection) |
| GDPR | On-premises deployment keeps all traffic data within the organization |

---

## Roadmap

Planned features, enhancements, and security improvements are tracked as GitHub Issues:
[github.com/RobertoDeLaCamara/Cognitive-Intrusion-Detection-System/issues](https://github.com/RobertoDeLaCamara/Cognitive-Intrusion-Detection-System/issues)

Milestones map to minor releases (v2.0, v3.0). MoSCoW priority labels are used to communicate delivery intent.

---

## Licensing and Deployment Rights

CNDS is an open-source portfolio project. Deployment, modification, and integration into commercial systems is permitted. Binary ML model files are not distributed with the source code and must be trained or provided separately.
