# How to Read This Documentation

The CNDS documentation is designed to be read in layers. Not every reader needs to reach the end — each section closes a complete arc of understanding before moving into the next level of detail.

---

## The story in five acts

### Act 0 — The vocabulary (optional but recommended)
**Read this if any term in the other documents stops you cold.**

> *What is MITRE ATT&CK? What is a flow? What is an LSTM? What does JA3 mean?*

**→ Read: [concepts.md](concepts.md)**

Twenty self-contained explanations of every concept the rest of the documentation assumes you know: MITRE ATT&CK (what it is, how it is structured, which techniques CNDS maps), network flows and the 5-tuple, CICFlowMeter and the CIC-IDS2017 dataset, JA3 TLS fingerprinting, Random Forest, Isolation Forest, LSTM Autoencoders, ensemble methods, confidence calibration, Shannon entropy, SIEM platforms, CEF syslog, JWT and RBAC, Prometheus, TCP flags, Scapy, Alembic migrations, MLflow, and a glossary of every attack type that appears in CNDS alerts.

You do not need to read this document front to back. It is a reference — come back to it whenever a term in another document is unfamiliar.

---

### Act I — The problem and the bet
**Start here if you are new to the system.**

> *Why does CNDS exist? What do existing tools fail to solve? Who is it for?*

**→ Read: [product.md](product.md)**

This document sets the context. CNDS was born from a gap: free intrusion detection tools (Snort, Suricata) are signature-based and blind to unknown attacks; commercial ML solutions (Darktrace, Vectra) are black boxes with inaccessible price tags. CNDS bets on combining four detection engines — two supervised, two unsupervised — with full transparency into how and why each alert fires.

After reading this document you will understand the *purpose* of the system and who it protects.

---

### Act II — The architecture: how a packet travels from the network to an alert
**Read this if you want to understand how the pieces fit together.**

> *What happens to a network packet from the moment it arrives at the interface until it appears as an alert on the dashboard?*

**→ Read: [architecture.md](architecture.md)**

This document tells the story of the packet. It enters raw from Scapy, passes through an async queue system, gets decomposed into three feature representations (flow, host, payload), runs through four detection engines in parallel, and emerges as an `EnsembleResult` object with a weighted score, an attack label, and the corresponding MITRE techniques — all before being persisted and broadcast.

The architecture includes a full ASCII diagram of the pipeline, the database schema table, the thread concurrency model, and the degradation modes when a model is unavailable.

After this document you will have a complete mental map of the system.

---

### Act III — The models: the intelligence behind detection
**This act has two readings depending on your technical depth.**

> *How does each detection engine work? What signals does it capture that the others cannot?*

**→ Read first: [engines.md](engines.md)**

A half-hour read that covers all four engines — Random Forest, Isolation Forest, LSTM Autoencoder, Rules Engine — with their characteristics, strengths, limitations, and how their scores are fused in the ensemble. Includes temperature calibration logic and severity classification. Sufficient to understand what the system detects and why.

> *How are those models trained? How are they retrained? What data do they need?*

**→ Read next: [ml-models.md](ml-models.md)**

The most technical and dense document in the collection. It goes to code level for each model: the 76 CICFlowMeter features with their exact indices and calculation formulas, the Isolation Forest sigmoid normalization, the per-IP FIFO buffers of the LSTM, the PyTorch autoencoder architecture, the exact hyperparameters of the production model, step-by-step procedures for training and retraining each model, and the MLflow version lifecycle.

This document is the reference for when you need to intervene in the models — whether to adapt the system to a new network, add an attack class, or diagnose performance degradation.

---

### Act IV — The system in use: how an analyst works with CNDS
**Read this to understand the operational value in concrete scenarios.**

> *How does CNDS detect a DoS? A port scan? Slow exfiltration? How does an analyst manage false positives?*

**→ Read: [use-cases.md](use-cases.md)**

Fifteen scenarios narrated end to end: the analyst receives the alert, sees each engine's score, understands why it fired, and acts. From triaging a `high`-severity alert with MITRE context to suppressing an authorized vulnerability scanner, through integration with Zeek/Arkime, incident management, and adaptive weight tuning from team feedback.

After this document you will know what to do with the system on day one of operations.

---

### Act V — Installation, the demo, and the APIs
**Read these documents when you are ready to deploy or integrate.**

The three final documents are operational references. Read them in any order depending on your immediate task:

> *I want to see the system working without deploying anything to production.*

**→ Read: [digital-twin-sandbox.md](digital-twin-sandbox.md)**

The digital twin is a simulated network (router, NAS, Gitea, Docker registry, workstation) with Scapy-generated synthetic traffic. No root, no database, no models needed. The demo runs five attack scenarios and produces a detection report. It also documents how to extend the twin with new devices and scenarios, and how to use the PCAP replay script to evaluate models against real captures.

> *I want to integrate CNDS into my stack or build something on top of it.*

**→ Read: [api-reference.md](api-reference.md)**

Complete reference for every REST and WebSocket endpoint: alerts, incidents, manual prediction, statistics, suppression rules, adaptive weights, JWT/RBAC authentication, Prometheus metrics. Includes JSON request/response examples for every operation.

> *I want to install it in production.*

**→ Read: [deployment.md](deployment.md)**

From prerequisites to production hardening: local and Docker Compose installation, every configuration variable with its effect, PostgreSQL and Alembic setup, GeoIP and SIEM configuration, systemd service, monitoring with key metrics and what to do when they spike.

---

## Reading paths by profile

Three suggested paths depending on your starting point:

**Executive / PM (30 minutes)**
```
product.md → use-cases.md (cases 1, 2, 10 only) → digital-twin-sandbox.md (demo section only)
```

**Engineer joining the project (2–3 hours)**
```
concepts.md (skim) → product.md → architecture.md → engines.md → use-cases.md → deployment.md → api-reference.md
```

**ML engineer / data scientist (3–4 hours)**
```
concepts.md (sections 3, 4, 6, 7, 8, 9, 10, 11) → architecture.md (Feature Extraction section) → engines.md → ml-models.md (full) → digital-twin-sandbox.md → deployment.md (Model Files section)
```

**Security analyst with no ML background (2 hours)**
```
concepts.md (sections 1, 2, 5, 13, 16, 20) → product.md → use-cases.md (full) → api-reference.md
```

---

## Dependency map between documents

```
product.md
    │
    └──→ architecture.md
              │
              ├──→ engines.md
              │         │
              │         └──→ ml-models.md
              │
              ├──→ use-cases.md
              │         │
              │         └──→ api-reference.md
              │
              ├──→ digital-twin-sandbox.md
              │
              └──→ deployment.md
```

Each document assumes you have read the ones above it in the tree. In particular, `ml-models.md` assumes you know the overall architecture (from `architecture.md`) and the role of each engine (from `engines.md`); and `use-cases.md` becomes much richer if you have already read `architecture.md`, because you can follow exactly which engine fired and why.
