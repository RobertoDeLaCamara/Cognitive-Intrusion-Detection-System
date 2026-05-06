# CNDS Sandbox

End-to-end demo environment that exercises the full CNDS stack: detection engines,
REST API, WebSocket alerts, SIEM integration, and unsupervised baseline training.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  orchestrator.py                                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Traffic Gen  │  │ API Exerciser│  │  SIEM Mock   │  │
│  │ (50k+ pkts)  │  │ (18 endpoints)│  │ (CEF syslog) │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         │                  │                  │          │
│         ▼                  ▼                  ▼          │
│  ┌─────────────────────────────────────────────────┐    │
│  │           CNDS API + Detection Pipeline          │    │
│  │  (FastAPI · Engines · Ensemble · SQLite/PG)      │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Interactive demo (30+ min, triggers unsupervised training)
python sandbox/orchestrator.py --demo

# CI mode (2-5 min, fast assertions)
python sandbox/orchestrator.py --ci

# Docker Compose
docker compose -f docker-compose.sandbox.yml up
```

## Modes

| Mode | Duration | Traffic | Unsupervised Training | Output |
|------|----------|---------|----------------------|--------|
| `--ci` | ~3 min | 5k vectors, 10 IPs | Skipped | JSON report + exit code |
| `--demo` | 30+ min | 50k+ vectors, 20+ IPs | Full cycle | Live dashboard + alerts |

## Components

| File | Purpose |
|------|---------|
| `traffic/background.py` | Benign traffic from 20+ IPs, high port entropy |
| `traffic/scenarios.py` | Attack scenarios (extends `demo/generate_traffic.py`) |
| `api_exerciser/exerciser.py` | Hits all ~18 REST endpoints + validates responses |
| `api_exerciser/ws_client.py` | WebSocket `/ws/alerts` consumer |
| `siem_mock/receiver.py` | UDP syslog receiver, validates CEF format |
| `orchestrator.py` | Starts everything, coordinates phases, generates report |

## Relationship with `demo/`

The `demo/` folder is a quick offline detection test (~5 seconds, no API).
The sandbox **imports and extends** its scenarios for full end-to-end coverage.
