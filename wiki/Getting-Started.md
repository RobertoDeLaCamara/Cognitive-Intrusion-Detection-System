# Getting Started

## Prerequisites

- Python 3.10+
- Root/sudo access (required for raw packet capture via Scapy)
- Docker & Docker Compose (optional, for containerised deployment)

## 1. Clone and Install

```bash
git clone https://github.com/RobertoDeLaCamara/Cognitive-Intrusion-Detection-System.git
cd Cognitive-Intrusion-Detection-System
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

## 2. Add Model Files

Model binaries are excluded from git. Copy your trained models into `models/`:

```bash
# Supervised engine — Random Forest Pipeline (76 features)
cp /path/to/rf_model.joblib               models/

# Isolation Forest + scaler
cp /path/to/isolation_forest.joblib       models/
cp /path/to/if_scaler.joblib              models/

# LSTM Autoencoder
cp /path/to/lstm_autoencoder.pt           models/
cp /path/to/lstm_config.json              models/   # tracked in git
```

CNDS works with any subset of models — missing engines are gracefully skipped and their ensemble weight is redistributed.

## 3. Run

### Live capture + detection (requires root)

```bash
sudo venv/bin/python main.py
```

### Specify a network interface

```bash
sudo venv/bin/python main.py --iface eth0
```

### Capture + REST API on port 8000

```bash
sudo venv/bin/python main.py --api
```

### API only (no live capture — useful for testing)

```bash
uvicorn src.api.main:app --host 0.0.0.0 --port 8000
```

### Stop after N seconds

```bash
sudo venv/bin/python main.py --duration 60
```

### Docker Compose

```bash
docker-compose up -d
# API:       http://localhost:8000
# Dashboard: http://localhost:8501
```

> **Note:** The default SQLite backend does not support concurrent writers. In Docker Compose, only the API service writes to the DB. For production multi-container setups, use PostgreSQL:
> ```
> DATABASE_URL=postgresql+asyncpg://user:pass@db:5432/cnds
> ```

## 4. Verify

```bash
# Health check — shows engine availability and capture stats
curl http://localhost:8000/health

# Swagger docs
open http://localhost:8000/docs
```

## 5. PCAP Replay (Offline Mode)

Replay a `.pcap` file for threat hunting or model evaluation:

```bash
python scripts/pcap_replay.py data/test.pcap --labels data/labels.csv --output results.json
```
