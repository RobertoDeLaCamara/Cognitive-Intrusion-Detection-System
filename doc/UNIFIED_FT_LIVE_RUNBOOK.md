# Unified FT-Transformer — Live capture runbook

End-to-end manual test for the unified ML-IDS+cnds FT-Transformer engine on
real traffic. This is the step beyond the offline smoke test
(`scripts/smoke_test_ft_unified.py`) and the integration tests
(`tests/test_ft_transformer_engine.py`).

## Pre-flight

Confirm the model and scaler are present and the engine loads without errors:

```bash
ls -lh models/unified/
# Expect:
#   unified_ft_transformer.pt   (≈6.5 MB)
#   unified_scaler.pkl          (≈2.4 KB)
#   unified_metadata.json       (≈11 KB)

python -m pytest tests/test_ft_transformer_engine.py -v
# 7 passed
```

The shared conftest disables FT auto-load in tests via `FT_MODEL_FILE`
override; that does not affect production runs of `main.py`.

## Capture interface

On Hawkeye (this host, WSL2), choose an interface that actually carries
traffic. `eth0`/`eth4` map to the host adapter via WSL2's mirrored
networking. For a clean test, ssh in from another host (e.g. raspi-62)
to generate inbound traffic, or generate from this same host to a LAN
target so the loopback shortcut isn't taken.

```bash
ip -4 addr | awk '/inet /{print $NF, $2}'
# Pick the iface bound to 192.168.1.49.
```

## Start cnds with the FT engine

```bash
cd /home/roberto/repos/cnds
# venv: torch CPU build + the rest of cnds requirements
source venv/bin/activate

# Make MLflow + MinIO reachable so the engine can fall back to
# the registry (the local checkpoint takes priority anyway).
export MLFLOW_TRACKING_URI=http://192.168.1.147:5050
export MLFLOW_S3_ENDPOINT_URL=http://192.168.1.189:9000
export AWS_ACCESS_KEY_ID=roberto
export AWS_SECRET_ACCESS_KEY=patilla1
# The proxy must be bypassed for all 192.168.1.x traffic.
export NO_PROXY=localhost,127.0.0.1,192.168.1.0/24
export no_proxy=$NO_PROXY

# WEIGHT_FT default rides on the existing supervised slot.
sudo --preserve-env=MLFLOW_TRACKING_URI,MLFLOW_S3_ENDPOINT_URL,AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY,NO_PROXY,no_proxy \
  venv/bin/python main.py --iface eth4 --api --duration 600
```

Look for these log lines on startup:

```
INFO src.engines.ft_transformer_engine: FTTransformerEngine: loaded ...
INFO src.engines.ft_transformer_engine: FTTransformerEngine ready  device=cpu  features=76  classes=10  benign_idx=0
```

If you see `FTTransformerEngine disabled` instead, the engine fell back to
the legacy `SupervisedEngine`. Check the model paths and torch install.

## Generate baseline benign traffic (≥30 s)

Browse normally, ssh, fetch a few URLs:

```bash
curl -s https://www.google.com >/dev/null
curl -s https://github.com >/dev/null
ping -c 5 8.8.8.8
```

Expect: no alerts in the cnds log, or only low-severity rule-based ones.
Tail the log:

```bash
tail -F /tmp/cnds_*.log 2>/dev/null || journalctl --user -fn 100
```

## Generate synthetic attacks

### SYN flood (target: a non-production host)

```bash
sudo hping3 -S -p 80 --flood -c 200 192.168.1.62
```

Expected detection: `attack_type=DoS` (class 3) with high `score`.

### Port scan

```bash
sudo nmap -sS -p 1-1000 -T4 192.168.1.62
```

Expected detection: `attack_type=Reconnaissance` (class 7) and the
`port_scan` rule firing.

### UDP fuzzing

```bash
sudo hping3 --udp -p 53 --rand-source --flood -c 500 192.168.1.62
```

Expected detection: `attack_type=Fuzzers` (class 5) — small datasets
sometimes mislabel as DoS.

## Validation checklist

After each attack:

- [ ] cnds logged `[ALERT]` with `engines=[..., 'supervised', ...]`
- [ ] `attack_type` matches expectation ±1 class (Fuzzers/DoS often
  blur on synthetic flows)
- [ ] `ensemble_score >= 0.55` (default threshold)
- [ ] Alert visible at `GET http://localhost:8000/api/alerts`
- [ ] Alert persisted in `cnds.db` (`sqlite3 cnds.db "SELECT
  attack_type, severity, ensemble_score FROM alerts ORDER BY id DESC LIMIT
  10;"`)

## Cleanup

```bash
# Stop cnds
# Reset any iface state if needed
# Optionally drop the test alerts from the DB
sqlite3 cnds.db "DELETE FROM alerts WHERE attack_type IN ('DoS','Reconnaissance','Fuzzers') AND timestamp > datetime('now','-1 hour');"
```

## Troubleshooting

- **No flows complete during capture** — the default `FLOW_TIMEOUT` is 120 s.
  For faster feedback set `FLOW_TIMEOUT=15` in the env before launching.
- **`FTTransformerEngine disabled`** despite the file being present — most
  likely a torch import failure. Run `python -c "import torch; print(torch.__version__)"`.
- **Alerts don't include `supervised`** in the engines list — the engine is
  loaded but `is_available` is False, or the predicted label was `Benign`.
  Confirm with `curl http://localhost:8000/health` and the startup logs.
- **WSL2 capture sees no traffic** — WSL2's mirrored networking only
  exposes the host's outbound, not arbitrary inbound. Use an attack target
  that is reachable from WSL2 (e.g. raspi-62) and generate the attack from
  this host outward.
