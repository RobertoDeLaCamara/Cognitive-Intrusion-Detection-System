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
# passes (2 dataset-backed tests skip unless CNDS_TEST_DATA_DIR is set)
```

The shared conftest disables FT auto-load in tests via `FT_MODEL_FILE`
override; that does not affect production runs of `main.py`.

## Capture interface

Choose an interface that actually carries traffic. Under WSL2 with mirrored
networking, `eth0`/`eth4` map to the host adapter. For a clean test, ssh in
from another host to generate inbound traffic, or generate from the capture
host to a LAN target so the loopback shortcut isn't taken.

```bash
ip -4 addr | awk '/inet /{print $NF, $2}'
# Pick the iface bound to your local subnet.
```

## Start cnds with the FT engine

```bash
cd /path/to/cnds
# venv: torch CPU build + the rest of cnds requirements
source venv/bin/activate

# Optional: MLflow + MinIO. With MLFLOW_TRACKING_URI set, the engine tries the
# registry first and uses the local checkpoint when the registry has no model.
export MLFLOW_TRACKING_URI=http://your-mlflow-host:5050
export MLFLOW_S3_ENDPOINT_URL=http://your-minio-host:9000
export AWS_ACCESS_KEY_ID=<minio-access-key>
export AWS_SECRET_ACCESS_KEY=<minio-secret-key>
# If an HTTP proxy is configured, bypass it for the local subnet.
export NO_PROXY=localhost,127.0.0.1,<your-lan-cidr>
export no_proxy=$NO_PROXY

# The FT engine uses the supervised slot (WEIGHT_SUPERVISED); there is no separate weight.
# FLOW_TIMEOUT=15 makes flows expire (and get scored) sooner than the default 120 s.
sudo --preserve-env=MLFLOW_TRACKING_URI,MLFLOW_S3_ENDPOINT_URL,AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY,NO_PROXY,no_proxy \
  FLOW_TIMEOUT=15 venv/bin/python main.py --iface eth4 --api --duration 600
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
`main.py` logs to the terminal (stderr); there is no log file unless you redirect it. A flow is only scored after it has been idle for `FLOW_TIMEOUT` seconds.

## Generate synthetic attacks

### SYN flood (target: a non-production host)

```bash
sudo hping3 -S -p 80 -s 40000 -k --flood -c 200 <TARGET_IP>
```

`-s 40000 -k` keeps one source port, so all SYNs fall on one flow. Expected
detection: the `syn_scan` rule (more than 20 SYNs, no data), which is a
critical rule and forces `score=1.000`; the label may be `DoS` (class 3).
Without `-k`, hping3 increments the source port, every SYN is its own flow
and the rule does not fire.

### Port scan

```bash
sudo nmap -sS -p 1-1000 -T4 <TARGET_IP>
```

Expected: the `port_scan` rule (15 distinct ports of one target within 60 s,
a critical rule) tags every probe flow, so an alert follows once the flows
expire (`FLOW_TIMEOUT`, 120 s idle). Some probe flows may also carry
`attack_type=Reconnaissance` (class 7). `syn_scan` does not fire here: a
sweep sends one SYN per port, each its own flow. Not verified on a live
capture yet; see issue #87.

### UDP fuzzing

```bash
sudo hping3 --udp -p 53 --rand-source --flood -c 500 <TARGET_IP>
```

Expected detection: `attack_type=Fuzzers` (class 5) — small datasets
sometimes mislabel as DoS.

## Validation checklist

After each attack:

- [ ] cnds logged an `[ALERT]` line whose `engines=` list includes `supervised`
- [ ] `attack_type` matches expectation ±1 class (Fuzzers/DoS often
  blur on synthetic flows)
- [ ] `score >= 0.55` (default threshold), or a critical rule in `rules=`
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
  that is reachable from WSL2 and generate the attack from this host outward.
