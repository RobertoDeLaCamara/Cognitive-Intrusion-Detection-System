#!/usr/bin/env python3
"""Demo seed: generate models if missing, then post synthetic predictions.

Runs as a one-shot container in `docker compose --profile demo up`.
Waits for the API to be healthy, generates demo ML models if they don't
exist, then sends crafted predict requests to populate the dashboard
with representative alerts.
"""

import logging
import sys
import time
from pathlib import Path

import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger(__name__)

API_URL = "http://api:8000"
MODELS_DIR = Path("models")


def wait_for_api(url: str, timeout: int = 120) -> bool:
    """Block until the API /health endpoint responds 200."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = httpx.get(f"{url}/health", timeout=5)
            if r.status_code == 200:
                log.info("API is healthy")
                return True
        except httpx.ConnectError:
            pass
        time.sleep(2)
    return False


def models_exist() -> bool:
    required = ["rf_model.joblib", "isolation_forest.joblib", "lstm_autoencoder.pt"]
    return all((MODELS_DIR / f).exists() for f in required)


def generate_models() -> None:
    log.info("Generating demo ML models...")
    sys.path.insert(0, str(Path(__file__).parent))
    from generate_demo_models import main as gen_main
    sys.argv = ["generate_demo_models", "--output-dir", str(MODELS_DIR)]
    gen_main()


def seed_alerts() -> None:
    """Send crafted /api/predict requests that trigger alerts."""
    # Each request uses payload_matches to trigger the rules engine,
    # plus synthetic flow/host features for the ML engines.
    # Requests use payload_matches WITHOUT flow_features to trigger the
    # rules-engine shortcut path (scores.rules = 1.0), ensuring alerts
    # fire regardless of the demo model quality.
    scenarios = [
        {
            "src_ip": "10.0.0.1", "dst_ip": "192.168.1.60",
            "src_port": 55000, "dst_port": 5000, "protocol": 6,
            "payload_matches": ["sql_injection"],
        },
        {
            "src_ip": "10.0.0.1", "dst_ip": "192.168.1.62",
            "src_port": 55200, "dst_port": 80, "protocol": 6,
            "payload_matches": ["xss", "path_traversal"],
        },
        {
            "src_ip": "10.0.0.1", "dst_ip": "192.168.1.62",
            "src_port": 55300, "dst_port": 80, "protocol": 6,
            "payload_matches": ["command_injection"],
        },
        {
            "src_ip": "10.0.0.1", "dst_ip": "192.168.1.60",
            "src_port": 55400, "dst_port": 5000, "protocol": 6,
            "payload_matches": ["shellshock"],
        },
        {
            "src_ip": "10.0.0.1", "dst_ip": "192.168.1.62",
            "src_port": 55500, "dst_port": 80, "protocol": 6,
            "payload_matches": ["log4j"],
        },
        {
            "src_ip": "192.168.1.60", "dst_ip": "10.0.0.1",
            "src_port": 56000, "dst_port": 443, "protocol": 6,
            "payload_matches": ["large_payload", "asymmetric_upload"],
        },
    ]

    posted = 0
    for scenario in scenarios:
        try:
            r = httpx.post(f"{API_URL}/api/predict", json=scenario, timeout=10)
            data = r.json()
            if data.get("is_anomaly"):
                posted += 1
                log.info("  Alert: %s → %s  [%s]  score=%.2f  severity=%s",
                         scenario["src_ip"], scenario["dst_ip"],
                         data.get("attack_type", "anomaly"),
                         data.get("ensemble_score", 0),
                         data.get("severity", "?"))
            else:
                log.info("  No alert (score=%.2f): %s → %s  rules=%s",
                         data.get("ensemble_score", 0),
                         scenario["src_ip"], scenario["dst_ip"],
                         scenario.get("payload_matches"))
        except Exception as e:
            log.warning("  Failed: %s", e)

    log.info("Seeded %d/%d alerts via /api/predict", posted, len(scenarios))


def main() -> None:
    log.info("CNDS Demo Seed starting...")

    if not wait_for_api(API_URL):
        log.error("API did not become healthy — aborting")
        sys.exit(1)

    if not models_exist():
        generate_models()
        log.info("Models generated. Note: API/detector need restart to load them.")
        log.info("Run: docker compose restart api detector")
    else:
        log.info("Models already present — skipping generation")

    seed_alerts()
    log.info("Demo seed complete. Dashboard: http://localhost:8501")


if __name__ == "__main__":
    main()
