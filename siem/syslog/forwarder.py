"""CEF syslog forwarder for CNDS alerts.

Polls the CNDS REST API and forwards alerts as CEF-formatted syslog
messages. Compatible with QRadar, ArcSight, Sentinel, and any
syslog-capable SIEM.

Usage:
    python siem/syslog/forwarder.py --syslog-host 10.0.0.50 --syslog-port 514
    python siem/syslog/forwarder.py --cnds-url http://localhost:8000 --poll-interval 30
"""

import argparse
import json
import logging
import os
import socket
import time
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("cnds.cef_forwarder")

_SEVERITY_MAP = {"low": 3, "medium": 5, "high": 8, "critical": 10}
_STATE_FILE = os.path.expanduser("~/.cnds_forwarder_state.json")


def _load_last_id() -> int:
    try:
        with open(_STATE_FILE) as f:
            return int(json.load(f).get("last_id", 0))
    except (FileNotFoundError, json.JSONDecodeError, TypeError, ValueError):
        return 0


def _save_last_id(last_id: int) -> None:
    try:
        with open(_STATE_FILE, "w") as f:
            json.dump({"last_id": last_id}, f)
    except OSError as e:
        logger.warning("Could not persist forwarder state: %s", e)


def alert_to_cef(alert: dict) -> str:
    """Convert a CNDS alert dict to a CEF syslog line."""
    severity = _SEVERITY_MAP.get(alert.get("severity", "medium"), 5)
    attack = alert.get("attack_type") or "Unknown"
    src_ip = alert.get("src_ip", "")
    dst_ip = alert.get("dst_ip", "")
    src_port = alert.get("src_port", "")
    dst_port = alert.get("dst_port", "")
    score = alert.get("ensemble_score", 0)
    alert_id = alert.get("id", 0)
    rules = " ".join(alert.get("triggered_rules") or [])
    ja3 = alert.get("ja3_hash") or ""

    mitre_ids = ""
    if alert.get("mitre_techniques"):
        mitre_ids = " ".join(t["id"] for t in alert["mitre_techniques"] if "id" in t)

    # CEF format: CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extensions
    extensions = (
        f"src={src_ip} dst={dst_ip} spt={src_port} dpt={dst_port} "
        f"cn1={score} cn1Label=EnsembleScore "
        f"cs1={rules} cs1Label=TriggeredRules "
        f"cs2={ja3} cs2Label=JA3Hash "
        f"cs3={mitre_ids} cs3Label=MITRETechniques "
        f"externalId={alert_id}"
    )

    return f"CEF:0|CNDS|CognitiveNDS|1.0|{attack}|{attack}|{severity}|{extensions}"


def send_syslog(message: str, host: str, port: int, proto: str = "udp") -> None:
    """Send a syslog message over UDP or TCP."""
    # Wrap in syslog header (facility=local4, severity=warning)
    pri = (20 * 8) + 4  # local4.warning
    ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    line = f"<{pri}>{ts} cnds {message}"

    if proto == "tcp":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((host, port))
            s.sendall((line + "\n").encode())
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(line.encode()[:65507], (host, port))


def main():
    parser = argparse.ArgumentParser(description="CNDS CEF syslog forwarder")
    parser.add_argument("--cnds-url", default="http://localhost:8000")
    parser.add_argument("--syslog-host", required=True)
    parser.add_argument("--syslog-port", type=int, default=514)
    parser.add_argument("--syslog-proto", choices=["udp", "tcp"], default="udp")
    parser.add_argument("--poll-interval", type=int, default=60, help="Seconds between polls")
    parser.add_argument("--severity", default="medium", help="Minimum severity to forward")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logger.info("Forwarding %s+ alerts from %s → %s:%d/%s",
                args.severity, args.cnds_url, args.syslog_host, args.syslog_port, args.syslog_proto)

    last_id = _load_last_id()
    logger.info("Resuming from last_id=%d", last_id)
    while True:
        try:
            resp = httpx.get(
                f"{args.cnds_url}/api/alerts",
                params={"severity": args.severity, "limit": 100},
                timeout=10,
            )
            resp.raise_for_status()
            alerts = resp.json()

            new_alerts = [a for a in alerts if a.get("id", 0) > last_id]
            for alert in sorted(new_alerts, key=lambda a: a.get("id", 0)):
                cef = alert_to_cef(alert)
                send_syslog(cef, args.syslog_host, args.syslog_port, args.syslog_proto)
                last_id = max(last_id, alert.get("id", 0))

            if new_alerts:
                logger.info("Forwarded %d alerts (last_id=%d)", len(new_alerts), last_id)
                _save_last_id(last_id)

        except Exception as e:
            logger.error("Poll/forward error: %s", e)

        time.sleep(args.poll_interval)


if __name__ == "__main__":
    main()
