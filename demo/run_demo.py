#!/usr/bin/env python3
"""
CNDS Local Network Twin Demo
============================
Runs the full cnds detection pipeline against synthetic traffic PCAPs that
model the local network (NAS .60, Gitea .62, Router .1).

No root required — uses offline PCAP replay instead of live capture.
The rules engine always runs; ML engines activate if model files exist in models/.

Usage:
    python demo/run_demo.py
    python demo/run_demo.py --no-generate        # reuse existing PCAPs
    python demo/run_demo.py --scenario icmp_flood  # single scenario
"""

import argparse
import logging
import sys
import time
import threading
import numpy as np
from pathlib import Path
from typing import List, Optional

# Suppress scapy noise
logging.getLogger("scapy").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

sys.path.insert(0, str(Path(__file__).parent.parent))

from scapy.all import rdpcap
from src.config import MIN_PACKETS_FOR_ML, setup_logging, TRUSTED_OUTBOUND
from src.capture.dispatcher import Dispatcher
from src.engines.registry import supervised, iforest, lstm, rules, ensemble
from src.ensemble.scorer import EngineScores, severity_from_score
from src.features.flow_extractor import FlowRecord
from src.enrichment.mitre import enrich as mitre_enrich
from demo.generate_traffic import SCENARIOS, generate_all, OUT_DIR

setup_logging()

# ── ANSI colors ───────────────────────────────────────────────────────────────
RED      = "\033[91m"
YELLOW   = "\033[93m"
GREEN    = "\033[92m"
CYAN     = "\033[96m"
MAGENTA  = "\033[95m"
BOLD     = "\033[1m"
DIM      = "\033[2m"
RESET    = "\033[0m"

SEVERITY_COLOR = {
    "low":      "\033[94m",   # blue
    "medium":   YELLOW,
    "high":     MAGENTA,
    "critical": RED,
}

# ── Alert state ───────────────────────────────────────────────────────────────
_alerts: list = []
_alerts_lock = threading.Lock()


def _on_alert(record, scores, result, severity):
    sev_str = severity.value if hasattr(severity, "value") else str(severity)
    color = SEVERITY_COLOR.get(sev_str, RESET)
    mitre = mitre_enrich(scores.attack_type, scores.triggered_rules or [])
    mitre_ids = [t["id"] for t in (mitre or [])]

    with _alerts_lock:
        _alerts.append({
            "src":      record.src_ip,
            "dst":      record.dst_ip,
            "type":     scores.attack_type or "anomaly",
            "severity": sev_str,
            "score":    result.score,
            "engines":  result.active_engines,
            "rules":    scores.triggered_rules or [],
            "mitre":    mitre_ids,
        })

    parts = [
        f"{color}{BOLD}ALERT{RESET}",
        f"src={record.src_ip:<15}",
        f"dst={record.dst_ip or '?':<15}",
        f"score={result.score:.2f}",
        f"{color}{sev_str.upper()}{RESET}",
    ]
    if scores.attack_type and scores.attack_type != "BENIGN":
        parts.append(f"type={scores.attack_type}")
    if scores.triggered_rules:
        parts.append(f"rules={scores.triggered_rules}")
    if mitre_ids:
        parts.append(f"mitre={mitre_ids}")
    print("    " + "  ".join(parts))


# ── Pipeline ──────────────────────────────────────────────────────────────────

def _make_callback():
    def on_flow_complete(
        record: FlowRecord,
        flow_vec: np.ndarray,
        host_vec: Optional[np.ndarray],
        payload_matches: List[str],
        payload_features: Optional[np.ndarray] = None,
        ja3_info: Optional[dict] = None,
    ) -> None:
        scores = EngineScores()

        if supervised.is_available:
            r = supervised.predict(flow_vec, payload_features)
            if r:
                label, conf = r
                scores.supervised = 0.0 if label == "BENIGN" else conf
                scores.attack_type = label
                scores.supervised_confidence = conf

        if host_vec is not None:
            if iforest.is_available:
                scores.isolation_forest = iforest.anomaly_score(host_vec)
            if lstm.is_available:
                lstm.update(record.src_ip, host_vec)
                scores.lstm = lstm.anomaly_score(record.src_ip)

        rule_score, triggered = rules.evaluate(record, flow_vec, payload_matches, ja3_info)
        scores.rules = rule_score
        scores.triggered_rules = triggered

        result = ensemble.score(scores)
        if result.is_anomaly:
            severity = severity_from_score(result.score, scores.attack_type)
            _on_alert(record, scores, result, severity)

    return on_flow_complete


def run_scenario(name: str, pcap_path: Path, dispatcher: Dispatcher) -> int:
    """Feed a PCAP through the dispatcher and return the number of new alerts."""
    before = len(_alerts)

    try:
        packets = rdpcap(str(pcap_path))
    except Exception as e:
        print(f"  {RED}Cannot read {pcap_path.name}: {e}{RESET}")
        return 0

    for pkt in packets:
        try:
            dispatcher.dispatch(pkt)
        except Exception:
            pass

    # Force-flush active flows immediately (bypass the 120s flow timeout)
    dispatcher.flush_all()

    return len(_alerts) - before


# ── Display helpers ───────────────────────────────────────────────────────────

def print_banner():
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════╗
║      CNDS — Local Network Digital Twin Demo          ║
║                                                      ║
║  192.168.1.1   Router/gateway                        ║
║  192.168.1.60  Synology NAS  (SMB, DSM, QuickConnect)║
║  192.168.1.62  Gitea server  (HTTP, SSH)             ║
║  10.0.0.1      Simulated external attacker           ║
╚══════════════════════════════════════════════════════╝{RESET}
""")


def print_engine_status():
    rows = [
        ("rules engine",     True,                   "always on"),
        ("supervised (RF)",  supervised.is_available, "requires models/rf_model.joblib"),
        ("isolation forest", iforest.is_available,    "requires models/isolation_forest.joblib"),
        ("lstm autoencoder", lstm.is_available,       "requires models/lstm_autoencoder.pt"),
    ]
    print(f"{BOLD}Detection engines:{RESET}")
    for name, active, note in rows:
        icon = f"{GREEN}✓{RESET}" if active else f"{YELLOW}✗{RESET}"
        dim_note = f"{DIM}({note}){RESET}" if not active else ""
        print(f"  {icon}  {name:<22} {dim_note}")

    if TRUSTED_OUTBOUND:
        print(f"\n{BOLD}Trusted outbound profiles (QuickConnect suppression):{RESET}")
        for ip, domains in TRUSTED_OUTBOUND.items():
            print(f"  {CYAN}{ip}{RESET} → {domains}")
    print()


def print_summary(scenario_results: dict):
    total = len(_alerts)
    print(f"\n{BOLD}{'═' * 56}")
    print(f"  DEMO COMPLETE   {total} alert(s) across {len(scenario_results)} scenario(s)")
    print(f"{'═' * 56}{RESET}\n")

    # Per-scenario table
    print(f"  {'Scenario':<28}  {'Alerts':>6}  {'Result'}")
    print(f"  {'─'*28}  {'─'*6}  {'─'*20}")
    for name, (n, expected_hit) in scenario_results.items():
        if name == "normal_traffic":
            result = f"{GREEN}✓ No false positives{RESET}" if n == 0 else f"{YELLOW}⚠ {n} FP(s){RESET}"
        elif n > 0:
            result = f"{GREEN}✓ Detected{RESET}"
        else:
            result = f"{YELLOW}✗ Missed (ML models needed?){RESET}"
        print(f"  {name:<28}  {n:>6}  {result}")

    if total == 0:
        return

    # Severity breakdown
    by_sev = {}
    for a in _alerts:
        by_sev.setdefault(a["severity"], []).append(a)
    print(f"\n  {BOLD}Severity breakdown:{RESET}")
    for sev in ["critical", "high", "medium", "low"]:
        if sev in by_sev:
            color = SEVERITY_COLOR[sev]
            bar = "█" * len(by_sev[sev])
            print(f"    {color}{sev.upper():<10}{RESET}  {len(by_sev[sev]):>3}  {bar}")

    # MITRE coverage
    all_mitre = sorted({t for a in _alerts for t in a["mitre"]})
    if all_mitre:
        print(f"\n  {BOLD}MITRE ATT&CK techniques observed:{RESET}")
        for t in all_mitre:
            print(f"    {CYAN}{t}{RESET}")

    print()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CNDS Local Network Twin Demo")
    parser.add_argument("--no-generate", action="store_true",
                        help="Skip PCAP generation and reuse existing files")
    parser.add_argument("--scenario", metavar="NAME",
                        help="Run only this scenario (default: all)")
    args = parser.parse_args()

    print_banner()

    if not args.no_generate:
        print(f"{BOLD}Generating synthetic traffic PCAPs...{RESET}")
        generate_all()
        print()

    print_engine_status()

    # Dispatcher with a very long flush_interval so flush_all() controls timing
    dispatcher = Dispatcher(flow_callback=_make_callback(), flush_interval=99999)
    dispatcher.start()

    scenarios_to_run = [
        s for s in SCENARIOS
        if not args.scenario or s[0] == args.scenario
    ]

    scenario_results = {}
    for name, _fn, desc in scenarios_to_run:
        pcap_path = OUT_DIR / f"{name}.pcap"
        if not pcap_path.exists():
            print(f"{YELLOW}  Skipping {name} — PCAP not found. Run without --no-generate.{RESET}")
            continue

        print(f"{BOLD}{'─' * 56}{RESET}")
        print(f"{BOLD}  {name}{RESET}")
        print(f"  {DIM}{desc}{RESET}\n")

        t0 = time.perf_counter()
        n = run_scenario(name, pcap_path, dispatcher)
        elapsed = time.perf_counter() - t0

        if n == 0:
            print(f"  {DIM}(no alerts in {elapsed:.2f}s){RESET}")
        else:
            print(f"  {DIM}→ {n} alert(s) in {elapsed:.2f}s{RESET}")

        scenario_results[name] = (n, name != "normal_traffic")
        print()

    dispatcher.stop()
    print_summary(scenario_results)


if __name__ == "__main__":
    main()
