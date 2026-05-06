"""CNDS Sandbox Orchestrator.

Starts all sandbox components, coordinates phases, and generates a final report.

Usage:
    python sandbox/orchestrator.py --demo    # Full 30+ min run with unsupervised training
    python sandbox/orchestrator.py --ci      # Fast 2-5 min CI validation
"""

import argparse
import asyncio
import json
import logging
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sandbox.traffic.background import generate_background, BackgroundStats
from sandbox.traffic.scenarios import run_all_scenarios, ScenarioResult
from sandbox.api_exerciser.exerciser import exercise_api, ExerciserReport
from sandbox.api_exerciser.ws_client import AlertWSClient, WSClientStats
from sandbox.siem_mock.receiver import SyslogReceiver, ReceiverStats

logger = logging.getLogger(__name__)


@dataclass
class SandboxReport:
    mode: str
    start_time: str
    end_time: str
    duration_secs: float
    background_traffic: dict
    attack_scenarios: dict
    api_exerciser: dict
    websocket: dict
    siem_mock: dict
    passed: bool


async def run_sandbox(ci_mode: bool = False, base_url: str = "http://localhost:8000") -> SandboxReport:
    """Run the full sandbox pipeline."""
    mode = "ci" if ci_mode else "demo"
    start = time.time()
    start_ts = datetime.now(timezone.utc).isoformat()

    logger.info("=== CNDS Sandbox [%s mode] ===", mode)

    # Phase 0: Start SIEM mock receiver
    logger.info("Phase 0: Starting SIEM mock receiver...")
    siem = SyslogReceiver(host="127.0.0.1", port=5514)
    try:
        await siem.start()
    except OSError as e:
        logger.warning("SIEM mock could not bind: %s (skipping)", e)
        siem = None

    # Phase 1: Start WebSocket client
    logger.info("Phase 1: Starting WebSocket client...")
    ws_client = AlertWSClient(base_url=base_url.replace("http", "ws"))
    try:
        await ws_client.start()
        await asyncio.sleep(0.5)  # Let it connect
    except Exception as e:
        logger.warning("WebSocket client failed to start: %s", e)

    # Phase 2: Background benign traffic
    logger.info("Phase 2: Generating background traffic...")
    bg_stats = await generate_background(
        base_url=base_url,
        total_vectors=5000 if ci_mode else 50000,
        batch_size=50 if ci_mode else 100,
        delay=0.02 if ci_mode else 0.05,
        ci_mode=ci_mode,
    )

    # Phase 3: Attack scenarios
    logger.info("Phase 3: Running attack scenarios...")
    scenario_results = await run_all_scenarios(base_url=base_url, ci_mode=ci_mode)

    # Phase 4: API exerciser
    logger.info("Phase 4: Exercising API endpoints...")
    api_report = await exercise_api(base_url=base_url)

    # Phase 5: Stop collectors and gather stats
    logger.info("Phase 5: Collecting results...")
    ws_stats = await ws_client.stop()
    siem_stats = await siem.stop() if siem else ReceiverStats()

    end = time.time()
    duration = end - start

    # Build report
    report = SandboxReport(
        mode=mode,
        start_time=start_ts,
        end_time=datetime.now(timezone.utc).isoformat(),
        duration_secs=round(duration, 1),
        background_traffic={
            "vectors_sent": bg_stats.vectors_sent,
            "unique_ips": len(bg_stats.unique_ips),
            "port_entropy": round(bg_stats.port_entropy, 2),
            "errors": bg_stats.errors,
        },
        attack_scenarios={
            name: {
                "vectors_sent": r.vectors_sent,
                "alerts_triggered": r.alerts_triggered,
                "attack_types": r.attack_types_seen[:5],
                "errors": r.errors,
            }
            for name, r in scenario_results.items()
        },
        api_exerciser={
            "total": api_report.total,
            "passed": api_report.passed,
            "failed": api_report.failed,
            "failures": [
                {"method": r.method, "path": r.path, "error": r.error}
                for r in api_report.results if not r.passed
            ],
        },
        websocket={
            "connected": ws_stats.connected,
            "messages_received": ws_stats.messages_received,
            "errors": ws_stats.errors,
        },
        siem_mock={
            "messages_received": siem_stats.messages_received,
            "valid_cef": siem_stats.valid_cef,
            "invalid_cef": siem_stats.invalid_cef,
        },
        passed=_evaluate_pass(ci_mode, bg_stats, scenario_results, api_report, ws_stats),
    )

    _print_summary(report)
    return report


def _evaluate_pass(
    ci_mode: bool,
    bg: BackgroundStats,
    scenarios: dict,
    api: ExerciserReport,
    ws: WSClientStats,
) -> bool:
    """Determine if the sandbox run passes CI assertions."""
    if bg.vectors_sent == 0:
        return False
    if api.failed > api.total * 0.3:  # Allow up to 30% failures (auth-gated endpoints)
        return False
    # At least one scenario should trigger alerts
    total_alerts = sum(r.alerts_triggered for r in scenarios.values())
    if total_alerts == 0:
        return False
    return True


def _print_summary(report: SandboxReport) -> None:
    """Print a human-readable summary."""
    status = "✓ PASSED" if report.passed else "✗ FAILED"
    print(f"\n{'='*60}")
    print(f"  CNDS Sandbox Report [{report.mode}] — {status}")
    print(f"{'='*60}")
    print(f"  Duration: {report.duration_secs}s")
    print(f"\n  Background Traffic:")
    print(f"    Vectors sent:  {report.background_traffic['vectors_sent']}")
    print(f"    Unique IPs:    {report.background_traffic['unique_ips']}")
    print(f"    Port entropy:  {report.background_traffic['port_entropy']} bits")
    print(f"\n  Attack Scenarios:")
    for name, data in report.attack_scenarios.items():
        alerts = data['alerts_triggered']
        sent = data['vectors_sent']
        mark = "✓" if alerts > 0 else "✗"
        print(f"    {mark} {name}: {alerts}/{sent} alerts")
    print(f"\n  API Exerciser: {report.api_exerciser['passed']}/{report.api_exerciser['total']} passed")
    if report.api_exerciser['failures']:
        for f in report.api_exerciser['failures'][:5]:
            print(f"    ✗ {f['method']} {f['path']}: {f['error']}")
    print(f"\n  WebSocket: {'connected' if report.websocket['connected'] else 'NOT connected'}, "
          f"{report.websocket['messages_received']} messages")
    print(f"  SIEM Mock: {report.siem_mock['valid_cef']} valid CEF / "
          f"{report.siem_mock['messages_received']} total")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(description="CNDS Sandbox Orchestrator")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--demo", action="store_true", help="Full demo run (30+ min)")
    group.add_argument("--ci", action="store_true", help="Fast CI run (2-5 min)")
    parser.add_argument("--url", default="http://localhost:8000", help="CNDS API base URL")
    parser.add_argument("--output", type=str, help="Write JSON report to file")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    report = asyncio.run(run_sandbox(ci_mode=args.ci, base_url=args.url))

    if args.output:
        Path(args.output).write_text(json.dumps(asdict(report), indent=2, default=str))
        logger.info("Report written to %s", args.output)

    sys.exit(0 if report.passed else 1)


if __name__ == "__main__":
    main()
