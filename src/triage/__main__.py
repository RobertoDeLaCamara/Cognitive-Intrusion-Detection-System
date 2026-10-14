"""CLI: ``python -m src.triage [--once | --loop] [--mode workflow|agent] [--alert-id N ...]``.

Run it out of process (cron, Jenkins, systemd timer, or ``--loop``): it never
sits on the capture path and the detector keeps working if it is down.
"""

import argparse
import asyncio
import json
import logging
import sys
from dataclasses import asdict

from .. import config
from ..api.database import AsyncSessionLocal, init_db
from .backends import ClaudeCLIBackend, StaticBackend
from .runner import run_once


def _parse_args(argv=None):
    p = argparse.ArgumentParser(prog="python -m src.triage", description=__doc__)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--once", action="store_true", help="one pass, then exit (default)")
    g.add_argument("--loop", action="store_true", help=f"poll every {config.TRIAGE_POLL_INTERVAL_SECS}s")
    p.add_argument("--mode", choices=("workflow", "agent"), default=config.TRIAGE_MODE)
    p.add_argument("--alert-id", type=int, nargs="+", help="triage these alerts only (re-annotates)")
    p.add_argument("--dry-run", action="store_true",
                   help="use a static needs_human backend: exercises the pipeline without calling a model")
    return p.parse_args(argv)


def _backend(args):
    if args.dry_run:
        return StaticBackend(output={
            "verdict": "needs_human", "confidence": 0.0,
            "summary": "Dry run: no model was called.", "evidence": [],
            "recommendation": "no_action",
        })
    return ClaudeCLIBackend(
        claude_bin=config.TRIAGE_CLAUDE_BIN,
        model=config.TRIAGE_CLAUDE_MODEL,
        bare=config.TRIAGE_CLAUDE_BARE,
        max_turns=config.TRIAGE_MAX_TURNS,
        timeout_secs=config.TRIAGE_TIMEOUT_SECS,
        mcp_config=config.TRIAGE_MCP_CONFIG,
        max_budget_usd=config.TRIAGE_MAX_USD_PER_ALERT,
    )


async def _main(args) -> int:
    await init_db()
    backend = _backend(args)
    while True:
        summary = await run_once(
            AsyncSessionLocal, backend, args.mode,
            min_severity=config.TRIAGE_MIN_SEVERITY,
            lookback_hours=config.TRIAGE_LOOKBACK_HOURS,
            batch_size=config.TRIAGE_BATCH_SIZE,
            min_confidence=config.TRIAGE_MIN_CONFIDENCE,
            daily_budget_usd=config.TRIAGE_DAILY_BUDGET_USD,
            alert_ids=args.alert_id,
        )
        print(json.dumps(asdict(summary)), flush=True)
        if not args.loop:
            return 0 if summary.errors == 0 else 1
        await asyncio.sleep(config.TRIAGE_POLL_INTERVAL_SECS)


def main(argv=None) -> None:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    sys.exit(asyncio.run(_main(_parse_args(argv))))


if __name__ == "__main__":
    main()
