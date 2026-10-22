"""Replay log files through the rules without touching the database.

Use it to tune thresholds against real logs before enabling live watching::

    zcat gitea.log.*.gz | python -m src.logwatch.replay --service gitea --tz Europe/Madrid \\
        --trusted 192.168.0.0/16,172.16.0.0/12 -
"""

import argparse
import gzip
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, List, Optional
from zoneinfo import ZoneInfo

from . import gitea
from .engine import LogRuleEngine, parse_networks
from .events import LogAlert, LogEvent
from .rules import load_rules

DEFAULT_RULES_DIR = Path(__file__).parent / "rules"
PARSERS = {gitea.SERVICE: gitea.parse_line}


def _lines(path: str) -> Iterator[str]:
    if path == "-":
        yield from sys.stdin
    elif path.endswith(".gz"):
        with gzip.open(path, "rt", errors="replace") as fh:
            yield from fh
    else:
        with open(path, errors="replace") as fh:
            yield from fh


def replay(lines: Iterable[str], service: str, engine: LogRuleEngine, tz=timezone.utc) -> List[LogAlert]:
    parse = PARSERS[service]
    alerts: List[LogAlert] = []
    events: List[LogEvent] = []
    for line in lines:
        ev = parse(line, tz=tz)
        if ev:
            events.append(ev)
    events.sort(key=lambda e: e.ts)           # files can be concatenated out of order
    for ev in events:
        alerts.extend(engine.feed(ev))
    return alerts


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help="log files (.gz ok); '-' reads stdin")
    ap.add_argument("--service", default=gitea.SERVICE, choices=sorted(PARSERS))
    ap.add_argument("--rules", default=str(DEFAULT_RULES_DIR), help="rules file or directory")
    ap.add_argument("--trusted", default="", help="comma-separated CIDRs treated as trusted")
    ap.add_argument("--tz", default="UTC", help="timezone of the timestamps in the log")
    args = ap.parse_args(argv)

    engine = LogRuleEngine(load_rules(args.rules), trusted=parse_networks(args.trusted.split(",")))
    lines = (line for f in args.files for line in _lines(f))
    alerts = replay(lines, args.service, engine, tz=ZoneInfo(args.tz))
    for a in alerts:
        when = datetime.fromtimestamp(a.last_ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        print(f"{when}Z  {a.severity.upper():8} {a.rule:24} {a.key:18} {a.count:>4}x/{a.window_secs}s")
    print(f"{len(alerts)} alert(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
