"""Poll log sources, run the rules and store the alerts."""

import asyncio
import logging
import time
from typing import Callable, Dict, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ..api import metrics
from .engine import LogRuleEngine
from .events import LogAlert, LogEvent
from .loki import LokiError, LokiSource
from .persist import already_alerted, persist_alert

logger = logging.getLogger(__name__)

SILENT_RULE = "logwatch_source_silent"
UNREACHABLE_RULE = "logwatch_source_unreachable"
UNREACHABLE_AFTER = 5            # consecutive failed polls


class LogWatcher:
    """One poll = read new lines per service, parse, evaluate, return the alerts.

    ``parsers`` maps a service name to ``parse(line, ts=...) -> LogEvent | None``. The watcher
    also reports its own blindness: a source that keeps failing, or answers with no lines for
    ``silent_polls`` polls in a row, raises one alert until data flows again.
    """

    def __init__(self, source: LokiSource, engine: LogRuleEngine, parsers: Dict[str, Callable],
                 silent_polls: int = 30):
        self.source, self.engine, self.parsers = source, engine, parsers
        self.silent_polls = silent_polls
        self._empty_polls = {s: 0 for s in parsers}
        self._failed_polls = {s: 0 for s in parsers}
        self._flagged: Dict[str, set] = {s: set() for s in parsers}

    async def poll_once(self) -> List[LogAlert]:
        alerts: List[LogAlert] = []
        for service, parse in self.parsers.items():
            try:
                entries = await self.source.poll(service)
            except LokiError as exc:
                metrics.inc_logwatch_error(service)
                self._failed_polls[service] += 1
                logger.warning("logwatch: %s poll failed (%d in a row): %s", service, self._failed_polls[service], exc)
                if self._failed_polls[service] >= UNREACHABLE_AFTER:
                    alerts += self._health_alert(service, UNREACHABLE_RULE,
                                                 f"logwatch cannot read {service} logs from Loki")
                continue
            self._failed_polls[service] = 0
            self._flagged[service].discard(UNREACHABLE_RULE)
            events: List[LogEvent] = [e for e in (parse(x.line, ts=x.ts) for x in entries) if e]
            metrics.inc_logwatch_events(service, len(events))
            if entries:
                self._empty_polls[service] = 0
                self._flagged[service].discard(SILENT_RULE)
            else:
                self._empty_polls[service] += 1
                if self._empty_polls[service] >= self.silent_polls:
                    alerts += self._health_alert(service, SILENT_RULE,
                                                 f"no {service} log lines in Loki for {self._empty_polls[service]} polls")
            for ev in events:
                alerts += self.engine.feed(ev)
        return alerts

    def _health_alert(self, service: str, rule: str, description: str) -> List[LogAlert]:
        if rule in self._flagged[service]:
            return []
        self._flagged[service].add(rule)
        now = time.time()
        return [LogAlert(rule=rule, service=service, description=description, severity="high", key=service,
                         ip=None, count=1, window_secs=0, first_ts=now, last_ts=now)]


async def run(watcher: LogWatcher, session_factory: Callable[[], AsyncSession], poll_secs: int,
              stop: Optional[asyncio.Event] = None) -> None:
    """Poll forever. Never raises: a bad poll or a DB hiccup is logged and retried next tick."""
    stop = stop or asyncio.Event()
    logger.info("logwatch started: services=%s every %ds", list(watcher.parsers), poll_secs)
    while not stop.is_set():
        try:
            alerts = await watcher.poll_once()
            if alerts:
                async with session_factory() as db:
                    for alert in alerts:
                        if not await already_alerted(db, alert):
                            await persist_alert(db, alert)
                            metrics.inc_alert(alert.severity, engine="logwatch")
                            logger.warning("logwatch alert [%s] %s from %s (%dx)", alert.severity, alert.rule,
                                           alert.key, alert.count)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("logwatch cycle failed; retrying next tick")
        try:
            await asyncio.wait_for(stop.wait(), timeout=poll_secs)
        except asyncio.TimeoutError:
            pass
