"""Read log lines from Loki's HTTP API with a per-stream cursor.

Each service has one cursor: the timestamp (ns) of the newest entry delivered plus the lines
seen at exactly that timestamp. Loki's ``start`` is inclusive, so the overlap is re-read and
filtered out; a restart of the poller (or an overlapping page) never double-counts an entry.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

import httpx

logger = logging.getLogger(__name__)

_NS = 1_000_000_000


class LokiError(Exception):
    """Loki was unreachable or answered with an error."""


@dataclass(frozen=True)
class Entry:
    ts_ns: int
    line: str

    @property
    def ts(self) -> float:
        return self.ts_ns / _NS


@dataclass
class Cursor:
    selector: str
    last_ns: Optional[int] = None
    seen: Set[str] = field(default_factory=set)

    def accept(self, entry: Entry) -> bool:
        """True the first time an entry is offered, False for anything already delivered."""
        if self.last_ns is None or entry.ts_ns > self.last_ns:
            self.last_ns, self.seen = entry.ts_ns, {entry.line}
            return True
        if entry.ts_ns == self.last_ns and entry.line not in self.seen:
            self.seen.add(entry.line)
            return True
        return False


class LokiSource:
    def __init__(self, url: str, streams: Dict[str, str], user: str = "", password: str = "",
                 batch: int = 1000, backfill_secs: int = 86400, lag_secs: int = 15,
                 timeout: float = 15.0, client: Optional[httpx.AsyncClient] = None):
        self.cursors = {name: Cursor(selector) for name, selector in streams.items()}
        self.batch = batch
        self.backfill_secs = backfill_secs
        self.lag_secs = lag_secs
        self._url = url.rstrip("/")
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._auth = (user, password) if user else None

    async def _query_range(self, selector: str, start_ns: int, end_ns: int) -> List[Entry]:
        params = {"query": selector, "start": str(start_ns), "end": str(end_ns),
                  "limit": str(self.batch), "direction": "forward"}
        try:
            resp = await self._client.get(f"{self._url}/loki/api/v1/query_range", params=params, auth=self._auth)
        except httpx.HTTPError as exc:
            raise LokiError(f"Loki unreachable: {exc}") from exc
        if resp.status_code != 200:
            raise LokiError(f"Loki answered {resp.status_code}: {resp.text[:200]}")
        try:
            streams = resp.json()["data"]["result"]
            entries = [Entry(int(ts), line) for s in streams for ts, line in s["values"]]
        except (KeyError, ValueError, TypeError) as exc:
            raise LokiError(f"unexpected Loki response: {exc}") from exc
        entries.sort(key=lambda e: e.ts_ns)
        return entries

    async def poll(self, service: str, now: Optional[float] = None) -> List[Entry]:
        """Entries of ``service`` not delivered before, oldest first.

        The cursor only advances over entries actually returned, so after a ``LokiError`` the
        next poll resumes from the same place.
        """
        cursor = self.cursors[service]
        now_ns = int((time.time() if now is None else now) * _NS)
        end_ns = now_ns - self.lag_secs * _NS
        start_ns = cursor.last_ns if cursor.last_ns is not None else now_ns - self.backfill_secs * _NS
        fresh: List[Entry] = []
        while True:
            page = await self._query_range(cursor.selector, start_ns, end_ns)
            accepted = [e for e in page if cursor.accept(e)]
            fresh.extend(accepted)
            if len(page) < self.batch:
                return fresh
            if not accepted:
                logger.warning("logwatch: more than %d '%s' entries share one timestamp; skipping ahead",
                               self.batch, service)
                cursor.last_ns, cursor.seen = page[-1].ts_ns + 1, set()
                start_ns = cursor.last_ns
                continue
            start_ns = page[-1].ts_ns

    async def aclose(self) -> None:
        await self._client.aclose()
