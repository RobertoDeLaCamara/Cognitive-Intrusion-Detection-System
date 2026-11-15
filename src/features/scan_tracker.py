"""Host-level port-scan tracker.

A port scan is many tiny flows to different ports of one target, so no single flow looks
unusual and the per-flow ``syn_scan`` rule never fires on it (issue #87). This tracker watches
the *start* of TCP connections (SYN without ACK) and flags a ``(src, dst)`` pair that touches at
least ``port_threshold`` distinct destination ports within ``window`` seconds.

Flows are scored only when they expire (``FLOW_TIMEOUT`` after their last packet), long after the
sliding window has moved on. So a flagged pair is remembered as the time interval of the scan
(``first`` .. ``last``) and a flow is a scan hit when it started inside that interval.

All times are capture times (``packet.time``), so a PCAP replay behaves like live capture.
"""

import threading
from collections import deque
from typing import Dict, Deque, FrozenSet, Iterable, List, Tuple

Pair = Tuple[str, str]


class ScanTracker:
    def __init__(
        self,
        port_threshold: int = 15,
        window: float = 60.0,
        allowlist: Iterable[str] = (),
        max_pairs: int = 5000,
        flag_ttl: float = 600.0,
    ):
        self.port_threshold = port_threshold
        self.window = window
        self.allowlist: FrozenSet[str] = frozenset(allowlist)
        self.max_pairs = max_pairs
        self.flag_ttl = flag_ttl  # must outlive FLOW_TIMEOUT so expiring flows still find the flag
        self._events: Dict[Pair, Deque[Tuple[float, int]]] = {}
        self._flagged: Dict[Pair, List[float]] = {}  # pair -> [first_ts, last_ts]
        self._lock = threading.Lock()
        self._last_prune = 0.0

    def observe(self, src: str, dst: str, dport: int, ts: float) -> None:
        """Record the start of a TCP connection from *src* to *dst*:*dport* at capture time *ts*."""
        if self.port_threshold <= 0 or src in self.allowlist:
            return
        pair = (src, dst)
        with self._lock:
            q = self._events.get(pair)
            if q is None:
                if len(self._events) >= self.max_pairs:
                    self._evict_oldest()
                q = self._events[pair] = deque()
            q.append((ts, dport))
            cutoff = ts - self.window
            while q and q[0][0] < cutoff:
                q.popleft()
            if len({p for _, p in q}) >= self.port_threshold:
                flag = self._flagged.get(pair)
                if flag is None or ts - flag[1] > self.flag_ttl:
                    self._flagged[pair] = [q[0][0], ts]
                else:
                    flag[1] = ts
            if ts - self._last_prune > self.window:
                self._prune(ts)

    def hits(self, src: str, dst: str, start: float) -> List[str]:
        """Rule names for a flow from *src* to *dst* that began at *start* (capture time)."""
        with self._lock:
            flag = self._flagged.get((src, dst))
        if flag is not None and flag[0] <= start <= flag[1]:
            return ["port_scan"]
        return []

    def _evict_oldest(self) -> None:
        oldest = min(self._events, key=lambda k: self._events[k][-1][0] if self._events[k] else 0.0)
        del self._events[oldest]

    def _prune(self, now: float) -> None:
        self._last_prune = now
        for pair in [p for p, q in self._events.items() if not q or q[-1][0] < now - self.window]:
            del self._events[pair]
        for pair in [p for p, f in self._flagged.items() if f[1] < now - self.flag_ttl]:
            del self._flagged[pair]
