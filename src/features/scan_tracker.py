"""Host-level trackers for behaviour that no single flow shows.

Two attacks are many tiny flows, none unusual alone, so no per-flow rule and no engine sees them:

* **Port scan** (issue #87): one source starts TCP connections to many distinct *ports* of one
  target. ``ScanTracker`` flags a ``(src, dst)`` pair that touches ``port_threshold`` distinct
  destination ports within ``window`` seconds.
* **Brute force** (issue #88): one source starts many TCP connections to one *service* (22, 3389,
  ...). ``BruteForceTracker`` flags a ``(src, dst, dport)`` that sees ``conn_threshold`` distinct
  source ports (= distinct connections; a retransmitted SYN reuses its source port and does not
  count twice) within ``window`` seconds.

* **DNS burst** (issue #89): one source asks one resolver for many distinct names under the
  same parent domain (``<random>.example.com``), the shape of DNS tunneling, exfiltration and
  DGA probing. ``DnsBurstTracker`` flags a ``(src, dst, parent)`` that sees ``qname_threshold``
  distinct query names within ``window`` seconds. The parent is the last two labels, so normal
  browsing (many unrelated domains, or a handful of CDN names under one parent) stays far below.

The TCP trackers watch only the start of TCP connections (SYN without ACK); the DNS tracker
watches UDP queries. All use capture time (``packet.time``), so a PCAP replay behaves like live
capture.

Flows are scored only when they expire (``FLOW_TIMEOUT`` after their last packet), long after the
sliding window has moved on. A flagged key is therefore remembered as the time intervals of the
activity (``first`` .. ``last``), and a flow is a hit when it started inside one of them. A new
crossing extends the last interval only when it comes within ``window`` of its end; a later burst
opens a new interval, so traffic in the quiet gap between two bursts is not a hit.
"""

import threading
from collections import deque
from typing import Deque, Dict, FrozenSet, Hashable, Iterable, List, Optional, Set, Tuple


class _DistinctTracker:
    """Flags a key that sees ``threshold`` distinct values within ``window`` seconds."""

    rule = ""

    def __init__(
        self,
        threshold: int,
        window: float,
        allowlist: Iterable[str] = (),
        max_keys: int = 5000,
        flag_ttl: float = 600.0,
    ):
        self.threshold = threshold
        self.window = window
        self.allowlist: FrozenSet[str] = frozenset(allowlist)
        self.max_keys = max_keys
        self.flag_ttl = flag_ttl  # must outlive FLOW_TIMEOUT so expiring flows still find the flag
        self._events: Dict[Hashable, Deque[Tuple[float, Hashable]]] = {}
        self._flagged: Dict[Hashable, List[List[float]]] = {}  # key -> [[first_ts, last_ts], ...]
        self._lock = threading.Lock()
        self._last_prune = 0.0

    def _observe(self, src: str, key: Hashable, value: Hashable, ts: float) -> None:
        if self.threshold <= 0 or src in self.allowlist:
            return
        with self._lock:
            q = self._events.get(key)
            if q is None:
                if len(self._events) >= self.max_keys:
                    self._evict_oldest()
                q = self._events[key] = deque()
            q.append((ts, value))
            cutoff = ts - self.window
            while q and q[0][0] < cutoff:
                q.popleft()
            if len({v for _, v in q}) >= self.threshold:
                intervals = self._flagged.setdefault(key, [])
                if intervals and ts - intervals[-1][1] <= self.window:
                    intervals[-1][1] = ts
                else:
                    intervals.append([q[0][0], ts])
            if ts - self._last_prune > self.window:
                self._prune(ts)

    def _hits(self, key: Hashable, start: float) -> List[str]:
        with self._lock:
            intervals = list(self._flagged.get(key, ()))
        if any(first <= start <= last for first, last in intervals):
            return [self.rule]
        return []

    def _overlaps(self, keys: Iterable[Hashable], start: float, end: float) -> bool:
        """True when the activity of any flagged key in *keys* overlaps ``start`` .. ``end``."""
        with self._lock:
            intervals = [iv for k in keys for iv in self._flagged.get(k, ())]
        return any(first <= end and start <= last for first, last in intervals)

    def _evict_oldest(self) -> None:
        oldest = min(self._events, key=lambda k: self._events[k][-1][0] if self._events[k] else 0.0)
        del self._events[oldest]

    def _prune(self, now: float) -> None:
        self._last_prune = now
        for key in [k for k, q in self._events.items() if not q or q[-1][0] < now - self.window]:
            del self._events[key]
        for key in list(self._flagged):
            live = [iv for iv in self._flagged[key] if iv[1] >= now - self.flag_ttl]
            if live:
                self._flagged[key] = live
            else:
                del self._flagged[key]


class ScanTracker(_DistinctTracker):
    """``port_scan``: distinct destination ports of one target from one source."""

    rule = "port_scan"

    def __init__(self, port_threshold: int = 15, window: float = 60.0, allowlist: Iterable[str] = (),
                 max_pairs: int = 5000, flag_ttl: float = 600.0):
        super().__init__(port_threshold, window, allowlist, max_pairs, flag_ttl)

    @property
    def port_threshold(self) -> int:
        return self.threshold

    def observe(self, src: str, dst: str, dport: int, ts: float) -> None:
        """Record the start of a TCP connection from *src* to *dst*:*dport* at capture time *ts*."""
        self._observe(src, (src, dst), dport, ts)

    def hits(self, src: str, dst: str, start: float) -> List[str]:
        """Rule names for a flow from *src* to *dst* that began at *start* (capture time)."""
        return self._hits((src, dst), start)


class BruteForceTracker(_DistinctTracker):
    """``brute_force``: many distinct connections from one source to one service port."""

    rule = "brute_force"

    def __init__(self, conn_threshold: int = 15, window: float = 60.0, ports: Iterable[int] = (22,),
                 allowlist: Iterable[str] = (), max_keys: int = 5000, flag_ttl: float = 600.0):
        super().__init__(conn_threshold, window, allowlist, max_keys, flag_ttl)
        self.ports: FrozenSet[int] = frozenset(ports)

    def observe(self, src: str, dst: str, dport: int, sport: int, ts: float) -> None:
        """Record the start of a TCP connection *src*:*sport* -> *dst*:*dport*."""
        if dport in self.ports:
            self._observe(src, (src, dst, dport), sport, ts)

    def hits(self, src: str, dst: str, dport: int, start: float) -> List[str]:
        return self._hits((src, dst, dport), start)


def parent_domain(qname: str) -> str:
    """Last two labels of *qname*, lower-cased (``a.b.example.com.`` -> ``example.com``)."""
    labels = [x for x in qname.lower().rstrip(".").split(".") if x]
    return ".".join(labels[-2:])


class DnsBurstTracker(_DistinctTracker):
    """``dns_burst``: many distinct query names under one parent domain from one source."""

    rule = "dns_burst"

    def __init__(self, qname_threshold: int = 40, window: float = 10.0, allowlist: Iterable[str] = (),
                 max_keys: int = 5000, flag_ttl: float = 600.0):
        super().__init__(qname_threshold, window, allowlist, max_keys, flag_ttl)
        # (src, dst) -> parents seen, so a flow (which does not know its query names) finds its flags
        self._parents: Dict[Tuple[str, str], Set[str]] = {}

    def observe(self, src: str, dst: str, qname: str, ts: float) -> None:
        """Record a DNS query for *qname* from *src* to the resolver *dst* at capture time *ts*."""
        name = qname.lower().rstrip(".")
        if not name or self.threshold <= 0 or src in self.allowlist:
            return
        parent = parent_domain(name)
        self._observe(src, (src, dst, parent), name, ts)
        if (src, dst, parent) in self._flagged:
            with self._lock:
                self._parents.setdefault((src, dst), set()).add(parent)

    def hits(self, src: str, dst: str, start: float, end: Optional[float] = None) -> List[str]:
        """Rule names for a flow *src* -> *dst* active from *start* to *end* (capture time).

        A tunnel that keeps one UDP socket is a single long flow that may have started before
        the burst crossed the threshold, so any overlap counts, not only the start.
        """
        end = start if end is None else end
        with self._lock:
            parents = list(self._parents.get((src, dst), ()))
        if self._overlaps([(src, dst, p) for p in parents], start, end):
            return [self.rule]
        return []

    def _prune(self, now: float) -> None:
        super()._prune(now)
        for pair in list(self._parents):
            live = {p for p in self._parents[pair] if (pair[0], pair[1], p) in self._flagged}
            if live:
                self._parents[pair] = live
            else:
                del self._parents[pair]
