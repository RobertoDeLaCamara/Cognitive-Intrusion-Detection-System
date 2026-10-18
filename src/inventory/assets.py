"""Network asset inventory built from completed flows (cnds#13).

AssetTracker keeps cheap per-IP counters in memory on the capture path and a flusher
merges them into the `host_profiles` table every ASSET_FLUSH_SECS, so profiles survive
restarts without a database write per flow. Only private LAN addresses are tracked.

classify() is a heuristic over what the host does on the wire:
  server       receives much more than it initiates (or is reached on several ports)
  iot          talks to few peers, only on common device ports, and is almost never contacted
  workstation  initiates to many peers and is rarely contacted
  unknown      too little traffic or no clear pattern
"""

import ipaddress
import logging
import threading
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Set

from ..timeutils import utcnow

logger = logging.getLogger(__name__)

SET_CAP = 200                # per-host cap on remembered peers / ports
MIN_FLOWS = 10               # below this a host stays "unknown"
IOT_PORTS = {53, 80, 123, 443, 1883, 5683, 8883}


def is_lan_address(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private and not (addr.is_multicast or addr.is_loopback
                                    or addr.is_link_local or addr.is_unspecified)


def classify(flows_out: int, flows_in: int, listen_ports: Iterable[int],
             out_ports: Iterable[int], peers: Iterable[str]) -> str:
    listen_ports, out_ports, peers = set(listen_ports), set(out_ports), set(peers)
    if flows_out + flows_in < MIN_FLOWS:
        return "unknown"
    if (flows_in >= MIN_FLOWS and flows_in >= 2 * flows_out) or (len(listen_ports) >= 3 and flows_in >= 5):
        return "server"
    if flows_out >= MIN_FLOWS and len(peers) <= 5 and out_ports <= IOT_PORTS and flows_in * 10 <= flows_out:
        return "iot"
    if len(peers) >= 10 and flows_out > flows_in:
        return "workstation"
    return "unknown"


class _Stats:
    __slots__ = ("flows_out", "flows_in", "listen_ports", "out_ports", "peers", "first_seen", "last_seen")

    def __init__(self, now: datetime):
        self.flows_out = 0
        self.flows_in = 0
        self.listen_ports: Set[int] = set()
        self.out_ports: Set[int] = set()
        self.peers: Set[str] = set()
        self.first_seen = self.last_seen = now


class AssetTracker:
    def __init__(self, max_hosts: int = 5000):
        self._max_hosts = max_hosts
        self._lock = threading.Lock()
        self._hosts: Dict[str, _Stats] = {}

    def observe(self, src_ip: str, dst_ip: str, dst_port: Optional[int] = None) -> None:
        now = utcnow()
        with self._lock:
            if is_lan_address(src_ip):
                s = self._get(src_ip, now)
                if s is not None:
                    s.flows_out += 1
                    s.last_seen = now
                    if dst_port and len(s.out_ports) < SET_CAP:
                        s.out_ports.add(int(dst_port))
                    if len(s.peers) < SET_CAP:
                        s.peers.add(dst_ip)
            if is_lan_address(dst_ip):
                s = self._get(dst_ip, now)
                if s is not None:
                    s.flows_in += 1
                    s.last_seen = now
                    if dst_port and len(s.listen_ports) < SET_CAP:
                        s.listen_ports.add(int(dst_port))
                    if len(s.peers) < SET_CAP:
                        s.peers.add(src_ip)

    def _get(self, ip: str, now: datetime) -> Optional[_Stats]:
        s = self._hosts.get(ip)
        if s is None:
            if len(self._hosts) >= self._max_hosts:
                return None
            s = self._hosts[ip] = _Stats(now)
        return s

    def drain(self) -> Dict[str, _Stats]:
        """Hand over everything seen since the last drain and start empty."""
        with self._lock:
            drained, self._hosts = self._hosts, {}
        return drained


def _merge_cap(existing: Optional[List], new: Iterable, cast=lambda x: x) -> List:
    merged = {cast(x) for x in (existing or [])} | {cast(x) for x in new}
    return sorted(merged)[:SET_CAP]


def flush(session, drained: Dict[str, _Stats]) -> int:
    """Merge drained counters into host_profiles with a sync SQLAlchemy session. Returns hosts written."""
    from ..api.models import HostProfile
    if not drained:
        return 0
    rows = {
        r.ip: r for r in session.query(HostProfile).filter(HostProfile.ip.in_(list(drained))).all()
    }
    for ip, s in drained.items():
        row = rows.get(ip)
        if row is None:
            row = HostProfile(ip=ip, first_seen=s.first_seen, flows_out=0, flows_in=0)
            session.add(row)
        row.last_seen = max(s.last_seen, row.last_seen or s.last_seen)
        row.flows_out = (row.flows_out or 0) + s.flows_out
        row.flows_in = (row.flows_in or 0) + s.flows_in
        row.listen_ports = _merge_cap(row.listen_ports, s.listen_ports, int)
        row.out_ports = _merge_cap(row.out_ports, s.out_ports, int)
        row.peers = _merge_cap(row.peers, s.peers, str)
        row.classification = classify(row.flows_out, row.flows_in, row.listen_ports, row.out_ports, row.peers)
    session.commit()
    return len(drained)
