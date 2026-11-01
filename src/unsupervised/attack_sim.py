"""Offline traffic simulator that produces host feature vectors with the real HostExtractor.

Used by the evaluation bench to get labelled attack vectors without touching a network. Packets
are built with scapy and fed to ``HostHistory`` with simulated timestamps; the extractor's clock
(``time.time``) is pinned to the simulated time while a vector is computed, so the vectors have
the same meaning as the ones the detector collects (sliding-window volume features included).

Each scenario returns ``(X, hosts, ts)`` with rows in time order: one vector after every
``flow_pkts`` packets of a source, which is roughly when the pipeline snapshots a host.
"""

from typing import Callable, Dict, List, Tuple
from unittest import mock

import numpy as np
from scapy.all import IP, TCP, UDP, Raw

from ..features.host_extractor import HostExtractor, HostHistory

Rows = Tuple[np.ndarray, List[str], np.ndarray]
Packet = Tuple[float, object]  # (simulated time, scapy packet)

ATTACKER = "198.51.100.7"
TARGET = "192.168.1.189"


def _payload(rng: np.random.Generator, size: int, high_entropy: bool) -> bytes:
    if size <= 0:
        return b""
    if high_entropy:
        return rng.integers(0, 256, size, dtype=np.uint8).tobytes()
    text = b"GET /index.html HTTP/1.1 Host: example.local Accept: text/html "
    return (text * (size // len(text) + 1))[:size]


def _tcp(src, dst, dport, flags="S", payload=b"", sport=40000):
    p = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    return p / Raw(payload) if payload else p


def _udp(src, dst, dport, payload=b"", sport=40000):
    p = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    return p / Raw(payload) if payload else p


def vectors_from_packets(packets: List[Packet], src: str, flow_pkts: int) -> Rows:
    """Run packets of one source through HostHistory and snapshot a vector every ``flow_pkts``."""
    ex = HostExtractor()
    hist = HostHistory()
    X, ts = [], []
    for i, (t, pkt) in enumerate(packets, start=1):
        hist.add_packet(pkt, t)
        if i % flow_pkts == 0 and hist.total_packets >= 3:
            with mock.patch("time.time", return_value=t):
                X.append(ex._compute(hist))
            ts.append(t)
    if not X:
        return np.empty((0, 18), dtype=np.float32), [], np.empty(0)
    return np.stack(X).astype(np.float32), [src] * len(X), np.asarray(ts, dtype=np.float64)


# ── attack scenarios ──────────────────────────────────────────────────────────

def syn_flood(rng, t0=0.0, src=ATTACKER, pps=800, seconds=10) -> Rows:
    pk = [(t0 + i / pps, _tcp(src, TARGET, 443, "S", sport=int(rng.integers(1024, 65535))))
          for i in range(int(pps * seconds))]
    return vectors_from_packets(pk, src, flow_pkts=25)


def port_scan(rng, t0=0.0, src=ATTACKER, pps=100, seconds=30) -> Rows:
    pk = [(t0 + i / pps, _tcp(src, TARGET, 1 + (i % 65000), "S")) for i in range(int(pps * seconds))]
    return vectors_from_packets(pk, src, flow_pkts=10)


def udp_flood(rng, t0=0.0, src=ATTACKER, pps=600, seconds=10) -> Rows:
    pk = [(t0 + i / pps, _udp(src, TARGET, int(rng.integers(1, 65535)), _payload(rng, 1200, True)))
          for i in range(int(pps * seconds))]
    return vectors_from_packets(pk, src, flow_pkts=25)


def ssh_bruteforce(rng, t0=0.0, src=ATTACKER, pps=8, seconds=120) -> Rows:
    pk = [(t0 + i / pps, _tcp(src, TARGET, 22, "PA", _payload(rng, int(rng.integers(60, 120)), True)))
          for i in range(int(pps * seconds))]
    return vectors_from_packets(pk, src, flow_pkts=8)


def dns_tunnel(rng, t0=0.0, src=ATTACKER, pps=20, seconds=120) -> Rows:
    pk = [(t0 + i / pps, _udp(src, TARGET, 53, _payload(rng, int(rng.integers(100, 200)), True)))
          for i in range(int(pps * seconds))]
    return vectors_from_packets(pk, src, flow_pkts=10)


def slow_exfil(rng, t0=0.0, src=ATTACKER, pps=3, seconds=300) -> Rows:
    """Low-rate encrypted upload to 443: deliberately close to ordinary TLS, a hard case."""
    pk = [(t0 + i / pps, _tcp(src, TARGET, 443, "PA", _payload(rng, int(rng.integers(1000, 1400)), True)))
          for i in range(int(pps * seconds))]
    return vectors_from_packets(pk, src, flow_pkts=6)


ATTACKS: Dict[str, Callable[..., Rows]] = {
    "syn_flood": syn_flood,
    "port_scan": port_scan,
    "udp_flood": udp_flood,
    "ssh_bruteforce": ssh_bruteforce,
    "dns_tunnel": dns_tunnel,
    "slow_exfil": slow_exfil,
}


def all_attacks(seed: int = 7, t0: float = 1_700_000_000.0) -> Dict[str, Rows]:
    rng = np.random.default_rng(seed)
    return {name: fn(rng, t0=t0) for name, fn in ATTACKS.items()}


# ── benign traffic (tests and the drift demonstration) ────────────────────────

def benign_hosts(rng, n_hosts=8, t0=1_700_000_000.0, seconds=1800) -> Rows:
    """Stationary LAN-like hosts: web browsing bursts, a periodic probe, small DNS lookups."""
    rows_x, rows_h, rows_t = [], [], []
    for h in range(n_hosts):
        src = f"192.168.1.{20 + h}"
        kind = h % 3
        pk: List[Packet] = []
        t = t0 + float(rng.uniform(0, 5))
        while t < t0 + seconds:
            if kind == 0:     # browsing: bursts to 443
                for _ in range(int(rng.integers(5, 25))):
                    t += float(rng.exponential(0.05))
                    pk.append((t, _tcp(src, "93.184.216.34", 443, "PA",
                                       _payload(rng, int(rng.integers(200, 1400)), True))))
                t += float(rng.exponential(8.0))
            elif kind == 1:   # periodic probe
                for _ in range(4):
                    t += 0.01
                    pk.append((t, _tcp(src, TARGET, 3001, "PA", _payload(rng, 80, False))))
                t += 15.0
            else:             # DNS client
                t += float(rng.exponential(3.0))
                pk.append((t, _udp(src, "192.168.1.1", 53, _payload(rng, int(rng.integers(30, 70)), False))))
        x, hh, tt = vectors_from_packets(pk, src, flow_pkts=5)
        rows_x.append(x); rows_h += hh; rows_t.append(tt)
    X = np.vstack(rows_x); ts = np.concatenate(rows_t)
    order = np.argsort(ts, kind="stable")
    return X[order], [rows_h[i] for i in order], ts[order]
