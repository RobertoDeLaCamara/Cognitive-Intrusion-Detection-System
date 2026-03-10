"""Per-IP host-level feature extractor (18 features).

Aggregates packet statistics per source IP over a sliding history window.
Adapted from cognitive-anomaly-detector.
"""

import time
import threading
import numpy as np
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from scapy.all import IP, TCP, UDP, ICMP, Raw

from ..config import HOST_WINDOW_SIZE, MAX_TRACKED_IPS, COMMON_PORTS
from .utils import byte_entropy

HOST_FEATURE_NAMES = [
    # Statistical (6)
    "packets_per_sec", "bytes_per_sec", "avg_packet_size", "packet_size_var",
    "total_packets", "total_bytes",
    # Temporal (4)
    "iat_mean", "iat_std", "burst_rate", "session_duration",
    # Protocol (3)
    "tcp_ratio", "udp_ratio", "icmp_ratio",
    # Port (2)
    "unique_ports", "uncommon_port_ratio",
    # Payload (3)
    "avg_payload_entropy", "avg_payload_size", "payload_size_var",
]


def _entropy(data: bytes) -> float:
    """Shannon entropy — delegates to shared utility."""
    return byte_entropy(data)


@dataclass
class HostHistory:
    packet_sizes: deque = field(default_factory=lambda: deque(maxlen=HOST_WINDOW_SIZE))
    payload_sizes: deque = field(default_factory=lambda: deque(maxlen=HOST_WINDOW_SIZE))
    timestamps: deque = field(default_factory=lambda: deque(maxlen=HOST_WINDOW_SIZE))
    payload_entropies: deque = field(default_factory=lambda: deque(maxlen=HOST_WINDOW_SIZE))
    ports: deque = field(default_factory=lambda: deque(maxlen=HOST_WINDOW_SIZE))

    first_seen: float = 0.0
    total_packets: int = 0
    total_bytes: int = 0
    tcp_count: int = 0
    udp_count: int = 0
    icmp_count: int = 0

    def add_packet(self, packet, ts: float) -> None:
        if self.first_seen == 0.0:
            self.first_seen = ts

        pkt_len = len(packet)
        self.packet_sizes.append(pkt_len)
        self.timestamps.append(ts)
        self.total_packets += 1
        self.total_bytes += pkt_len

        port = None
        if TCP in packet:
            self.tcp_count += 1
            port = packet[TCP].dport
        elif UDP in packet:
            self.udp_count += 1
            port = packet[UDP].dport
        elif ICMP in packet:
            self.icmp_count += 1
        self.ports.append(port)

        if Raw in packet:
            raw = packet[Raw].load
            self.payload_sizes.append(len(raw))
            self.payload_entropies.append(_entropy(raw))
        else:
            self.payload_sizes.append(0)
            self.payload_entropies.append(0.0)


class HostExtractor:
    """Extracts 18 ML features per source IP."""

    def __init__(self):
        self._data: Dict[str, HostHistory] = defaultdict(HostHistory)
        self._lock = threading.RLock()

    def process_packet(self, packet) -> Optional[str]:
        if IP not in packet:
            return None
        src = packet[IP].src
        ts = time.time()
        with self._lock:
            if len(self._data) >= MAX_TRACKED_IPS and src not in self._data:
                self._evict_least_active()
            self._data[src].add_packet(packet, ts)
        return src

    def extract_features(self, ip: str) -> Optional[np.ndarray]:
        with self._lock:
            if ip not in self._data:
                return None
            h = self._data[ip]
            if h.total_packets < 3:
                return None
            # Snapshot mutable deques under lock to avoid races with process_packet
            snapshot = HostHistory(
                packet_sizes=deque(h.packet_sizes, maxlen=HOST_WINDOW_SIZE),
                payload_sizes=deque(h.payload_sizes, maxlen=HOST_WINDOW_SIZE),
                timestamps=deque(h.timestamps, maxlen=HOST_WINDOW_SIZE),
                payload_entropies=deque(h.payload_entropies, maxlen=HOST_WINDOW_SIZE),
                ports=deque(h.ports, maxlen=HOST_WINDOW_SIZE),
                first_seen=h.first_seen,
                total_packets=h.total_packets,
                total_bytes=h.total_bytes,
                tcp_count=h.tcp_count,
                udp_count=h.udp_count,
                icmp_count=h.icmp_count,
            )

        try:
            return self._compute(snapshot)
        except Exception:
            return None

    def _compute(self, h: HostHistory) -> np.ndarray:
        now = time.time()
        duration = max(now - h.first_seen, 1e-3)

        # Statistical
        sizes = np.array(h.packet_sizes, dtype=float)
        pkt_s = h.total_packets / duration
        byt_s = h.total_bytes / duration
        avg_sz = float(sizes.mean()) if len(sizes) else 0.0
        var_sz = float(sizes.var()) if len(sizes) > 1 else 0.0

        # Temporal
        ts_arr = np.array(h.timestamps, dtype=float)
        if len(ts_arr) >= 2:
            iats = np.diff(ts_arr)
            iat_mean = float(iats.mean())
            iat_std = float(iats.std()) if len(iats) > 1 else 0.0
        else:
            iat_mean = iat_std = 0.0
        recent = sum(1 for t in h.timestamps if t > now - 5.0)
        burst_rate = recent / 5.0

        # Protocol
        total = max(h.total_packets, 1)
        tcp_r = h.tcp_count / total
        udp_r = h.udp_count / total
        icmp_r = h.icmp_count / total

        # Port
        valid_ports = [p for p in h.ports if p is not None]
        if valid_ports:
            port_set = set(valid_ports)
            unique_ports = float(len(port_set))
            uncommon = sum(1 for p in valid_ports if p not in COMMON_PORTS)
            uncommon_ratio = uncommon / len(valid_ports)
        else:
            unique_ports = uncommon_ratio = 0.0

        # Payload
        ps_arr = np.array(h.payload_sizes, dtype=float)
        pe_arr = np.array(h.payload_entropies, dtype=float)
        nz_sizes = ps_arr[ps_arr > 0]
        nz_ent = pe_arr[pe_arr > 0]
        avg_ent = float(nz_ent.mean()) if len(nz_ent) else 0.0
        avg_pay = float(nz_sizes.mean()) if len(nz_sizes) else 0.0
        var_pay = float(nz_sizes.var()) if len(nz_sizes) > 1 else 0.0

        return np.array([
            pkt_s, byt_s, avg_sz, var_sz,
            float(h.total_packets), float(h.total_bytes),
            iat_mean, iat_std, burst_rate, duration,
            tcp_r, udp_r, icmp_r,
            unique_ports, uncommon_ratio,
            avg_ent, avg_pay, var_pay,
        ], dtype=np.float32)

    def _evict_least_active(self) -> None:
        if not self._data:
            return
        # Evict IP with oldest last-seen timestamp (least recently active)
        oldest = min(self._data, key=lambda k: self._data[k].timestamps[-1] if self._data[k].timestamps else 0.0)
        del self._data[oldest]

    def tracked_ips(self) -> List[str]:
        with self._lock:
            return list(self._data.keys())
