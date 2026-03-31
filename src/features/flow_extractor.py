"""CICFlowMeter-compatible flow feature extractor.

Reconstructs bidirectional flows from raw Scapy packets and computes
the 76 features expected by the ML-IDS supervised model.

Flow key: (src_ip, dst_ip, src_port, dst_port, protocol)
The initiator is determined by the first packet seen.
"""

import time
import logging
import threading
import numpy as np
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from scapy.all import IP, TCP, UDP, ICMP, Raw

logger = logging.getLogger(__name__)

from ..config import (
    FLOW_TIMEOUT, MAX_ACTIVE_FLOWS, ACTIVE_IDLE_THRESH, COMMON_PORTS,
    MAX_PAYLOAD_SAMPLES, PAYLOAD_SAMPLE_BYTES,
)

# 76 feature names matching ML-IDS PredictionRequest fields
FLOW_FEATURE_NAMES = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
    "totlen_fwd_pkts", "totlen_bwd_pkts",
    "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
    "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "flow_byts_s", "flow_pkts_s",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_tot", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_tot", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fwd_header_len", "bwd_header_len",
    "fwd_pkts_s", "bwd_pkts_s",
    "pkt_len_min", "pkt_len_max", "pkt_len_mean", "pkt_len_std", "pkt_len_var",
    "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
    "ack_flag_cnt", "urg_flag_cnt", "cwr_flag_count", "ece_flag_cnt",
    "down_up_ratio", "pkt_size_avg",
    "fwd_seg_size_avg", "bwd_seg_size_avg",
    "fwd_byts_b_avg", "fwd_pkts_b_avg", "fwd_blk_rate_avg",
    "bwd_byts_b_avg", "bwd_pkts_b_avg", "bwd_blk_rate_avg",
    "subflow_fwd_pkts", "subflow_fwd_byts",
    "subflow_bwd_pkts", "subflow_bwd_byts",
    "init_fwd_win_byts", "init_bwd_win_byts",
    "fwd_act_data_pkts", "fwd_seg_size_min",
    "active_mean", "active_std", "active_max", "active_min",
    "idle_mean", "idle_std", "idle_max", "idle_min",
]

FlowKey = Tuple[str, str, int, int, int]  # src_ip, dst_ip, sport, dport, proto


@dataclass
class FlowRecord:
    """Accumulates per-packet data for a single bidirectional flow."""

    key: FlowKey
    start_time: float = 0.0
    last_time: float = 0.0

    # Directional packet lists
    fwd_lengths: List[int] = field(default_factory=list)
    bwd_lengths: List[int] = field(default_factory=list)
    fwd_times: List[float] = field(default_factory=list)
    bwd_times: List[float] = field(default_factory=list)

    # Header lengths
    fwd_header_len: int = 0
    bwd_header_len: int = 0

    # TCP flags (cumulative counts across all packets)
    fin: int = 0
    syn: int = 0
    rst: int = 0
    psh: int = 0
    ack: int = 0
    urg: int = 0
    cwe: int = 0
    ece: int = 0

    # Directional PSH/URG
    fwd_psh: int = 0
    bwd_psh: int = 0
    fwd_urg: int = 0
    bwd_urg: int = 0

    # Initial window sizes
    init_fwd_win: int = -1
    init_bwd_win: int = -1

    # Forward packets with actual payload
    fwd_act_data_pkts: int = 0

    # Forward payload samples for payload feature extraction (Phase 3)
    fwd_payloads: List[bytes] = field(default_factory=list)

    # Active / idle period tracking
    _last_active: float = 0.0
    active_periods: List[float] = field(default_factory=list)
    idle_periods: List[float] = field(default_factory=list)
    _current_active_start: float = 0.0

    # Bulk transfer tracking (consecutive data packets without idle gaps)
    _fwd_bulk_bytes: List[int] = field(default_factory=list)
    _fwd_bulk_pkts: List[int] = field(default_factory=list)
    _bwd_bulk_bytes: List[int] = field(default_factory=list)
    _bwd_bulk_pkts: List[int] = field(default_factory=list)
    _cur_fwd_bulk_bytes: int = 0
    _cur_fwd_bulk_pkts: int = 0
    _cur_bwd_bulk_bytes: int = 0
    _cur_bwd_bulk_pkts: int = 0
    _last_fwd_time: float = 0.0
    _last_bwd_time: float = 0.0

    def add_packet(self, packet, timestamp: float, is_forward: bool) -> None:
        pkt_len = len(packet)
        ip = packet[IP]
        proto = ip.proto

        if self.start_time == 0.0:
            self.start_time = timestamp
            self._last_active = timestamp
            self._current_active_start = timestamp
        else:
            gap = timestamp - self.last_time
            if gap > ACTIVE_IDLE_THRESH:
                # Record active period that just ended
                active_dur = self.last_time - self._current_active_start
                if active_dur > 0:
                    self.active_periods.append(active_dur)
                self.idle_periods.append(gap)
                self._current_active_start = timestamp

        self.last_time = timestamp

        if is_forward:
            self.fwd_lengths.append(pkt_len)
            self.fwd_times.append(timestamp)
            hdr_len = ip.ihl * 4 if hasattr(ip, 'ihl') else 20
            self.fwd_header_len += hdr_len
            # Bulk transfer tracking
            if self._last_fwd_time > 0 and (timestamp - self._last_fwd_time) > ACTIVE_IDLE_THRESH:
                if self._cur_fwd_bulk_pkts > 1:
                    self._fwd_bulk_bytes.append(self._cur_fwd_bulk_bytes)
                    self._fwd_bulk_pkts.append(self._cur_fwd_bulk_pkts)
                self._cur_fwd_bulk_bytes = 0
                self._cur_fwd_bulk_pkts = 0
            self._cur_fwd_bulk_bytes += pkt_len
            self._cur_fwd_bulk_pkts += 1
            self._last_fwd_time = timestamp
        else:
            self.bwd_lengths.append(pkt_len)
            self.bwd_times.append(timestamp)
            hdr_len = ip.ihl * 4 if hasattr(ip, 'ihl') else 20
            self.bwd_header_len += hdr_len
            # Bulk transfer tracking
            if self._last_bwd_time > 0 and (timestamp - self._last_bwd_time) > ACTIVE_IDLE_THRESH:
                if self._cur_bwd_bulk_pkts > 1:
                    self._bwd_bulk_bytes.append(self._cur_bwd_bulk_bytes)
                    self._bwd_bulk_pkts.append(self._cur_bwd_bulk_pkts)
                self._cur_bwd_bulk_bytes = 0
                self._cur_bwd_bulk_pkts = 0
            self._cur_bwd_bulk_bytes += pkt_len
            self._cur_bwd_bulk_pkts += 1
            self._last_bwd_time = timestamp

        # TCP flags
        if TCP in packet:
            tcp = packet[TCP]
            flags = tcp.flags
            self.fin += int(bool(flags & 0x01))
            self.syn += int(bool(flags & 0x02))
            self.rst += int(bool(flags & 0x04))
            self.psh += int(bool(flags & 0x08))
            self.ack += int(bool(flags & 0x10))
            self.urg += int(bool(flags & 0x20))
            self.ece += int(bool(flags & 0x40))
            self.cwe += int(bool(flags & 0x80))

            if is_forward:
                self.fwd_psh += int(bool(flags & 0x08))
                self.fwd_urg += int(bool(flags & 0x20))
                if self.init_fwd_win < 0:
                    self.init_fwd_win = tcp.window
            else:
                self.bwd_psh += int(bool(flags & 0x08))
                self.bwd_urg += int(bool(flags & 0x20))
                if self.init_bwd_win < 0:
                    self.init_bwd_win = tcp.window

            # Payload data
            if is_forward and tcp.payload and len(bytes(tcp.payload)) > 0:
                self.fwd_act_data_pkts += 1
                if len(self.fwd_payloads) < MAX_PAYLOAD_SAMPLES:
                    self.fwd_payloads.append(bytes(tcp.payload)[:PAYLOAD_SAMPLE_BYTES])

        # UDP payload capture
        if UDP in packet and is_forward:
            udp_payload = bytes(packet[UDP].payload) if packet[UDP].payload else b""
            if udp_payload:
                self.fwd_act_data_pkts += 1
                if len(self.fwd_payloads) < MAX_PAYLOAD_SAMPLES:
                    self.fwd_payloads.append(udp_payload[:PAYLOAD_SAMPLE_BYTES])

    def to_feature_vector(self) -> Optional[np.ndarray]:
        """Compute all 76 features. Returns None if insufficient data."""
        all_pkts = self.fwd_lengths + self.bwd_lengths
        if len(all_pkts) < 2:
            return None

        duration = max(self.last_time - self.start_time, 1e-6)

        # --- Directional counts / lengths ---
        n_fwd = len(self.fwd_lengths)
        n_bwd = len(self.bwd_lengths)
        tot_fwd_bytes = sum(self.fwd_lengths)
        tot_bwd_bytes = sum(self.bwd_lengths)

        def _stats(vals):
            if not vals:
                return 0.0, 0.0, 0.0, 0.0
            a = np.array(vals, dtype=float)
            return float(a.max()), float(a.min()), float(a.mean()), float(a.std())

        def _iat_stats(times):
            if len(times) < 2:
                return 0.0, 0.0, 0.0, 0.0, 0.0
            iats = np.diff(np.array(times))
            return float(iats.sum()), float(iats.mean()), float(iats.std()), \
                   float(iats.max()), float(iats.min())

        fwd_max, fwd_min, fwd_mean, fwd_std = _stats(self.fwd_lengths)
        bwd_max, bwd_min, bwd_mean, bwd_std = _stats(self.bwd_lengths)

        all_times = sorted(self.fwd_times + self.bwd_times)
        _, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = _iat_stats(all_times)

        fwd_iat_tot, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = _iat_stats(self.fwd_times)
        bwd_iat_tot, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = _iat_stats(self.bwd_times)

        all_arr = np.array(all_pkts, dtype=float)
        pkt_min, pkt_max, pkt_mean, pkt_std = float(all_arr.min()), float(all_arr.max()), \
                                               float(all_arr.mean()), float(all_arr.std())

        # Active/idle
        def _period_stats(periods):
            if not periods:
                return 0.0, 0.0, 0.0, 0.0
            a = np.array(periods)
            return float(a.mean()), float(a.std()), float(a.max()), float(a.min())

        # Close out current active period
        periods = self.active_periods.copy()
        last_act = self.last_time - self._current_active_start
        if last_act > 0:
            periods.append(last_act)
        act_mean, act_std, act_max, act_min = _period_stats(periods)
        idl_mean, idl_std, idl_max, idl_min = _period_stats(self.idle_periods)

        fwd_seg_min = float(min(self.fwd_lengths)) if self.fwd_lengths else 0.0

        # Finalize bulk transfer segments
        fwd_bulks_b = self._fwd_bulk_bytes[:]
        fwd_bulks_p = self._fwd_bulk_pkts[:]
        if self._cur_fwd_bulk_pkts > 1:
            fwd_bulks_b.append(self._cur_fwd_bulk_bytes)
            fwd_bulks_p.append(self._cur_fwd_bulk_pkts)
        bwd_bulks_b = self._bwd_bulk_bytes[:]
        bwd_bulks_p = self._bwd_bulk_pkts[:]
        if self._cur_bwd_bulk_pkts > 1:
            bwd_bulks_b.append(self._cur_bwd_bulk_bytes)
            bwd_bulks_p.append(self._cur_bwd_bulk_pkts)

        n_fwd_bulk = len(fwd_bulks_b) or 1
        n_bwd_bulk = len(bwd_bulks_b) or 1
        fwd_byts_b_avg = sum(fwd_bulks_b) / n_fwd_bulk if fwd_bulks_b else 0.0
        fwd_pkts_b_avg = sum(fwd_bulks_p) / n_fwd_bulk if fwd_bulks_p else 0.0
        fwd_blk_rate_avg = n_fwd_bulk / duration if fwd_bulks_b else 0.0
        bwd_byts_b_avg = sum(bwd_bulks_b) / n_bwd_bulk if bwd_bulks_b else 0.0
        bwd_pkts_b_avg = sum(bwd_bulks_p) / n_bwd_bulk if bwd_bulks_p else 0.0
        bwd_blk_rate_avg = n_bwd_bulk / duration if bwd_bulks_b else 0.0

        features = [
            duration,
            float(n_fwd), float(n_bwd),
            float(tot_fwd_bytes), float(tot_bwd_bytes),
            fwd_max, fwd_min, fwd_mean, fwd_std,
            bwd_max, bwd_min, bwd_mean, bwd_std,
            (tot_fwd_bytes + tot_bwd_bytes) / duration,   # flow_byts_s
            (n_fwd + n_bwd) / duration,                   # flow_pkts_s
            flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min,
            fwd_iat_tot, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min,
            bwd_iat_tot, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min,
            float(self.fwd_psh), float(self.bwd_psh),
            float(self.fwd_urg), float(self.bwd_urg),
            float(self.fwd_header_len), float(self.bwd_header_len),
            n_fwd / duration, n_bwd / duration,
            pkt_min, pkt_max, pkt_mean, pkt_std, float(np.var(all_arr)),
            float(self.fin), float(self.syn), float(self.rst), float(self.psh),
            float(self.ack), float(self.urg), float(self.cwe), float(self.ece),
            float(n_bwd) / max(n_fwd, 1),               # down_up_ratio
            pkt_mean,                                    # pkt_size_avg
            fwd_mean, bwd_mean,                          # seg_size_avg
            fwd_byts_b_avg, fwd_pkts_b_avg, fwd_blk_rate_avg,   # bulk fwd
            bwd_byts_b_avg, bwd_pkts_b_avg, bwd_blk_rate_avg,   # bulk bwd
            float(n_fwd), float(tot_fwd_bytes),          # subflow fwd
            float(n_bwd), float(tot_bwd_bytes),          # subflow bwd
            float(max(self.init_fwd_win, 0)),
            float(max(self.init_bwd_win, 0)),
            float(self.fwd_act_data_pkts),
            fwd_seg_min,
            act_mean, act_std, act_max, act_min,
            idl_mean, idl_std, idl_max, idl_min,
        ]

        if len(features) != 76:
            logger.error("Feature vector length %d, expected 76", len(features))
            return None
        return np.array(features, dtype=np.float32)

    @property
    def src_ip(self) -> str:
        return self.key[0]

    @property
    def dst_ip(self) -> str:
        return self.key[1]


class FlowExtractor:
    """Tracks active flows and emits feature vectors when flows expire."""

    def __init__(self):
        self._flows: Dict[FlowKey, FlowRecord] = {}
        self._lock = threading.RLock()
        # Min-heap of (last_time, flow_key) for efficient expiry
        self._expiry_heap: List[Tuple[float, FlowKey]] = []

    def process_packet(self, packet) -> None:
        if IP not in packet:
            return
        ip = packet[IP]
        src, dst = ip.src, ip.dst
        proto = ip.proto
        sport, dport = 0, 0

        if TCP in packet:
            sport, dport = packet[TCP].sport, packet[TCP].dport
        elif UDP in packet:
            sport, dport = packet[UDP].sport, packet[UDP].dport

        fwd_key = (src, dst, sport, dport, proto)
        rev_key = (dst, src, dport, sport, proto)
        ts = time.time()

        with self._lock:
            if fwd_key in self._flows:
                self._flows[fwd_key].add_packet(packet, ts, True)
            elif rev_key in self._flows:
                self._flows[rev_key].add_packet(packet, ts, False)
            else:
                if len(self._flows) >= MAX_ACTIVE_FLOWS:
                    self._evict_oldest()
                self._flows[fwd_key] = FlowRecord(key=fwd_key)
                self._flows[fwd_key].add_packet(packet, ts, True)
                import heapq
                heapq.heappush(self._expiry_heap, (ts, fwd_key))

    def collect_expired(self) -> List[Tuple[FlowRecord, np.ndarray]]:
        """Return (record, features) for flows that have timed out."""
        import heapq
        now = time.time()
        cutoff = now - FLOW_TIMEOUT
        expired_records = []

        with self._lock:
            # Heap-based fast path
            while self._expiry_heap and self._expiry_heap[0][0] <= cutoff:
                _, key = heapq.heappop(self._expiry_heap)
                rec = self._flows.get(key)
                if rec is None:
                    continue  # already evicted
                if rec.last_time > cutoff:
                    # Flow got new packets since heap entry — re-push
                    heapq.heappush(self._expiry_heap, (rec.last_time, key))
                    continue
                expired_records.append(self._flows.pop(key))

            # Fallback: catch any flows not in the heap (e.g. manually inserted)
            if not self._expiry_heap and self._flows:
                fallback_keys = [
                    k for k, rec in self._flows.items()
                    if rec.start_time > 0 and rec.last_time <= cutoff
                ]
                for key in fallback_keys:
                    expired_records.append(self._flows.pop(key))

        results = []
        for rec in expired_records:
            vec = rec.to_feature_vector()
            if vec is not None:
                results.append((rec, vec))
        return results

    def collect_all(self) -> List[Tuple[FlowRecord, np.ndarray]]:
        """Force-collect all current flows (e.g. at shutdown)."""
        results = []
        with self._lock:
            for rec in self._flows.values():
                vec = rec.to_feature_vector()
                if vec is not None:
                    results.append((rec, vec))
            self._flows.clear()
        return results

    def _evict_oldest(self) -> None:
        if not self._flows:
            return
        oldest_key = min(self._flows, key=lambda k: self._flows[k].start_time)
        del self._flows[oldest_key]
        # Compact heap: rebuild to remove stale references
        import heapq
        self._expiry_heap = [(t, k) for t, k in self._expiry_heap if k in self._flows]
        heapq.heapify(self._expiry_heap)

    @property
    def active_flow_count(self) -> int:
        with self._lock:
            return len(self._flows)
