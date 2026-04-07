"""Provenance metadata describing a single baseline training window."""

from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List

from .triggers import _shannon_entropy_bits


@dataclass
class ProvenanceMetadata:
    window_start_iso: str
    window_end_iso: str
    fire_reason: str
    distinct_src_ips: int
    distinct_dst_ports: int
    top_dst_ports: list  # list of [port, count] pairs (JSON-serializable)
    dst_port_entropy_bits: float
    hour_of_day_histogram: dict
    protocol_histogram: dict

    @classmethod
    def from_window(
        cls,
        samples,
        window_start_ts: float,
        window_end_ts: float,
        fire_reason: str,
    ) -> "ProvenanceMetadata":
        src_ips = set()
        dst_port_counts: Counter = Counter()
        hour_hist: Counter = Counter()
        proto_hist: Counter = Counter()

        for s in samples:
            src_ips.add(s.src_ip)
            dst_port_counts[int(s.dst_port)] += 1
            proto_hist[str(s.protocol)] += 1
            try:
                hour = datetime.fromtimestamp(s.ts_epoch, tz=timezone.utc).hour
            except (OSError, ValueError, OverflowError):
                hour = 0
            hour_hist[int(hour)] += 1

        top_ports = [[int(p), int(c)] for p, c in dst_port_counts.most_common(20)]

        return cls(
            window_start_iso=datetime.fromtimestamp(window_start_ts, tz=timezone.utc).isoformat(),
            window_end_iso=datetime.fromtimestamp(window_end_ts, tz=timezone.utc).isoformat(),
            fire_reason=fire_reason,
            distinct_src_ips=len(src_ips),
            distinct_dst_ports=len(dst_port_counts),
            top_dst_ports=top_ports,
            dst_port_entropy_bits=_shannon_entropy_bits(dst_port_counts),
            hour_of_day_histogram={str(k): int(v) for k, v in sorted(hour_hist.items())},
            protocol_histogram={str(k): int(v) for k, v in proto_hist.items()},
        )

    def to_dict(self) -> dict:
        return asdict(self)
