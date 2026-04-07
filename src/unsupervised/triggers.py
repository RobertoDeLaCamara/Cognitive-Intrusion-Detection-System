"""Composite trigger for firing unsupervised baseline training windows."""

import math
from collections import Counter
from dataclasses import dataclass, field


def _shannon_entropy_bits(counts: Counter) -> float:
    """Compute Shannon entropy (in bits) of a Counter of observations."""
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    entropy = 0.0
    for c in counts.values():
        if c <= 0:
            continue
        p = c / total
        entropy -= p * math.log2(p)
    return entropy


@dataclass
class TriggerState:
    """Snapshot of collector state used to evaluate trigger conditions."""
    n_total: int = 0
    n_distinct_src_ips: int = 0
    elapsed_sec: float = 0.0
    dst_port_counts: Counter = field(default_factory=Counter)


@dataclass
class CompositeTrigger:
    """All conditions must be satisfied for the trigger to fire."""
    min_total_vectors: int = 50_000
    min_distinct_src_ips: int = 20
    min_elapsed_sec: float = 1800.0  # 30 min
    min_dst_port_entropy_bits: float = 2.5

    def should_fire(self, state: TriggerState) -> bool:
        if state.n_total < self.min_total_vectors:
            return False
        if state.n_distinct_src_ips < self.min_distinct_src_ips:
            return False
        if state.elapsed_sec < self.min_elapsed_sec:
            return False
        if _shannon_entropy_bits(state.dst_port_counts) < self.min_dst_port_entropy_bits:
            return False
        return True
