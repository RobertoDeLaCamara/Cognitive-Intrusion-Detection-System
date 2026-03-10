"""Confidence decay — reduce score for repeated alerts from the same IP (Phase 9).

Prevents alert fatigue from persistent scanners by applying exponential
decay to the ensemble score based on recent alert count.
"""

import threading
import time
from collections import OrderedDict

from ..config import CONFIDENCE_DECAY_FACTOR, CONFIDENCE_DECAY_WINDOW, MAX_TRACKED_IPS

_hits: OrderedDict = OrderedDict()  # ip -> [timestamp, ...]
_lock = threading.Lock()
_MAX_ENTRIES = MAX_TRACKED_IPS


def _cleanup_locked():
    """Remove stale IPs when dict exceeds capacity."""
    while len(_hits) > _MAX_ENTRIES:
        _hits.popitem(last=False)


def apply_decay(ip: str, score: float) -> float:
    """Apply exponential decay based on recent alert count for this IP."""
    now = time.time()
    cutoff = now - CONFIDENCE_DECAY_WINDOW

    with _lock:
        timestamps = _hits.get(ip, [])
        timestamps = [t for t in timestamps if t > cutoff]
        repeat_count = len(timestamps)
        timestamps.append(now)
        _hits[ip] = timestamps
        _hits.move_to_end(ip)
        _cleanup_locked()

    if repeat_count == 0:
        return score
    return score * (CONFIDENCE_DECAY_FACTOR ** repeat_count)


def recent_alert_count(ip: str) -> int:
    """Return number of recent alerts for this IP within the decay window."""
    now = time.time()
    cutoff = now - CONFIDENCE_DECAY_WINDOW
    with _lock:
        return sum(1 for t in _hits.get(ip, []) if t > cutoff)
