"""Live collector for unsupervised baseline training windows.

Accumulates host feature vectors in a ring-capped buffer. When the composite
trigger fires (or a hard cap is hit), the buffer is snapshotted and handed off
to a background training thread.
"""

import logging
import threading
import time
from collections import Counter
from dataclasses import dataclass
from typing import Callable, List, Optional

import numpy as np

from .provenance import ProvenanceMetadata
from .triggers import CompositeTrigger, TriggerState, _shannon_entropy_bits

logger = logging.getLogger(__name__)


@dataclass
class CollectedSample:
    host_vec: np.ndarray
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    ts_epoch: float


class BaselineCollector:
    """Thread-safe, O(1) hot-path collector of feature vectors."""

    HARD_CAP = 500_000

    def __init__(
        self,
        trigger: CompositeTrigger,
        on_window_ready: Callable[[List[CollectedSample], ProvenanceMetadata], None],
        enabled: bool = True,
    ):
        self._trigger = trigger
        self._on_window_ready = on_window_ready
        self._enabled = enabled

        self._lock = threading.Lock()
        self._buffer: List[CollectedSample] = []
        self._src_ips: set = set()
        self._dst_port_counts: Counter = Counter()
        self._window_start_ts: float = time.time()
        self._training_in_flight: bool = False
        self._dropped_while_training: int = 0

    # ── hot path ────────────────────────────────────────────────────────────
    def observe(self, record, host_vec: np.ndarray) -> None:
        """Called from the flow pipeline on every completed flow."""
        if not self._enabled or host_vec is None:
            return

        # FlowRecord attribute extraction (keep outside the lock).
        try:
            src_ip = record.src_ip
            dst_ip = record.dst_ip
            # FlowRecord.key = (src_ip, dst_ip, sport, dport, proto)
            key = getattr(record, "key", None)
            if key is not None:
                dst_port = int(key[3])
                protocol = str(key[4])
            else:
                dst_port = int(getattr(record, "dst_port", 0) or 0)
                protocol = str(getattr(record, "protocol", "") or "")
            ts_epoch = float(
                getattr(record, "last_time", None)
                or getattr(record, "end_ts", None)
                or time.time()
            )
        except Exception as exc:
            logger.debug(
                "BaselineCollector.observe: field extraction failed (%s) — skipping record",
                exc,
            )
            return

        sample = CollectedSample(
            host_vec=np.asarray(host_vec, dtype=np.float32),
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            ts_epoch=ts_epoch,
        )

        snapshot: Optional[List[CollectedSample]] = None
        provenance: Optional[ProvenanceMetadata] = None
        fire_reason = ""
        window_start_ts = 0.0
        window_end_ts = 0.0

        with self._lock:
            if self._training_in_flight:
                self._dropped_while_training += 1
                return  # drop sample while training is running

            self._buffer.append(sample)
            self._src_ips.add(src_ip)
            self._dst_port_counts[dst_port] += 1

            n_total = len(self._buffer)
            elapsed = max(0.0, ts_epoch - self._window_start_ts)  # guard against clock skew

            state = TriggerState(
                n_total=n_total,
                n_distinct_src_ips=len(self._src_ips),
                elapsed_sec=elapsed,
                dst_port_counts=self._dst_port_counts,
            )

            hit_hard_cap = n_total >= self.HARD_CAP
            should_fire = hit_hard_cap or self._trigger.should_fire(state)

            if should_fire:
                fire_reason = "hard_cap" if hit_hard_cap else "composite_trigger"
                snapshot = self._buffer
                window_start_ts = self._window_start_ts
                window_end_ts = ts_epoch
                self._training_in_flight = True
                # Reset live state for next window.
                self._buffer = []
                self._src_ips = set()
                self._dst_port_counts = Counter()
                self._window_start_ts = ts_epoch  # same time base as TriggerState.elapsed_sec

        if snapshot is None:
            return

        try:
            provenance = ProvenanceMetadata.from_window(
                snapshot, window_start_ts, window_end_ts, fire_reason
            )
        except Exception as e:
            logger.error("Failed to build provenance metadata: %s", e)
            with self._lock:
                self._training_in_flight = False
            return

        t = threading.Thread(
            target=self._run_training,
            args=(snapshot, provenance),
            name="baseline-trainer",
            daemon=True,
        )
        try:
            t.start()
        except Exception as e:
            logger.error("Failed to start baseline training thread: %s", e)
            with self._lock:
                self._training_in_flight = False

    def _run_training(
        self,
        snapshot: List[CollectedSample],
        provenance: ProvenanceMetadata,
    ) -> None:
        try:
            logger.info(
                "Baseline window ready: n=%d reason=%s", len(snapshot), provenance.fire_reason
            )
            self._on_window_ready(snapshot, provenance)
        except Exception as e:
            logger.exception("Baseline training failed: %s", e)
        finally:
            with self._lock:
                dropped = self._dropped_while_training
                self._dropped_while_training = 0
                self._training_in_flight = False
            if dropped:
                logger.warning(
                    "Baseline training complete — %d samples dropped during training run", dropped
                )
