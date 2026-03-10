"""Packet dispatcher — fans a single captured packet out to all feature pipelines.

Each packet is processed by:
  1. FlowExtractor  — bidirectional flow reconstruction (76 CICFlowMeter features)
  2. HostExtractor  — per-source-IP host features (18 features)
  3. PayloadAnalyzer — application-layer pattern matching

The dispatcher also periodically flushes timed-out flows and triggers
the full detection pipeline (engines + ensemble) for each completed flow.
"""

import time
import logging
import threading
from collections import OrderedDict
from typing import Callable, Optional

from ..features.flow_extractor import FlowExtractor, FlowRecord
from ..features.host_extractor import HostExtractor
from ..features.payload_analyzer import analyze_payload, extract_payload_features
from ..enrichment.dns_logger import extract_dns_query
from ..config import MAX_ACTIVE_FLOWS

import numpy as np

logger = logging.getLogger(__name__)


class Dispatcher:
    """Routes each packet to all feature extraction pipelines.

    Args:
        flow_callback: Called with (FlowRecord, flow_features, host_features,
                       payload_matches, payload_features) when a flow expires.
                       host_features may be None.
        flush_interval: How often (seconds) to check for expired flows.
    """

    def __init__(
        self,
        flow_callback: Callable,
        flush_interval: float = 10.0,
    ):
        self._flow_extractor = FlowExtractor()
        self._host_extractor = HostExtractor()
        self._flow_callback = flow_callback
        self._flush_interval = flush_interval
        self._flusher: Optional[threading.Thread] = None
        self._stop = threading.Event()

        # Track latest payload matches per src_ip (LRU eviction)
        self._payload_hits: OrderedDict[str, list[str]] = OrderedDict()
        self._payload_lock = threading.Lock()
        self._max_payload_entries = MAX_ACTIVE_FLOWS

    def dispatch(self, packet) -> None:
        """Process one packet through all pipelines."""
        # 1. Flow-level features
        self._flow_extractor.process_packet(packet)

        # 2. Host-level features
        src_ip = self._host_extractor.process_packet(packet)

        # 3. Payload analysis (cheap — pattern match only)
        matches = analyze_payload(packet)

        # 4. DNS query logging (Phase 8)
        extract_dns_query(packet)
        if matches and src_ip:
            with self._payload_lock:
                # LRU eviction: remove oldest entry when at capacity
                if src_ip not in self._payload_hits and len(self._payload_hits) >= self._max_payload_entries:
                    self._payload_hits.popitem(last=False)
                existing = self._payload_hits.get(src_ip, [])
                # Keep last 20 unique matches per IP
                combined = list(set(existing + matches))[-20:]
                self._payload_hits[src_ip] = combined
                self._payload_hits.move_to_end(src_ip)

    def _flush_loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(self._flush_interval)
            self._flush_expired()

    def _flush_expired(self) -> None:
        expired = self._flow_extractor.collect_expired()
        for record, flow_vec in expired:
            host_vec = self._host_extractor.extract_features(record.src_ip)
            with self._payload_lock:
                payload_matches = self._payload_hits.pop(record.src_ip, [])
            payload_features = extract_payload_features(record.fwd_payloads)
            try:
                self._flow_callback(record, flow_vec, host_vec, payload_matches, payload_features)
            except Exception as e:
                logger.error("Flow callback error for %s: %s", record.src_ip, e)

    def flush_all(self) -> None:
        """Force flush all active flows (e.g. on shutdown)."""
        for record, flow_vec in self._flow_extractor.collect_all():
            host_vec = self._host_extractor.extract_features(record.src_ip)
            with self._payload_lock:
                payload_matches = self._payload_hits.pop(record.src_ip, [])
            payload_features = extract_payload_features(record.fwd_payloads)
            try:
                self._flow_callback(record, flow_vec, host_vec, payload_matches, payload_features)
            except Exception as e:
                logger.error("Flush callback error: %s", e)

    def start(self) -> None:
        self._stop.clear()
        self._flusher = threading.Thread(
            target=self._flush_loop, daemon=True, name="flow-flusher"
        )
        self._flusher.start()
        logger.info("Dispatcher started (flush interval=%.1fs)", self._flush_interval)

    def stop(self) -> None:
        self._stop.set()
        self.flush_all()
        if self._flusher:
            self._flusher.join(timeout=5.0)

    @property
    def stats(self) -> dict:
        return {
            "active_flows": self._flow_extractor.active_flow_count,
            "tracked_ips": len(self._host_extractor.tracked_ips()),
        }
