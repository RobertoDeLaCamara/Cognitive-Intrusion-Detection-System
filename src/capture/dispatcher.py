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

from ..features.flow_extractor import FlowExtractor, FlowKey
from ..features.host_extractor import HostExtractor
from ..features.payload_analyzer import analyze_payload, extract_payload_features
from ..features.ja3 import extract_ja3, is_malicious_ja3
from ..enrichment.dns_logger import extract_dns_query
from ..config import MAX_ACTIVE_FLOWS


logger = logging.getLogger(__name__)

# SSH is encrypted after the version exchange, and its interactive packets are
# too short for the entropy check in payload_analyzer.looks_encrypted() (which
# needs >= 256 bytes), so a few random bytes spelling "../" or "; id " raised
# CRITICAL payload rules on plain SSH sessions. A flow counts as SSH when either
# end uses port 22 or either side sends the "SSH-" version banner (SSH on other
# ports, e.g. Gitea's 2223; the banner is missed if capture starts mid-session).
_SSH_PORTS = frozenset({22})
_SSH_BANNER = b"SSH-"


def _is_ssh_packet(flow_key: FlowKey, packet) -> bool:
    if flow_key[2] in _SSH_PORTS or flow_key[3] in _SSH_PORTS:
        return True
    raw = packet.getlayer("Raw")
    return raw is not None and bytes(raw.load[:4]) == _SSH_BANNER


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

        # Payload matches per flow, forward direction only (LRU eviction).
        # Keyed by flow rather than src_ip so a match in one flow can't be
        # attributed to another flow from the same host (issue #21).
        self._payload_hits: OrderedDict[FlowKey, list[str]] = OrderedDict()
        self._payload_lock = threading.Lock()
        self._max_payload_entries = MAX_ACTIVE_FLOWS

        # JA3 fingerprint per flow, forward direction only (LRU eviction).
        # Keyed by flow for the same reason as _payload_hits: per src_ip, one
        # TLS ClientHello was attached to whichever flow from that host expired
        # next (e.g. a DNS query), and a later handshake overwrote an earlier one.
        self._ja3_hits: OrderedDict[FlowKey, dict] = OrderedDict()
        self._ja3_lock = threading.Lock()

        # Flows identified as SSH (LRU, same bound): their payload matches are
        # dropped, see _is_ssh_packet().
        self._ssh_flows: OrderedDict[FlowKey, None] = OrderedDict()

    def dispatch(self, packet) -> None:
        """Process one packet through all pipelines."""
        # 1. Flow-level features
        flow_ref = self._flow_extractor.process_packet(packet)

        # 2. Host-level features
        self._host_extractor.process_packet(packet)

        # 3. Payload analysis (cheap — pattern match only)
        matches = analyze_payload(packet)

        # 4. DNS query logging (Phase 8)
        extract_dns_query(packet)

        # 5. JA3 fingerprinting
        ja3_result = extract_ja3(packet)
        if ja3_result and flow_ref is not None and flow_ref[1]:
            flow_key = flow_ref[0]
            ja3_hash, ja3_str = ja3_result
            with self._ja3_lock:
                if flow_key not in self._ja3_hits and len(self._ja3_hits) >= self._max_payload_entries:
                    self._ja3_hits.popitem(last=False)
                self._ja3_hits[flow_key] = {"hash": ja3_hash, "string": ja3_str, "malicious": is_malicious_ja3(ja3_hash)}
                self._ja3_hits.move_to_end(flow_key)

        if flow_ref is not None and self._mark_ssh(flow_ref[0], packet):
            matches = []

        if matches and flow_ref is not None and flow_ref[1]:
            flow_key = flow_ref[0]
            with self._payload_lock:
                # LRU eviction: remove oldest entry when at capacity
                if flow_key not in self._payload_hits and len(self._payload_hits) >= self._max_payload_entries:
                    self._payload_hits.popitem(last=False)
                existing = self._payload_hits.get(flow_key, [])
                # Keep last 20 unique matches per flow
                combined = list(set(existing + matches))[-20:]
                self._payload_hits[flow_key] = combined
                self._payload_hits.move_to_end(flow_key)

    def _mark_ssh(self, flow_key: FlowKey, packet) -> bool:
        """Return True if *flow_key* is SSH, recording it the first time it is seen."""
        with self._payload_lock:
            if flow_key in self._ssh_flows:
                return True
            if not _is_ssh_packet(flow_key, packet):
                return False
            if len(self._ssh_flows) >= self._max_payload_entries:
                self._ssh_flows.popitem(last=False)
            self._ssh_flows[flow_key] = None
            # Drop matches collected before the banner showed up.
            self._payload_hits.pop(flow_key, None)
            return True

    def _flush_loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(self._flush_interval)
            self._flush_expired()

    def _flush_expired(self) -> None:
        expired = self._flow_extractor.collect_expired()
        for record, flow_vec in expired:
            host_vec = self._host_extractor.extract_features(record.src_ip)
            record.host_hits = self._host_extractor.host_hits(
                record.src_ip, record.dst_ip, record.key[3], record.start_time, record.last_time)
            with self._payload_lock:
                payload_matches = self._payload_hits.pop(record.key, [])
                self._ssh_flows.pop(record.key, None)
            with self._ja3_lock:
                ja3_info = self._ja3_hits.pop(record.key, None)
            payload_features = extract_payload_features(record.fwd_payloads)
            try:
                self._flow_callback(record, flow_vec, host_vec, payload_matches, payload_features, ja3_info)
            except Exception as e:
                logger.error("Flow callback error for %s: %s", record.src_ip, e)

    def flush_all(self) -> None:
        """Force flush all active flows (e.g. on shutdown)."""
        for record, flow_vec in self._flow_extractor.collect_all():
            host_vec = self._host_extractor.extract_features(record.src_ip)
            record.host_hits = self._host_extractor.host_hits(
                record.src_ip, record.dst_ip, record.key[3], record.start_time, record.last_time)
            with self._payload_lock:
                payload_matches = self._payload_hits.pop(record.key, [])
                self._ssh_flows.pop(record.key, None)
            with self._ja3_lock:
                ja3_info = self._ja3_hits.pop(record.key, None)
            payload_features = extract_payload_features(record.fwd_payloads)
            try:
                self._flow_callback(record, flow_vec, host_vec, payload_matches, payload_features, ja3_info)
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
