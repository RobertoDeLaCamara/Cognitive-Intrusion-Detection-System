"""Rule-based detection engine.

Produces a 0/1 alert score from flow and payload signals.
Adapted from cognitive-anomaly-detector.
"""

import logging
from typing import List, Optional, Tuple
import numpy as np

from ..features.flow_extractor import FlowRecord, FLOW_FEATURE_NAMES
from ..config import (
    ICMP_FLOOD_THRESHOLD, PORT_SCAN_THRESHOLD,
    LARGE_PAYLOAD_BYTES, RATE_SPIKE_MULTIPLIER,
)

logger = logging.getLogger(__name__)

# Protocol numbers
PROTO_ICMP = 1
PROTO_TCP  = 6
PROTO_UDP  = 17

# Feature indices by name
_IDX_SYN_FLAG_CNT = FLOW_FEATURE_NAMES.index("syn_flag_cnt")
_IDX_TOT_FWD_PKTS = FLOW_FEATURE_NAMES.index("tot_fwd_pkts")


class RulesEngine:
    """Evaluates heuristic rules against flow metadata and payload matches."""

    def evaluate(
        self,
        record: FlowRecord,
        flow_features: np.ndarray,
        payload_matches: List[str],
        ja3_info: Optional[dict] = None,
    ) -> Tuple[float, List[str]]:
        """Return (score, triggered_rules).

        score: 0.0 (clean) or 1.0 (at least one rule triggered).
        triggered_rules: list of rule names that fired.
        """
        triggered = []
        _, _, sport, dport, proto = record.key

        n_fwd = len(record.fwd_lengths)
        n_bwd = len(record.bwd_lengths)
        duration = max(record.last_time - record.start_time, 1e-6)
        fwd_rate = n_fwd / duration

        # 1. ICMP flood
        if proto == PROTO_ICMP and n_fwd > ICMP_FLOOD_THRESHOLD:
            triggered.append("icmp_flood")

        # 2. Port scan heuristic: many unique destination ports, few bytes
        # (Detected at the dispatcher level via host features — flagged here
        # if the single flow has suspiciously high port diversity.)
        # Proxy: high SYN count with low data
        if (flow_features is not None and
                flow_features[_IDX_SYN_FLAG_CNT] > PORT_SCAN_THRESHOLD and
                flow_features[_IDX_TOT_FWD_PKTS] < 5):
            triggered.append("syn_scan")

        # 3. Large payload
        if record.fwd_lengths:
            max_fwd = max(record.fwd_lengths)
            if max_fwd > LARGE_PAYLOAD_BYTES:
                triggered.append("large_payload")

        # 4. Payload signatures
        for match in payload_matches:
            triggered.append(f"payload:{match}")

        # 5. Asymmetric traffic (potential exfiltration): much more upload than download
        if n_fwd > 10 and n_bwd > 0:
            ratio = sum(record.fwd_lengths) / max(sum(record.bwd_lengths), 1)
            if ratio > 50:
                triggered.append("asymmetric_upload")

        # 6. Malicious JA3 fingerprint
        if ja3_info and ja3_info.get("malicious"):
            triggered.append("malicious_ja3")

        score = 1.0 if triggered else 0.0
        return score, triggered
