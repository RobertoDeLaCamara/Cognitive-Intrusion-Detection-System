"""Drift detection between an ongoing collection window and the last trained baseline.

Compares the current CollectorSnapshot against the ProvenanceMetadata of the
most recently trained window to detect distributional shift. Returns None when
there is no baseline to compare against or too few samples are collected.

Drift score ∈ [0, 1]:
  0.4 × entropy_score   (abs delta in Shannon entropy, normalized to 2 bits)
  0.3 × ips_divergence  (relative change in distinct source IPs)
  0.3 × port_drift      (1 − Jaccard of top-20 destination ports)

Verdicts (thresholds configurable via config.py):
  nominal  — drift_score < BASELINE_DRIFT_WARN
  warning  — BASELINE_DRIFT_WARN ≤ drift_score < BASELINE_DRIFT_CRIT
  critical — drift_score ≥ BASELINE_DRIFT_CRIT
"""

from dataclasses import dataclass
from typing import Optional

from ..config import BASELINE_DRIFT_WARN, BASELINE_DRIFT_CRIT
from .collector import CollectorSnapshot

# Minimum vectors collected before drift is meaningful.
_MIN_VECTORS_FOR_DRIFT = 1_000


@dataclass
class DriftReport:
    dst_port_entropy_delta_bits: float
    distinct_src_ips_ratio: float   # current / last_baseline; 1.0 = identical
    top_ports_jaccard: float        # Jaccard similarity of top-20 port sets
    drift_score: float              # ∈ [0, 1]
    verdict: str                    # "nominal" | "warning" | "critical"


def compute_drift(
    snapshot: CollectorSnapshot,
    last_provenance: dict,
) -> Optional[DriftReport]:
    """Compute distributional drift between the current window and the last baseline.

    Args:
        snapshot: live snapshot from BaselineCollector.snapshot()
        last_provenance: provenance dict from WindowTrainer.get_history()[-1]["provenance"]

    Returns None when too few vectors have been collected or provenance is missing.
    """
    if snapshot is None or last_provenance is None:
        return None
    if snapshot.n_total < _MIN_VECTORS_FOR_DRIFT:
        return None

    # ── Entropy delta ─────────────────────────────────────────────────────────
    prev_entropy = float(last_provenance.get("dst_port_entropy_bits", 0.0))
    entropy_delta = abs(snapshot.dst_port_entropy_bits - prev_entropy)
    # 2-bit delta → score 1.0; linear below that.
    entropy_score = min(entropy_delta / 2.0, 1.0)

    # ── Distinct-IP divergence ────────────────────────────────────────────────
    prev_ips = int(last_provenance.get("distinct_src_ips", 0)) or 1
    ips_ratio = snapshot.n_distinct_src_ips / prev_ips
    ips_divergence = min(abs(ips_ratio - 1.0), 1.0)

    # ── Jaccard over top-20 destination ports ─────────────────────────────────
    prev_top = {int(p) for p, _ in last_provenance.get("top_dst_ports", [])}
    curr_top = set(snapshot.top_dst_ports)
    if prev_top or curr_top:
        intersection = len(prev_top & curr_top)
        union = len(prev_top | curr_top)
        jaccard = intersection / union if union > 0 else 1.0
    else:
        jaccard = 1.0
    port_drift = 1.0 - jaccard

    # ── Combined score ────────────────────────────────────────────────────────
    drift_score = (
        0.4 * entropy_score
        + 0.3 * ips_divergence
        + 0.3 * port_drift
    )
    drift_score = max(0.0, min(1.0, drift_score))

    if drift_score >= BASELINE_DRIFT_CRIT:
        verdict = "critical"
    elif drift_score >= BASELINE_DRIFT_WARN:
        verdict = "warning"
    else:
        verdict = "nominal"

    return DriftReport(
        dst_port_entropy_delta_bits=entropy_delta,
        distinct_src_ips_ratio=ips_ratio,
        top_ports_jaccard=jaccard,
        drift_score=drift_score,
        verdict=verdict,
    )
