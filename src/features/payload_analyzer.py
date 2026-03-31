"""Payload pattern matching and numeric feature extraction.

Adapted from cognitive-anomaly-detector. Uses regex on bounded input (4KB max)
to remain safe in worker threads.
"""

import re
import numpy as np
from typing import List
from scapy.all import Raw
from .utils import byte_entropy


# Compiled patterns: (name, regex)
_PATTERNS: List[tuple] = [
    ("sql_injection",    re.compile(rb"(?:union\s+select|select\s+\*|drop\s+table|insert\s+into|delete\s+from|'.*?'|;--|xp_)", re.IGNORECASE)),
    ("xss",              re.compile(rb"(?:<script|javascript:|onerror=|onload=|<img\s|<svg\s|alert\()", re.IGNORECASE)),
    ("command_injection",re.compile(rb"(?:;\s*(?:ls|cat|wget|curl|bash|sh|python|perl)\b|&&\s*\w+|\|\s*\w+|`[^`]+`|\$\([^)]+\))", re.IGNORECASE)),
    ("path_traversal",   re.compile(rb"(?:\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e)", re.IGNORECASE)),
    ("log4j",            re.compile(rb"\$\{(?:jndi|env|sys|java):", re.IGNORECASE)),
    ("shellshock",       re.compile(rb"\(\s*\)\s*\{.*?;\s*\}", re.IGNORECASE)),
]

# Ordered pattern names for binary feature vector (indices 0-5)
PATTERN_NAMES = [name for name, _ in _PATTERNS]

PAYLOAD_FEATURE_NAMES = [
    "has_sqli", "has_xss", "has_cmdi", "has_traversal", "has_log4j", "has_shellshock",
    "pattern_match_count", "max_payload_entropy", "mean_payload_length", "suspicious_char_ratio",
]

# Quick pre-screen bytes to avoid regex overhead for clearly benign payloads
_PRESCREEN = re.compile(rb"(?:select|union|script|javascript|onerror|\.\.\/|jndi|\(\s*\)\s*\{|;\s*(?:ls|cat|wget))", re.IGNORECASE)


def analyze_payload(packet) -> List[str]:
    """Return list of matched attack pattern names for this packet."""
    if Raw not in packet:
        return []
    payload = packet[Raw].load
    if not payload:
        return []
    # Limit to first 4KB to bound matching time
    sample = payload[:4096]
    # Quick pre-screen: skip expensive per-pattern matching if no suspicious bytes
    if not _PRESCREEN.search(sample):
        return []
    matches = []
    for name, pattern in _PATTERNS:
        try:
            if pattern.search(sample):
                matches.append(name)
        except Exception:
            pass
    return matches


def _entropy(data: bytes) -> float:
    """Shannon entropy — delegates to shared utility."""
    return byte_entropy(data)


def _suspicious_char_ratio(data: bytes) -> float:
    """Fraction of non-printable / control characters (excluding common whitespace)."""
    if not data:
        return 0.0
    suspicious = sum(1 for b in data if b < 0x20 and b not in (0x09, 0x0A, 0x0D))
    return suspicious / len(data)


def extract_payload_features(payloads: List[bytes]) -> np.ndarray:
    """Compute 10 numeric features from a flow's collected payload samples.

    Args:
        payloads: List of raw payload byte strings from forward packets.

    Returns:
        np.ndarray of shape (10,) with dtype float32.
    """
    features = np.zeros(10, dtype=np.float32)
    if not payloads:
        return features

    # Run pattern matching across all payloads
    matched_set: set = set()
    for payload in payloads:
        sample = payload[:4096]
        for name, pattern in _PATTERNS:
            if name not in matched_set:
                try:
                    if pattern.search(sample):
                        matched_set.add(name)
                except Exception:
                    pass

    # Indices 0-5: binary flags per pattern
    for i, name in enumerate(PATTERN_NAMES):
        features[i] = 1.0 if name in matched_set else 0.0

    # Index 6: total distinct patterns matched
    features[6] = float(len(matched_set))

    # Index 7: max entropy across payloads
    features[7] = max(_entropy(p[:4096]) for p in payloads)

    # Index 8: mean payload length
    features[8] = float(np.mean([len(p) for p in payloads]))

    # Index 9: suspicious char ratio (across concatenated payloads, capped)
    combined = b"".join(p[:4096] for p in payloads)[:16384]
    features[9] = _suspicious_char_ratio(combined)

    return features
