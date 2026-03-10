"""Shared utility functions for CNDS feature extraction."""

import numpy as np


def byte_entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts / counts.sum()
    probs = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs)))
