"""Optional on-disk copy of each collected baseline window, for offline evaluation.

Off unless ``BASELINE_DUMP_DIR`` is set. Written from the training thread, never on the
capture hot path, and best effort: a failure here must not stop training. One compressed
``.npz`` per window (host vectors, source IP, timestamp, destination port, protocol).
"""

import logging
import os
from pathlib import Path
from typing import List, Tuple

import numpy as np

logger = logging.getLogger(__name__)

PREFIX = "window-"


def dump_window(directory: str, samples: list, window_start_ts: float, keep: int = 48) -> str:
    """Write ``samples`` (``CollectedSample`` list) to ``directory``; return the file path.

    Keeps only the newest ``keep`` files (0 = keep all). Raises on I/O errors, callers log them.
    """
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{PREFIX}{int(window_start_ts)}-{len(samples)}.npz"
    tmp = d / (path.name + ".tmp")
    with open(tmp, "wb") as f:
        np.savez_compressed(
            f,
            X=np.stack([s.host_vec for s in samples]).astype(np.float32),
            src_ip=np.asarray([s.src_ip for s in samples]),
            ts=np.asarray([s.ts_epoch for s in samples], dtype=np.float64),
            dst_port=np.asarray([s.dst_port for s in samples], dtype=np.int32),
            protocol=np.asarray([s.protocol for s in samples]),
        )
    os.replace(tmp, path)
    if keep > 0:
        files = sorted(d.glob(f"{PREFIX}*.npz"), key=lambda p: p.stat().st_mtime)
        for old in files[:-keep]:
            try:
                old.unlink()
            except OSError:
                logger.debug("could not remove old window dump %s", old)
    return str(path)


def load_windows(directory: str) -> List[Tuple[np.ndarray, np.ndarray, np.ndarray]]:
    """Load every dump in ``directory`` oldest first as ``(X, hosts, ts)`` tuples."""
    out = []
    for p in sorted(Path(directory).glob(f"{PREFIX}*.npz"), key=lambda q: q.stat().st_mtime):
        with np.load(p, allow_pickle=False) as z:
            out.append((z["X"].astype(np.float32), z["src_ip"].astype(str), z["ts"].astype(np.float64)))
    return out
