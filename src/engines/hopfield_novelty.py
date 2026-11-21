"""Hopfield novelty scorer (Simplified Hopfield Energy) over FT-Transformer embeddings.

Shadow-mode signal: it is computed and logged but carries no ensemble weight.

Each known class c is stored as one pattern xi_c, the L2-normalised mean of the
CLS embeddings of its training flows. A flow with embedding q scores

    novelty(q) = -1/beta * logsumexp(beta * <q_hat, xi_c>)

i.e. the energy of a modern Hopfield network whose memories are the class
prototypes. Higher = further from every class the model was trained on.

Same maths as ``HopfieldOOD(mode="she")`` in scikit-hopfield (``ood.py``), vendored
here (a few lines) because that package is not on PyPI and cnds installs from
hashed, per-architecture lock files. Validation that motivated it:
scikit-hopfield ``examples/cnds_ids_ood_validation`` (2026-10-25).

The prototypes are fitted offline by ``scripts/fit_hopfield_prototypes.py`` and
stored as a pickle-free ``.npz``. They only make sense for the exact weights they
were fitted on, so the file carries a fingerprint of the model and the scorer
refuses to run when it does not match the loaded checkpoint.
"""

from __future__ import annotations

import hashlib
import logging
import os
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

_EPS = 1e-12
REQUIRED_KEYS = ("prototypes", "beta", "threshold", "fingerprint", "class_labels")


def model_fingerprint(cls_token: np.ndarray, head_weight: np.ndarray) -> str:
    """sha256 over the CLS token and classification head weights (float32 bytes)."""
    h = hashlib.sha256()
    for arr in (cls_token, head_weight):
        a = np.ascontiguousarray(np.asarray(arr, dtype=np.float32))
        h.update(str(a.shape).encode())
        h.update(a.tobytes())
    return h.hexdigest()


def l2_normalize(x: np.ndarray) -> np.ndarray:
    x = np.asarray(x, dtype=np.float64)
    return x / np.maximum(np.linalg.norm(x, axis=-1, keepdims=True), _EPS)


def she_energy(embeddings: np.ndarray, prototypes: np.ndarray, beta: float) -> np.ndarray:
    """-1/beta * logsumexp(beta * q_hat . P^T) for each row of ``embeddings``."""
    q = l2_normalize(np.atleast_2d(embeddings))
    sim = beta * (q @ np.asarray(prototypes, dtype=np.float64).T)
    m = sim.max(axis=1, keepdims=True)
    lse = (m + np.log(np.exp(sim - m).sum(axis=1, keepdims=True)))[:, 0]
    return -lse / beta


class HopfieldNoveltyScorer:
    """Loads SHE prototypes and scores embeddings; disabled unless everything checks out."""

    def __init__(self, path: str, expected_fingerprint: Optional[str], expected_dim: Optional[int]):
        self.prototypes: Optional[np.ndarray] = None
        self.beta: float = 0.0
        self.threshold: float = float("inf")
        self.class_labels: tuple = ()
        self._load(path, expected_fingerprint, expected_dim)

    @property
    def is_available(self) -> bool:
        return self.prototypes is not None

    def _load(self, path: str, expected_fingerprint: Optional[str], expected_dim: Optional[int]) -> None:
        if not os.path.exists(path):
            logger.info("Hopfield novelty disabled: no prototypes at %s", path)
            return
        try:
            with np.load(path, allow_pickle=False) as data:
                missing = [k for k in REQUIRED_KEYS if k not in data.files]
                if missing:
                    raise ValueError(f"missing keys {missing}")
                prototypes = np.asarray(data["prototypes"], dtype=np.float64)
                beta = float(data["beta"])
                threshold = float(data["threshold"])
                fingerprint = str(data["fingerprint"])
                labels = tuple(str(s) for s in data["class_labels"])
        except Exception as e:  # corrupt file, wrong format, pickled arrays
            logger.warning("Hopfield novelty disabled: cannot read %s (%s)", path, e)
            return

        problem = None
        if prototypes.ndim != 2 or prototypes.shape[0] == 0:
            problem = f"prototypes must be 2-D and non-empty, got shape {prototypes.shape}"
        elif expected_dim is not None and prototypes.shape[1] != expected_dim:
            problem = f"prototype dim {prototypes.shape[1]} != embedding dim {expected_dim}"
        elif not np.isfinite(prototypes).all() or not np.isfinite([beta, threshold]).all():
            problem = "non-finite values"
        elif beta <= 0:
            problem = f"beta must be > 0, got {beta}"
        elif len(labels) != prototypes.shape[0]:
            problem = f"{len(labels)} class labels for {prototypes.shape[0]} prototypes"
        elif expected_fingerprint is None or fingerprint != expected_fingerprint:
            problem = "fitted on a different model (fingerprint mismatch); refit with scripts/fit_hopfield_prototypes.py"
        if problem:
            logger.warning("Hopfield novelty disabled: %s (%s)", problem, path)
            return

        self.prototypes = l2_normalize(prototypes)
        self.beta = beta
        self.threshold = threshold
        self.class_labels = labels
        logger.info(
            "Hopfield novelty ready (shadow mode)  prototypes=%d  beta=%g  threshold=%.4f",
            prototypes.shape[0], beta, threshold,
        )

    def score(self, embedding: np.ndarray) -> Optional[float]:
        """Novelty of one embedding, or None when the scorer is disabled."""
        if self.prototypes is None:
            return None
        return float(she_energy(embedding, self.prototypes, self.beta)[0])

    def is_novel(self, score: Optional[float]) -> bool:
        return score is not None and score >= self.threshold
