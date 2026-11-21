"""Unit tests for the shadow-mode Hopfield novelty scorer (pure numpy, no torch)."""

import numpy as np
import pytest

from src.engines.hopfield_novelty import (
    HopfieldNoveltyScorer,
    l2_normalize,
    model_fingerprint,
    she_energy,
)

FP = "f" * 64
DIM = 8


def _protos(n=3, dim=DIM, seed=0):
    return l2_normalize(np.random.default_rng(seed).normal(size=(n, dim)))


def _write(path, **overrides):
    p = _protos()
    data = dict(
        prototypes=p,
        beta=np.float64(32.0),
        threshold=np.float64(-0.5),
        fingerprint=np.str_(FP),
        class_labels=np.array([f"c{i}" for i in range(len(p))], dtype=np.str_),
    )
    data.update(overrides)
    data = {k: v for k, v in data.items() if v is not None}
    np.savez(path, **data)
    return path


def _scorer(path, fp=FP, dim=DIM):
    return HopfieldNoveltyScorer(str(path), expected_fingerprint=fp, expected_dim=dim)


# ── maths ────────────────────────────────────────────────────────────────────

def test_energy_lower_near_a_prototype_than_far_from_all():
    P = _protos()
    near = P[1] * 5.0                     # scale must not matter (L2-normalised)
    far = -P.sum(axis=0)                  # points away from every prototype
    e_near, e_far = she_energy(np.vstack([near, far]), P, beta=32.0)
    assert e_near < e_far


def test_energy_matches_reference_formula():
    P = _protos()
    q = np.random.default_rng(1).normal(size=DIM)
    beta = 8.0
    ref = -np.log(np.exp(beta * (l2_normalize(q) @ P.T)).sum()) / beta
    assert she_energy(q, P, beta)[0] == pytest.approx(ref, rel=1e-12)


def test_energy_is_stable_for_large_beta():
    P = _protos()
    out = she_energy(P, P, beta=1e6)
    assert np.isfinite(out).all()
    assert out == pytest.approx(-np.ones(len(P)), abs=1e-5)   # self-similarity 1 → energy -1


def test_fingerprint_changes_with_weights_and_shape():
    a = np.ones((1, 1, 4), dtype=np.float32)
    w = np.ones((10, 4), dtype=np.float32)
    base = model_fingerprint(a, w)
    assert base == model_fingerprint(a.copy(), w.copy())
    w2 = w.copy()
    w2[0, 0] = 1.0001
    assert model_fingerprint(a, w2) != base
    assert model_fingerprint(a.reshape(1, 4), w) != base


# ── loading ──────────────────────────────────────────────────────────────────

def test_loads_and_scores(tmp_path):
    s = _scorer(_write(tmp_path / "p.npz"))
    assert s.is_available
    assert s.class_labels == ("c0", "c1", "c2")
    assert s.beta == 32.0
    score = s.score(np.ones(DIM))
    assert isinstance(score, float)
    assert s.is_novel(score) == (score >= -0.5)


def test_missing_file_disables(tmp_path):
    s = _scorer(tmp_path / "absent.npz")
    assert not s.is_available
    assert s.score(np.ones(DIM)) is None
    assert s.is_novel(None) is False


@pytest.mark.parametrize("kwargs, fp, dim", [
    ({}, "0" * 64, DIM),                                      # fitted on another model
    ({}, None, DIM),                                          # engine could not fingerprint
    ({}, FP, DIM + 1),                                        # embedding size changed
    ({"prototypes": np.full((3, DIM), np.nan)}, FP, DIM),     # non-finite
    ({"beta": np.float64(0.0)}, FP, DIM),
    ({"threshold": np.float64(np.inf)}, FP, DIM),
    ({"class_labels": np.array(["a"], dtype=np.str_)}, FP, DIM),
    ({"fingerprint": None}, FP, DIM),                         # required key missing
    ({"prototypes": np.zeros((0, DIM))}, FP, DIM),
])
def test_invalid_artifact_disables(tmp_path, kwargs, fp, dim):
    s = _scorer(_write(tmp_path / "p.npz", **kwargs), fp=fp, dim=dim)
    assert not s.is_available


def test_pickled_arrays_are_refused(tmp_path):
    path = tmp_path / "p.npz"
    np.savez(
        path,
        prototypes=np.array([object()], dtype=object),   # needs pickle to load
        beta=np.float64(32.0),
        threshold=np.float64(0.0),
        fingerprint=np.str_(FP),
        class_labels=np.array(["a"], dtype=np.str_),
    )
    assert not _scorer(path).is_available


def test_corrupt_file_disables(tmp_path):
    path = tmp_path / "p.npz"
    path.write_bytes(b"not an npz")
    assert not _scorer(path).is_available
