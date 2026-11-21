"""Integration tests for the FT-Transformer supervised engine.

These tests exercise the full inference path (load → scaler → torch forward →
softmax → label) against real samples from the unified dataset.  They are
skipped automatically when:
  - torch is not installed in the active environment, or
  - the unified checkpoint at models/unified/ is absent, or
  - the dataset is not available: the two tests that read it need
    CNDS_TEST_DATA_DIR to point at a directory with Data.csv and Label.csv
    (the CIC-UNSW-NB15 redistribution).
"""

import os
from pathlib import Path

import numpy as np
import pytest

REPO = Path(__file__).resolve().parents[1]
CKPT = REPO / "models" / "unified" / "unified_ft_transformer.pt"
_DATA_DIR = os.getenv("CNDS_TEST_DATA_DIR", "")
DATA = Path(_DATA_DIR) if _DATA_DIR else None
_NO_DATA = DATA is None or not (DATA / "Data.csv").exists()
_NO_DATA_REASON = "set CNDS_TEST_DATA_DIR to a directory with Data.csv and Label.csv"

torch = pytest.importorskip("torch")

if not CKPT.exists():
    pytest.skip(
        f"Unified FT-Transformer checkpoint not present at {CKPT}",
        allow_module_level=True,
    )


@pytest.fixture(scope="module", autouse=True)
def _ensure_real_torch():
    """Sanity-check that real torch is in sys.modules.

    `tests/engines/test_baseline_engine.py` swaps in a fake torch module
    via a function-scoped fixture and restores it on teardown, so by the
    time tests in this file run, sys.modules["torch"] should already be
    the real module. If a stub somehow leaked we skip the test rather
    than reload (reloading torch breaks its `torch._C` C extension and
    poisons later tests like test_window_stability).
    """
    import sys

    torch_mod = sys.modules.get("torch")
    if torch_mod is None or not getattr(torch_mod, "__file__", None):
        pytest.skip("real torch not available (fake stub leaked from another test)")
    yield


@pytest.fixture(scope="module")
def engine():
    """Build the FT engine pointing explicitly at the on-disk checkpoint.

    The shared conftest sets FT_MODEL_FILE=__disabled_in_tests__ to prevent the
    registry singleton from importing real torch during collection (which would
    break test_baseline_engine's fake-torch fixture). We bypass that here by
    passing the real paths to the constructor directly.

    Wrapped in ``torch.no_grad()`` because earlier test modules can leave
    autograd state in a configuration that breaks Parameter creation during
    in-place init (`nn.init.kaiming_uniform_`).
    """
    from src.engines.ft_transformer_engine import FTTransformerEngine
    with torch.no_grad():
        eng = FTTransformerEngine(
            model_path=str(CKPT),
            scaler_path=str(REPO / "models" / "unified" / "unified_scaler.pkl"),
            use_gpu=False,
        )
    if not eng.is_available:
        pytest.skip("FT engine could not load (model or scaler missing)")
    return eng


def test_loads_with_correct_shape(engine):
    assert engine.is_available
    assert engine._n_features == 76
    assert len(engine._labels) == 10
    assert engine._labels[0] == "Benign"


def test_predict_zero_vector_returns_label_and_confidence(engine):
    out = engine.predict(np.zeros(76, dtype=np.float32))
    assert out is not None
    label, conf = out
    assert isinstance(label, str)
    assert 0.0 <= conf <= 1.0


def test_anomaly_score_zero_vector_in_unit_range(engine):
    s = engine.anomaly_score(np.zeros(76, dtype=np.float32))
    assert 0.0 <= s <= 1.0


def test_handles_nan_inf_safely(engine):
    v = np.full(76, np.nan, dtype=np.float32)
    v[0] = np.inf
    v[1] = -np.inf
    out = engine.predict(v)
    assert out is not None  # nan_to_num must keep the forward pass alive


def test_rejects_wrong_feature_count(engine):
    with pytest.raises(ValueError):
        engine._forward(np.zeros(75, dtype=np.float32))


@pytest.mark.skipif(_NO_DATA, reason=_NO_DATA_REASON)
def test_classifies_benign_majority(engine):
    """Take N=200 known-Benign rows, expect >=90% predicted as Benign."""
    import pandas as pd

    X = pd.read_csv(DATA / "Data.csv").values.astype(np.float32)
    y = pd.read_csv(DATA / "Label.csv").values.ravel().astype(np.int64)
    benign_idx = np.where(y == 0)[0][:200]
    correct = 0
    for i in benign_idx:
        label, _ = engine.predict(X[i])
        if label == "Benign":
            correct += 1
    assert correct / len(benign_idx) >= 0.90, (
        f"Expected >=90% benign-correct, got {correct}/{len(benign_idx)}"
    )


@pytest.mark.skipif(_NO_DATA, reason=_NO_DATA_REASON)
def test_classifies_attack_majority_non_benign(engine):
    """For each attack class with >=50 samples, expect <50% predicted as Benign.

    A coarse but stable check that the engine flags attack-shaped flows
    rather than falling through to the benign label everywhere.
    """
    import pandas as pd

    X = pd.read_csv(DATA / "Data.csv").values.astype(np.float32)
    y = pd.read_csv(DATA / "Label.csv").values.ravel().astype(np.int64)

    rng = np.random.default_rng(42)
    failures = []
    for c in range(1, 10):  # skip 0 (Benign)
        idx = np.where(y == c)[0]
        if len(idx) < 50:
            continue
        sample = rng.choice(idx, size=min(100, len(idx)), replace=False)
        benign_count = 0
        for i in sample:
            label, _ = engine.predict(X[i])
            if label == "Benign":
                benign_count += 1
        if benign_count / len(sample) >= 0.5:
            failures.append((c, benign_count, len(sample)))
    assert not failures, (
        f"Classes mostly mislabelled as Benign: {failures}"
    )


# ── Hopfield novelty (shadow mode) ───────────────────────────────────────────

PROTOS = REPO / "models" / "unified" / "she_prototypes.npz"


def test_embedding_path_matches_model_forward(engine):
    """_forward_with_embedding must reproduce FTTransformer.forward exactly."""
    rng = np.random.default_rng(0)
    for _ in range(5):
        x = rng.normal(size=76).astype(np.float32) * 100
        probs_ref = engine._forward(x)
        probs, emb = engine._forward_with_embedding(x)
        assert np.allclose(probs, probs_ref, atol=1e-6)
        assert emb.shape == (engine._model.head.in_features,)


def test_predict_with_novelty_agrees_with_predict(engine):
    x = np.zeros(76, dtype=np.float32)
    label, conf = engine.predict(x)
    label2, conf2, _ = engine.predict_with_novelty(x)
    assert label2 == label
    assert conf2 == pytest.approx(conf, abs=1e-6)


def test_fingerprint_is_stable_hex(engine):
    assert engine.fingerprint is not None and len(engine.fingerprint) == 64
    int(engine.fingerprint, 16)


@pytest.mark.skipif(not PROTOS.exists(), reason="she_prototypes.npz not fitted")
def test_shipped_prototypes_match_this_checkpoint():
    from src.engines.ft_transformer_engine import FTTransformerEngine
    with torch.no_grad():
        eng = FTTransformerEngine(
            model_path=str(CKPT),
            scaler_path=str(REPO / "models" / "unified" / "unified_scaler.pkl"),
            use_gpu=False,
            prototypes_path=str(PROTOS),
        )
    assert eng.novelty_scorer is not None, "prototypes were fitted on a different checkpoint"
    _, _, novelty = eng.predict_with_novelty(np.zeros(76, dtype=np.float32))
    assert novelty is not None and np.isfinite(novelty)


def test_novelty_disabled_by_flag():
    from src.engines.ft_transformer_engine import FTTransformerEngine
    with torch.no_grad():
        eng = FTTransformerEngine(
            model_path=str(CKPT),
            scaler_path=str(REPO / "models" / "unified" / "unified_scaler.pkl"),
            use_gpu=False,
            novelty_enabled=False,
            prototypes_path=str(PROTOS),
        )
    assert eng.novelty_scorer is None
    assert eng.fingerprint is not None
    assert eng.predict_with_novelty(np.zeros(76, dtype=np.float32))[2] is None
