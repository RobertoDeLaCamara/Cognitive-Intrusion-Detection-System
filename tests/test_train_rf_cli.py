"""CLI contract of scripts/train_rf.py: no machine-specific defaults, clear error without imbalanced-learn."""
import importlib.util
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("train_rf", ROOT / "scripts" / "train_rf.py")
train_rf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(train_rf)


def test_data_dir_is_required(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["train_rf.py"])
    with pytest.raises(SystemExit) as exc:
        train_rf.main()
    assert exc.value.code == 2
    assert "--data-dir" in capsys.readouterr().err


def test_smote_without_imbalanced_learn_names_the_fix(monkeypatch):
    # A None entry in sys.modules makes the import raise ImportError.
    monkeypatch.setitem(sys.modules, "imblearn", None)
    monkeypatch.setitem(sys.modules, "imblearn.over_sampling", None)
    with pytest.raises(SystemExit) as exc:
        train_rf.apply_smote(np.zeros((4, 2), dtype=np.float32), np.array(["Benign"] * 4))
    assert "imbalanced-learn" in str(exc.value.code)
    assert "--no-smote" in str(exc.value.code)
