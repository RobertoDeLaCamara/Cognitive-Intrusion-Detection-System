"""Pickle model artifacts are verified against a SHA-256 manifest before joblib.load."""

import joblib
import pytest

from src import model_integrity as mi


@pytest.fixture
def models(tmp_path):
    joblib.dump({"ok": 1}, tmp_path / "m.joblib")
    return tmp_path


def _kw(models, mode="auto"):
    return dict(mode=mode, models_dir=str(models), manifest_path=str(models / "MANIFEST.sha256"))


def _write_manifest(models, digest=None):
    d = digest or mi.sha256_file(str(models / "m.joblib"))
    (models / "MANIFEST.sha256").write_text(f"{d}  m.joblib\n")


def test_matching_hash_loads(models):
    _write_manifest(models)
    assert mi.load_joblib(str(models / "m.joblib"), **_kw(models)) == {"ok": 1}


def test_tampered_file_is_refused_before_unpickling(models):
    _write_manifest(models)
    (models / "m.joblib").write_bytes(b"not what was hashed")
    with pytest.raises(mi.ModelIntegrityError, match="does not match"):
        mi.load_joblib(str(models / "m.joblib"), **_kw(models))


def test_file_missing_from_manifest_is_refused(models):
    (models / "MANIFEST.sha256").write_text(f"{'0' * 64}  other.joblib\n")
    with pytest.raises(mi.ModelIntegrityError, match="not listed"):
        mi.verify(str(models / "m.joblib"), **_kw(models))


def test_auto_without_manifest_loads_unverified(models):
    assert mi.load_joblib(str(models / "m.joblib"), **_kw(models)) == {"ok": 1}


def test_enforce_without_manifest_is_refused(models):
    with pytest.raises(mi.ModelIntegrityError, match="not found"):
        mi.verify(str(models / "m.joblib"), **_kw(models, "enforce"))


def test_off_skips_checks_even_on_mismatch(models):
    _write_manifest(models, "0" * 64)
    mi.verify(str(models / "m.joblib"), **_kw(models, "off"))


def test_path_outside_models_dir_is_not_listed(models, tmp_path_factory):
    _write_manifest(models)
    other = tmp_path_factory.mktemp("elsewhere") / "m.joblib"
    joblib.dump({"ok": 1}, other)
    with pytest.raises(mi.ModelIntegrityError, match="not listed"):
        mi.verify(str(other), **_kw(models))
