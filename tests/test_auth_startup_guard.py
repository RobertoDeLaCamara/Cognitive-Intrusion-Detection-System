"""Startup guard: the API refuses to start without auth unless AUTH_DISABLED=true (cnds#20)."""

import logging
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

def _enforce_auth_configured(*args):
    # Imported at call time so the module stays collectable on a base without the guard.
    from src.api.main import _enforce_auth_configured as guard

    return guard(*args)


ROOT = Path(__file__).resolve().parent.parent
DISABLED_MSG = "authentication is disabled"


def _child_env(**overrides):
    env = dict(os.environ)
    for k in ("API_KEY", "JWT_SECRET", "AUTH_DISABLED"):
        env.pop(k, None)
    env["MLFLOW_TRACKING_URI"] = ""
    env["FT_MODEL_FILE"] = "__disabled_in_tests__"
    env.update(overrides)
    return env


# --- AC-1 / AC-5: refuses to start -------------------------------------------

def test_guard_refuses_without_credentials():
    with pytest.raises(SystemExit) as exc:
        _enforce_auth_configured("", "", False)
    msg = str(exc.value.code)
    assert "API_KEY" in msg
    assert "JWT_SECRET" in msg
    assert "AUTH_DISABLED" in msg


def test_api_import_exits_nonzero_without_auth():
    proc = subprocess.run(
        [sys.executable, "-c", "import src.api.main"],
        cwd=ROOT, env=_child_env(), capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode != 0
    for name in ("API_KEY", "JWT_SECRET", "AUTH_DISABLED"):
        assert name in proc.stderr


# --- AC-2 / AC-5: starts with credentials ------------------------------------

def test_guard_allows_api_key(caplog):
    with caplog.at_level(logging.WARNING):
        assert _enforce_auth_configured("k", "", False) is None
    assert DISABLED_MSG not in caplog.text.lower()


def test_guard_allows_jwt_secret(caplog):
    with caplog.at_level(logging.WARNING):
        assert _enforce_auth_configured("", "s", False) is None
    assert DISABLED_MSG not in caplog.text.lower()


def test_guard_credentials_win_over_auth_disabled(caplog):
    with caplog.at_level(logging.WARNING):
        assert _enforce_auth_configured("k", "", True) is None
    assert DISABLED_MSG not in caplog.text.lower()


def test_api_import_succeeds_with_api_key():
    proc = subprocess.run(
        [sys.executable, "-c", "import src.api.main"],
        cwd=ROOT, env=_child_env(API_KEY="k"), capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode == 0, proc.stderr[-1000:]


def test_api_import_succeeds_with_jwt_secret():
    proc = subprocess.run(
        [sys.executable, "-c", "import src.api.main"],
        cwd=ROOT, env=_child_env(JWT_SECRET="s" * 32), capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode == 0, proc.stderr[-1000:]


# --- AC-3 / AC-5: AUTH_DISABLED=true warns -----------------------------------

def test_guard_auth_disabled_warns(caplog):
    with caplog.at_level(logging.WARNING, logger="src.api.main"):
        assert _enforce_auth_configured("", "", True) is None
    assert DISABLED_MSG in caplog.text.lower()


def test_api_import_succeeds_with_auth_disabled():
    proc = subprocess.run(
        [sys.executable, "-c", "import src.api.main"],
        cwd=ROOT, env=_child_env(AUTH_DISABLED="true"), capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode == 0, proc.stderr[-1000:]


@pytest.mark.parametrize("value,expected", [
    ("true", "True"), ("TRUE", "True"), (" true ", "True"),
    ("false", "False"), ("1", "False"), ("yes", "False"), ("", "False"),
])
def test_auth_disabled_parsing(value, expected):
    proc = subprocess.run(
        [sys.executable, "-c", "from src.config import AUTH_DISABLED; print(AUTH_DISABLED)"],
        cwd=ROOT, env=_child_env(AUTH_DISABLED=value), capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr[-1000:]
    assert proc.stdout.strip().splitlines()[-1] == expected


# --- AC-4: config files -------------------------------------------------------

def test_env_sandbox_sets_auth_disabled():
    text = (ROOT / ".env.sandbox").read_text()
    assert re.search(r"^AUTH_DISABLED=true\s*$", text, re.M)


def test_sandbox_compose_sets_auth_disabled_in_api_service():
    text = (ROOT / "docker-compose.sandbox.yml").read_text()
    start = text.index("\n  api:")
    end = text.index("\n  detector:")
    assert 'AUTH_DISABLED: "true"' in text[start:end]


def test_production_compose_does_not_set_auth_disabled():
    assert "AUTH_DISABLED" not in (ROOT / "docker-compose.yml").read_text()


def test_env_example_documents_but_does_not_enable_auth_disabled():
    text = (ROOT / ".env.example").read_text()
    assert "AUTH_DISABLED" in text
    assert not re.search(r"^\s*AUTH_DISABLED\s*=\s*true", text, re.M | re.I)


def test_readme_documents_auth_disabled():
    assert "AUTH_DISABLED" in (ROOT / "README.md").read_text()
