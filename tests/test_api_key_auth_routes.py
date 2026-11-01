"""API-key middleware must guard /api/auth/users when JWT is off (user admin was open)."""

import hmac  # noqa: F401  (middleware imports it)

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

import src.api.main as main_mod

KEY = "k" * 32


@pytest.mark.parametrize("path,jwt,required", [
    ("/health", False, False),
    ("/api/auth/token", False, False),
    ("/api/auth/token", True, False),
    ("/api/auth/users", False, True),
    ("/api/auth/users/3", False, True),
    ("/api/auth/users", True, False),   # JWT on: require_role("admin") guards it
    ("/api/alerts", False, True),
    ("/api/alerts", True, True),
])
def test_api_key_required(path, jwt, required):
    assert main_mod.api_key_required(path, jwt) is required


def _client(monkeypatch, jwt):
    monkeypatch.setattr(main_mod, "jwt_auth_enabled", lambda: jwt)
    app = FastAPI()
    main_mod.install_api_key_middleware(app, KEY)

    @app.get("/api/auth/users")
    async def users():
        return ["x"]

    @app.post("/api/auth/token")
    async def token():
        return {"ok": 1}

    return TestClient(app)


def test_users_route_needs_key_without_jwt(monkeypatch):
    c = _client(monkeypatch, jwt=False)
    assert c.get("/api/auth/users").status_code == 401
    assert c.get("/api/auth/users", headers={"X-API-Key": "bad"}).status_code == 401
    assert c.get("/api/auth/users", headers={"X-API-Key": KEY}).status_code == 200


def test_login_stays_open(monkeypatch):
    c = _client(monkeypatch, jwt=False)
    assert c.post("/api/auth/token").status_code == 200
