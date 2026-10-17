"""/ws/alerts authentication in each auth mode (cnds#25)."""

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import src.api.routers.websocket as ws_mod

KEY = "s3cret-key"


def make_client(monkeypatch, *, api_key="", jwt=False, valid_tokens=()):
    monkeypatch.setattr(ws_mod, "API_KEY", api_key)
    monkeypatch.setattr(ws_mod, "jwt_enabled", lambda: jwt)

    def fake_decode(token):
        if token in valid_tokens:
            return {"sub": "u"}
        raise ValueError("bad token")

    monkeypatch.setattr(ws_mod, "decode_token", fake_decode)
    app = FastAPI()
    app.include_router(ws_mod.router)
    return TestClient(app)


def denied_code(client, url, **kw):
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(url, **kw):
            pass
    return exc.value.code


def connects(client, url, **kw):
    with client.websocket_connect(url, **kw):
        return True


# --- API-key-only mode: the gap reported in cnds#25 ---------------------------

def test_api_key_mode_rejects_anonymous(monkeypatch):
    c = make_client(monkeypatch, api_key=KEY)
    assert denied_code(c, "/ws/alerts") == 4001


def test_api_key_mode_rejects_wrong_key(monkeypatch):
    c = make_client(monkeypatch, api_key=KEY)
    assert denied_code(c, "/ws/alerts?key=nope") == 4003
    assert denied_code(c, "/ws/alerts", headers={"X-API-Key": "nope"}) == 4003


def test_api_key_mode_accepts_header_and_query(monkeypatch):
    c = make_client(monkeypatch, api_key=KEY)
    assert connects(c, "/ws/alerts", headers={"X-API-Key": KEY})
    assert connects(c, f"/ws/alerts?key={KEY}")


def test_non_ascii_key_does_not_crash(monkeypatch):
    c = make_client(monkeypatch, api_key=KEY)
    assert denied_code(c, "/ws/alerts?key=cl%C3%A9") == 4003


# --- JWT-only mode: behaviour unchanged ---------------------------------------

def test_jwt_mode_missing_token(monkeypatch):
    c = make_client(monkeypatch, jwt=True)
    assert denied_code(c, "/ws/alerts") == 4001


def test_jwt_mode_invalid_token(monkeypatch):
    c = make_client(monkeypatch, jwt=True)
    assert denied_code(c, "/ws/alerts?token=junk") == 4003


def test_jwt_mode_valid_token(monkeypatch):
    c = make_client(monkeypatch, jwt=True, valid_tokens=("good",))
    assert connects(c, "/ws/alerts?token=good")


def test_jwt_mode_does_not_accept_an_api_key(monkeypatch):
    c = make_client(monkeypatch, jwt=True)
    assert denied_code(c, f"/ws/alerts?key={KEY}") == 4001


# --- both configured: either credential works ---------------------------------

def test_both_modes_accept_either_credential(monkeypatch):
    c = make_client(monkeypatch, api_key=KEY, jwt=True, valid_tokens=("good",))
    assert connects(c, "/ws/alerts?token=good")
    assert connects(c, "/ws/alerts", headers={"X-API-Key": KEY})
    assert denied_code(c, "/ws/alerts") == 4001
    assert denied_code(c, "/ws/alerts?token=bad") == 4003


# --- auth disabled -------------------------------------------------------------

def test_open_when_auth_is_disabled(monkeypatch):
    c = make_client(monkeypatch)
    assert connects(c, "/ws/alerts")
