"""The dashboard's API client authenticates the way the API requires (cnds#21)."""

from dashboard.api_client import ApiClient


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


class FakeSession:
    """Records every request and answers from a script of (matcher, response)."""

    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.handler(method, url, kwargs)


def client(handler, **kw):
    session = FakeSession(handler)
    return ApiClient("http://api:8000/", session=session, **kw), session


def test_open_api_sends_no_credentials():
    c, s = client(lambda m, u, k: FakeResponse(200, {"ok": 1}))
    assert c.get("/api/stats").json() == {"ok": 1}
    method, url, kw = s.calls[0]
    assert (method, url) == ("GET", "http://api:8000/api/stats")  # trailing slash handled
    assert kw["headers"] == {}


def test_api_key_is_sent_as_header():
    c, s = client(lambda m, u, k: FakeResponse(), api_key="k3y")
    c.get("/api/alerts", params={"limit": 5})
    _, _, kw = s.calls[0]
    assert kw["headers"] == {"X-API-Key": "k3y"}
    assert kw["params"] == {"limit": 5}


def jwt_handler(valid_token="tok-1", logins=None):
    state = {"token": valid_token}

    def handler(method, url, kw):
        if url.endswith("/api/auth/token"):
            if logins is not None:
                logins.append(kw["json"])
            if kw["json"]["password"] != "pw":
                return FakeResponse(401)
            return FakeResponse(200, {"access_token": state["token"]})
        sent = kw["headers"].get("Authorization")
        if sent == f"Bearer {state['token']}":
            return FakeResponse(200, {"data": 1})
        return FakeResponse(401)
    return handler, state


def test_jwt_login_happens_once_and_token_is_reused():
    logins = []
    handler, _ = jwt_handler(logins=logins)
    c, s = client(handler, username="dash", password="pw")
    assert c.get("/api/stats").status_code == 200
    assert c.get("/api/alerts").status_code == 200
    assert logins == [{"username": "dash", "password": "pw"}]
    assert [m for m, u, _ in s.calls].count("POST") == 1


def test_expired_token_triggers_one_relogin_and_retry():
    handler, state = jwt_handler("old")
    c, s = client(handler, username="dash", password="pw")
    assert c.get("/api/stats").status_code == 200
    state["token"] = "new"             # the server now only accepts a fresh token
    resp = c.get("/api/stats")
    assert resp.status_code == 200
    assert c._token == "new"


def test_wrong_password_fails_without_looping():
    handler, _ = jwt_handler()
    c, s = client(handler, username="dash", password="wrong")
    assert c.get("/api/stats").status_code == 401
    # initial login + (401 -> login again) is the most it may try; never an endless loop
    assert len(s.calls) <= 4


def test_401_without_login_credentials_is_returned_as_is():
    c, s = client(lambda m, u, k: FakeResponse(401), api_key="bad")
    assert c.get("/api/stats").status_code == 401
    assert len(s.calls) == 1


def test_patch_is_sent_with_the_token():
    handler, _ = jwt_handler()
    c, s = client(lambda m, u, k: handler(m, u, k), username="dash", password="pw")
    c.patch("/api/alerts/7", json={"acknowledged": True})
    method, url, kw = s.calls[-1]
    assert (method, url) == ("PATCH", "http://api:8000/api/alerts/7")
    assert kw["headers"]["Authorization"] == "Bearer tok-1"
    assert kw["json"] == {"acknowledged": True}


def test_from_env(monkeypatch):
    monkeypatch.setenv("CNDS_API_KEY", "abc")
    monkeypatch.setenv("CNDS_API_USER", "u")
    monkeypatch.setenv("CNDS_API_PASSWORD", "p")
    c = ApiClient.from_env("http://x:1")
    assert (c.base_url, c.api_key, c.username, c.password) == ("http://x:1", "abc", "u", "p")
    assert c.uses_login


def test_login_network_error_does_not_raise():
    import requests

    def boom(m, u, k):
        if u.endswith("/api/auth/token"):
            raise requests.ConnectionError("down")
        return FakeResponse(401)

    c, _ = client(boom, username="dash", password="pw")
    assert c.get("/api/stats").status_code == 401
