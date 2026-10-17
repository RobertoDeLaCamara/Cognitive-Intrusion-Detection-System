"""HTTP client the dashboard uses to talk to the CNDS REST API.

It authenticates the way the API is configured:

* ``CNDS_API_KEY``: sent as ``X-API-Key`` (API-key deployments).
* ``CNDS_API_USER`` + ``CNDS_API_PASSWORD``: the client logs in at ``/api/auth/token``
  and sends the JWT as a Bearer token (JWT deployments). Tokens expire, so a 401
  triggers one re-login and retry.

With none of them set it sends nothing, which only works when the API runs with
``AUTH_DISABLED=true``. The account needs the ``analyst`` or ``admin`` role to
acknowledge alerts; a ``viewer`` can read.
"""

import os
import threading
from typing import Optional

import requests


class ApiClient:
    def __init__(
        self,
        base_url: str,
        api_key: str = "",
        username: str = "",
        password: str = "",
        timeout: float = 5,
        session: Optional[requests.Session] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.username = username
        self.password = password
        self.timeout = timeout
        self._session = session or requests.Session()
        self._token: Optional[str] = None
        self._lock = threading.Lock()

    @classmethod
    def from_env(cls, base_url: Optional[str] = None) -> "ApiClient":
        return cls(
            base_url or os.getenv("CNDS_API_URL", "http://localhost:8000"),
            api_key=os.getenv("CNDS_API_KEY", ""),
            username=os.getenv("CNDS_API_USER", ""),
            password=os.getenv("CNDS_API_PASSWORD", ""),
        )

    @property
    def uses_login(self) -> bool:
        return bool(self.username and self.password)

    def _headers(self) -> dict:
        headers = {}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _login(self) -> bool:
        """Fetch a fresh JWT. Returns True on success."""
        with self._lock:
            try:
                resp = self._session.request(
                    "POST", f"{self.base_url}/api/auth/token",
                    json={"username": self.username, "password": self.password},
                    headers={"X-API-Key": self.api_key} if self.api_key else {},
                    timeout=self.timeout,
                )
                if resp.status_code == 200:
                    self._token = resp.json().get("access_token")
                    return bool(self._token)
            except (requests.RequestException, ValueError):
                pass
            self._token = None
            return False

    def request(self, method: str, path: str, **kwargs) -> requests.Response:
        """Send a request; on 401 with login credentials, log in again and retry once."""
        if self.uses_login and self._token is None:
            self._login()

        def send():
            return self._session.request(
                method, f"{self.base_url}{path}",
                headers=self._headers(), timeout=self.timeout, **kwargs,
            )

        resp = send()
        if resp.status_code == 401 and self.uses_login and self._login():
            resp = send()
        return resp

    def get(self, path: str, **kwargs) -> requests.Response:
        return self.request("GET", path, **kwargs)

    def patch(self, path: str, **kwargs) -> requests.Response:
        return self.request("PATCH", path, **kwargs)
