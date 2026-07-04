"""Mitigation backends for the guardian auto-response module (Phase 10).

Each backend implements block()/unblock() for a src_ip. Callers (engine.py)
are responsible for catching exceptions — a failed block() must not result in
a MitigationAction row that falsely claims the device was blocked.
"""

import logging
from typing import Protocol, Tuple

import httpx

from ..config import ADGUARD_URL, ADGUARD_USERNAME, ADGUARD_PASSWORD

logger = logging.getLogger(__name__)


class MitigationBackend(Protocol):
    async def block(self, ip: str, reason: str) -> None: ...
    async def unblock(self, ip: str) -> None: ...


class AdGuardBackend:
    """DNS-level blocking via AdGuard Home's access-control list.

    AdGuard has no incremental add/remove endpoint — POST /control/access/set
    always replaces the full {allowed_clients, disallowed_clients,
    blocked_hosts} payload, so block()/unblock() must read-modify-write.
    """

    _LIST_URL = "/control/access/list"
    _SET_URL = "/control/access/set"

    def __init__(self):
        # httpx accepts a plain (user, pass) tuple; empty strings behave the
        # same as "unset" (AdGuard rejects with 401, same as today's default).
        self._auth: Tuple[str, str] = (ADGUARD_USERNAME, ADGUARD_PASSWORD)

    async def _get_list(self, client: httpx.AsyncClient) -> dict:
        resp = await client.get(f"{ADGUARD_URL}{self._LIST_URL}", auth=self._auth)
        resp.raise_for_status()
        return resp.json()

    async def _set_list(self, client: httpx.AsyncClient, current: dict) -> None:
        resp = await client.post(f"{ADGUARD_URL}{self._SET_URL}", auth=self._auth, json=current)
        resp.raise_for_status()

    async def block(self, ip: str, reason: str = "") -> None:
        async with httpx.AsyncClient(timeout=10.0) as client:
            current = await self._get_list(client)
            disallowed = current.setdefault("disallowed_clients", [])
            if ip not in disallowed:
                disallowed.append(ip)
                await self._set_list(client, current)
        logger.info("AdGuard: blocked %s (%s)", ip, reason)

    async def unblock(self, ip: str) -> None:
        async with httpx.AsyncClient(timeout=10.0) as client:
            current = await self._get_list(client)
            disallowed = current.setdefault("disallowed_clients", [])
            if ip in disallowed:
                disallowed.remove(ip)
                await self._set_list(client, current)
        logger.info("AdGuard: unblocked %s", ip)
