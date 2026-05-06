"""API exerciser — hits all ~18 CNDS REST endpoints and validates responses.

Designed to run after traffic generators have populated the database with
alerts so that GET endpoints return meaningful data.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class EndpointResult:
    method: str
    path: str
    status: int = 0
    passed: bool = False
    error: Optional[str] = None


@dataclass
class ExerciserReport:
    results: List[EndpointResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return self.total - self.passed


async def exercise_api(
    base_url: str = "http://localhost:8000",
    timeout: float = 10,
) -> ExerciserReport:
    """Exercise all CNDS API endpoints and validate responses."""
    report = ExerciserReport()

    async with httpx.AsyncClient(base_url=base_url, timeout=timeout) as c:
        # 1. GET /health
        report.results.append(await _check(c, "GET", "/health", expect_keys=["status", "engines"]))

        # 2. POST /api/predict
        predict_body = {
            "src_ip": "192.168.1.200",
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "protocol": 6,
            "host_features": [10.0] * 18,
        }
        report.results.append(await _check(
            c, "POST", "/api/predict", json=predict_body,
            expect_keys=["src_ip", "ensemble_score", "is_anomaly"],
        ))

        # 3. GET /api/alerts
        report.results.append(await _check(c, "GET", "/api/alerts", expect_list=True))

        # 4. GET /api/alerts?severity=high
        report.results.append(await _check(c, "GET", "/api/alerts?severity=high", expect_list=True))

        # 5. GET /api/alerts/trends
        report.results.append(await _check(c, "GET", "/api/alerts/trends", expect_keys=["bucket", "data"]))

        # 6. GET /api/stats
        report.results.append(await _check(c, "GET", "/api/stats", expect_keys=["total_alerts", "by_severity"]))

        # 7. GET /api/alerts/{id} — get first alert if exists
        alert_id = await _get_first_alert_id(c)
        if alert_id:
            report.results.append(await _check(c, "GET", f"/api/alerts/{alert_id}", expect_keys=["id", "src_ip"]))

            # 8. PATCH /api/alerts/{id}
            report.results.append(await _check(
                c, "PATCH", f"/api/alerts/{alert_id}",
                json={"acknowledged": True, "notes": "sandbox test"},
                expect_keys=["id", "acknowledged"],
            ))
        else:
            report.results.append(EndpointResult("GET", "/api/alerts/{id}", error="no alerts to test"))
            report.results.append(EndpointResult("PATCH", "/api/alerts/{id}", error="no alerts to test"))

        # 9. GET /api/alerts/export?format=json
        report.results.append(await _check(c, "GET", "/api/alerts/export?format=json", expect_status=200))

        # 10. GET /api/alerts/export?format=csv
        report.results.append(await _check(c, "GET", "/api/alerts/export?format=csv", expect_status=200))

        # 11. GET /api/incidents
        report.results.append(await _check(c, "GET", "/api/incidents", expect_list=True))

        # 12. POST /api/incidents
        report.results.append(await _check(
            c, "POST", "/api/incidents",
            json={"title": "Sandbox test incident", "severity": "medium"},
            expect_keys=["id", "title"], expect_status=201,
        ))

        # 13. GET /api/suppression-rules
        report.results.append(await _check(c, "GET", "/api/suppression-rules", expect_list=True))

        # 14. POST /api/suppression-rules
        report.results.append(await _check(
            c, "POST", "/api/suppression-rules",
            json={"src_ip": "10.99.99.99", "reason": "sandbox test", "duration_minutes": 5},
            expect_keys=["id", "expires_at"], expect_status=201,
        ))

        # 15. GET /api/adaptive-weights
        report.results.append(await _check(c, "GET", "/api/adaptive-weights", expect_keys=["status"]))

        # 16. GET /api/dns-log
        report.results.append(await _check(c, "GET", "/api/dns-log", expect_status=200))

        # 17. GET /api/baseline/status
        report.results.append(await _check(c, "GET", "/api/baseline/status", expect_status=200))

        # 18. POST /api/auth/token (expect 501 if JWT not configured, or 401 with bad creds)
        report.results.append(await _check(
            c, "POST", "/api/auth/token",
            json={"username": "test", "password": "test"},
            expect_status=[401, 501],
        ))

    logger.info("API exerciser: %d/%d passed", report.passed, report.total)
    return report


async def _get_first_alert_id(client: httpx.AsyncClient) -> Optional[int]:
    try:
        resp = await client.get("/api/alerts", params={"limit": 1})
        if resp.status_code == 200:
            alerts = resp.json()
            if alerts:
                return alerts[0]["id"]
    except Exception:
        pass
    return None


async def _check(
    client: httpx.AsyncClient,
    method: str,
    path: str,
    json: dict = None,
    expect_keys: List[str] = None,
    expect_list: bool = False,
    expect_status: int | List[int] = 200,
) -> EndpointResult:
    """Make a request and validate the response."""
    result = EndpointResult(method=method, path=path)
    try:
        if method == "GET":
            resp = await client.get(path)
        elif method == "POST":
            resp = await client.post(path, json=json)
        elif method == "PATCH":
            resp = await client.patch(path, json=json)
        else:
            resp = await client.request(method, path, json=json)

        result.status = resp.status_code

        # Check status
        valid_statuses = expect_status if isinstance(expect_status, list) else [expect_status]
        if resp.status_code not in valid_statuses:
            result.error = f"expected status {valid_statuses}, got {resp.status_code}"
            return result

        # Validate response body
        if expect_keys or expect_list:
            data = resp.json()
            if expect_list and not isinstance(data, list):
                result.error = "expected list response"
                return result
            if expect_keys and isinstance(data, dict):
                missing = [k for k in expect_keys if k not in data]
                if missing:
                    result.error = f"missing keys: {missing}"
                    return result

        result.passed = True
    except Exception as e:
        result.error = str(e)

    return result
