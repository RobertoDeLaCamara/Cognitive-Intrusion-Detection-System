"""API access shared by every dashboard page (cached fetchers and write helpers)."""

import os
from typing import Any, Dict, List, Optional

import streamlit as st

try:
    from api_client import ApiClient          # `streamlit run dashboard/app.py`
except ImportError:                           # imported as a package
    from dashboard.api_client import ApiClient

API_URL = os.getenv("CNDS_API_URL", "http://localhost:8000")


@st.cache_resource
def get_api() -> ApiClient:
    """One client for the session: keeps the JWT between Streamlit reruns."""
    return ApiClient.from_env(API_URL)


@st.cache_data(ttl=5)
def fetch_stats() -> Optional[Dict[str, Any]]:
    try:
        return get_api().get("/api/stats").json()
    except Exception:
        return None


@st.cache_data(ttl=5)
def fetch_alerts(limit: int = 500, hours: Optional[int] = None) -> List[Dict[str, Any]]:
    params: Dict[str, Any] = {"limit": limit}
    if hours:
        params["hours"] = hours
    try:
        resp = get_api().get("/api/alerts", params=params)
        return resp.json() if resp.status_code == 200 else []
    except Exception:
        return []


@st.cache_data(ttl=30)
def fetch_trends(hours: int = 24, bucket: str = "hour") -> Optional[Dict[str, Any]]:
    try:
        return get_api().get("/api/alerts/trends", params={"hours": hours, "bucket": bucket}).json()
    except Exception:
        return None


@st.cache_data(ttl=5)
def fetch_alert(alert_id: int) -> Optional[Dict[str, Any]]:
    try:
        resp = get_api().get(f"/api/alerts/{alert_id}")
        return resp.json() if resp.status_code == 200 else None
    except Exception:
        return None


@st.cache_data(ttl=5)
def fetch_related(src_ip: str, limit: int = 50) -> List[Dict[str, Any]]:
    try:
        resp = get_api().get("/api/alerts", params={"src_ip": src_ip, "limit": limit})
        return resp.json() if resp.status_code == 200 else []
    except Exception:
        return []


@st.cache_data(ttl=10)
def fetch_incidents(limit: int = 200) -> List[Dict[str, Any]]:
    try:
        resp = get_api().get("/api/incidents", params={"limit": limit})
        return resp.json() if resp.status_code == 200 else []
    except Exception:
        return []


def update_alert(alert_id: int, **fields: Any) -> bool:
    """PATCH an alert; shows the reason in the UI and returns False on failure."""
    try:
        resp = get_api().patch(f"/api/alerts/{alert_id}", json=fields)
    except Exception as exc:
        st.error(f"Could not reach the API: {exc}")
        return False
    if resp.status_code in (401, 403):
        st.error("The dashboard account cannot modify alerts (it needs the analyst or admin role).")
        return False
    if resp.status_code != 200:
        st.error(f"Update failed (HTTP {resp.status_code}).")
        return False
    st.cache_data.clear()
    return True


def create_incident(title: str, severity: str, description: str = "") -> Optional[int]:
    try:
        resp = get_api().request("POST", "/api/incidents", json={
            "title": title, "severity": severity, "description": description or None})
    except Exception as exc:
        st.error(f"Could not reach the API: {exc}")
        return None
    if resp.status_code != 201:
        st.error(f"Could not create the incident (HTTP {resp.status_code}).")
        return None
    st.cache_data.clear()
    return resp.json().get("id")
