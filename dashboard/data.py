"""Pure data helpers for the dashboard (no Streamlit imports, so they are unit-testable)."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

import pandas as pd

SEVERITIES = ["critical", "high", "medium", "low"]
SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
SEVERITY_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}  # low=0 … critical=3

FRAME_COLUMNS = [
    "id", "timestamp", "severity", "src_ip", "dst_ip", "src_port", "dst_port", "flow",
    "attack_type", "ensemble_score", "top_engine", "rules", "mitre", "tactics", "country",
    "asset", "source", "acknowledged", "label", "incident_id", "notes",
]


def _geo_country(geo: Any) -> str:
    if isinstance(geo, dict):
        return str(geo.get("country") or geo.get("country_name") or "")
    return ""


def _flow(row: Dict[str, Any]) -> str:
    src = f"{row.get('src_ip') or '?'}"
    if row.get("src_port"):
        src += f":{row['src_port']}"
    dst = f"{row.get('dst_ip') or '?'}"
    if row.get("dst_port"):
        dst += f":{row['dst_port']}"
    return f"{src} → {dst}"


def top_engine(engine_scores: Any) -> str:
    """Name of the engine with the highest score, or '' when there are none."""
    if not isinstance(engine_scores, dict):
        return ""
    scored = {k: v for k, v in engine_scores.items() if isinstance(v, (int, float))}
    return max(scored, key=scored.get) if scored else ""


def alerts_to_frame(alerts: Optional[Iterable[Dict[str, Any]]]) -> pd.DataFrame:
    """Flatten API alerts into one row each, with display-ready derived columns."""
    rows: List[Dict[str, Any]] = []
    for a in alerts or []:
        techniques = [t for t in (a.get("mitre_techniques") or []) if isinstance(t, dict)]
        rows.append({
            "id": a.get("id"),
            "timestamp": a.get("timestamp"),
            "severity": a.get("severity") or "low",
            "src_ip": a.get("src_ip") or "",
            "dst_ip": a.get("dst_ip") or "",
            "src_port": a.get("src_port"),
            "dst_port": a.get("dst_port"),
            "flow": _flow(a),
            "attack_type": a.get("attack_type") or "",
            "ensemble_score": a.get("ensemble_score") or 0.0,
            "top_engine": top_engine(a.get("engine_scores")),
            "rules": ", ".join(a.get("triggered_rules") or []),
            "mitre": ", ".join(t.get("id", "") for t in techniques if t.get("id")),
            "tactics": ", ".join(sorted({t["tactic"] for t in techniques if t.get("tactic")})),
            "country": _geo_country(a.get("src_geo")),
            "asset": a.get("src_asset_type") or "",
            "source": a.get("source") or "",
            "acknowledged": bool(a.get("acknowledged")),
            "label": a.get("label") or "",
            "incident_id": a.get("incident_id"),
            "notes": a.get("notes") or "",
        })
    df = pd.DataFrame(rows, columns=FRAME_COLUMNS)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    return df


def apply_filters(
    df: pd.DataFrame,
    severities: Optional[List[str]] = None,
    status: str = "All",
    text: str = "",
    attack_types: Optional[List[str]] = None,
    engines: Optional[List[str]] = None,
    sources: Optional[List[str]] = None,
    hours: Optional[int] = None,
    now: Optional[pd.Timestamp] = None,
) -> pd.DataFrame:
    """Filter the alert frame. `status` is All | Unacknowledged | Acknowledged.

    `text` matches case-insensitively against IPs, attack type, rules and MITRE ids.
    """
    out = df
    if severities:
        out = out[out["severity"].isin(severities)]
    if status == "Unacknowledged":
        out = out[~out["acknowledged"]]
    elif status == "Acknowledged":
        out = out[out["acknowledged"]]
    if attack_types:
        out = out[out["attack_type"].isin(attack_types)]
    if engines:
        out = out[out["top_engine"].isin(engines)]
    if sources:
        out = out[out["source"].isin(sources)]
    if hours:
        now = now if now is not None else pd.Timestamp.now(tz="UTC")
        out = out[out["timestamp"] >= now - pd.Timedelta(hours=hours)]
    text = text.strip().lower()
    if text:
        haystack = (out["src_ip"] + " " + out["dst_ip"] + " " + out["attack_type"] + " "
                    + out["rules"] + " " + out["mitre"]).str.lower()
        out = out[haystack.str.contains(text, regex=False)]
    return out


def relative_time(ts: Any, now: Optional[pd.Timestamp] = None) -> str:
    """'42s ago', '5m ago', '3h ago', '2d ago'."""
    if ts is None or pd.isna(ts):
        return ""
    now = now if now is not None else pd.Timestamp.now(tz="UTC")
    seconds = max(int((now - ts).total_seconds()), 0)
    for limit, unit, size in ((60, "s", 1), (3600, "m", 60), (86400, "h", 3600)):
        if seconds < limit:
            return f"{seconds // size}{unit} ago"
    return f"{seconds // 86400}d ago"


def kpis(df: pd.DataFrame, now: Optional[pd.Timestamp] = None) -> Dict[str, Any]:
    """Headline numbers for the overview, computed from the loaded alerts."""
    now = now if now is not None else pd.Timestamp.now(tz="UTC")
    last = df[df["timestamp"] >= now - pd.Timedelta(hours=24)]
    prev = df[(df["timestamp"] < now - pd.Timedelta(hours=24))
              & (df["timestamp"] >= now - pd.Timedelta(hours=48))]
    return {
        "unacknowledged": int((~df["acknowledged"]).sum()),
        "crit_high": int(df["severity"].isin(["critical", "high"]).sum()),
        "last_24h": len(last),
        "last_24h_delta": len(last) - len(prev),
        "unique_sources": int(df["src_ip"].nunique()),
    }


def top_values(df: pd.DataFrame, column: str, n: int = 10, split: bool = False) -> pd.Series:
    """Most frequent values of a column. `split=True` explodes comma-joined cells."""
    series = df[column]
    if split:
        series = series.str.split(", ").explode()
    series = series[series.notna() & (series != "")]
    return series.value_counts().head(n)


def trends_frame(trends: Optional[Dict[str, Any]]) -> pd.DataFrame:
    """`/alerts/trends` payload -> one row per bucket, one column per severity."""
    data = (trends or {}).get("data") or {}
    rows = []
    for bucket, v in sorted(data.items()):
        row = {sev: 0 for sev in SEVERITIES}
        row.update(v.get("by_severity") or {})
        row["bucket"] = pd.to_datetime(bucket, utc=True)
        rows.append(row)
    if not rows:
        return pd.DataFrame(columns=["bucket", *SEVERITIES])
    return pd.DataFrame(rows).set_index("bucket")[SEVERITIES]


def engine_rows(engine_scores: Any) -> List[Dict[str, Any]]:
    """Per-engine score rows for the detail page (None scores kept as None)."""
    if not isinstance(engine_scores, dict):
        return []
    return [{"engine": k, "score": v if isinstance(v, (int, float)) else None}
            for k, v in sorted(engine_scores.items())]
