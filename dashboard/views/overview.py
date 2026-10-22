"""Alerts overview: KPIs, severity timeline, filterable alert table, bulk triage."""

import pandas as pd
import streamlit as st

try:
    import common
    import data
except ImportError:                           # imported as a package
    from dashboard import common, data

REFRESH_SECONDS = 15
WINDOWS = {"Last hour": 1, "Last 6 hours": 6, "Last 24 hours": 24, "Last 7 days": 168, "All loaded": None}
SEVERITY_COLORS = {"critical": "#d62728", "high": "#ff7f0e", "medium": "#f2c037", "low": "#2ca02c"}

st.title("🛡️ CNDS Command Centre")


def _open_detail(alert_id: int) -> None:
    st.session_state["alert_id"] = int(alert_id)
    st.switch_page("views/alert_detail.py")


def _kpi_row(df: pd.DataFrame, stats: dict) -> None:
    k = data.kpis(df)
    cols = st.columns(5)
    cols[0].metric("Total alerts", (stats or {}).get("total_alerts", len(df)))
    cols[1].metric("Unacknowledged", (stats or {}).get("unacknowledged", k["unacknowledged"]))
    cols[2].metric("Critical + high (loaded)", k["crit_high"])
    cols[3].metric("Last 24 h", k["last_24h"], delta=k["last_24h_delta"], delta_color="inverse",
                   help="Change against the previous 24 h")
    cols[4].metric("Distinct sources", k["unique_sources"])


def _timeline() -> None:
    frame = data.trends_frame(common.fetch_trends(24))
    st.caption("Alerts per hour, last 24 h")
    if frame.empty:
        st.info("No alerts in the last 24 hours.")
        return
    st.bar_chart(frame, color=[SEVERITY_COLORS[s] for s in data.SEVERITIES], height=180)


def _filters(df: pd.DataFrame) -> dict:
    with st.expander("Filters", expanded=True):
        c1, c2, c3, c4 = st.columns([2, 2, 2, 3])
        severities = c1.multiselect("Severity", data.SEVERITIES, placeholder="All")
        status = c2.radio("Status", ["All", "Unacknowledged", "Acknowledged"], horizontal=True)
        window = c3.selectbox("Time window", list(WINDOWS), index=2)
        text = c4.text_input("Search", placeholder="IP, attack type, rule or MITRE id (e.g. T1110)")
        c5, c6, c7 = st.columns(3)
        attack_types = c5.multiselect("Attack type", sorted(t for t in df["attack_type"].unique() if t),
                                      placeholder="All")
        engines = c6.multiselect("Dominant engine", sorted(e for e in df["top_engine"].unique() if e),
                                 placeholder="All")
        sources = c7.multiselect("Source", sorted(s for s in df["source"].unique() if s), placeholder="All")
    return dict(severities=severities, status=status, text=text, attack_types=attack_types,
                engines=engines, sources=sources, hours=WINDOWS[window])


def _table(view: pd.DataFrame) -> list:
    """Render the alert table; returns the ids of the selected rows."""
    shown = pd.DataFrame({
        "ID": view["id"],
        "When": view["timestamp"].map(data.relative_time),
        "Severity": view["severity"].map(lambda s: f"{data.SEVERITY_ICON.get(s, '')} {s}"),
        "Flow": view["flow"],
        "Attack": view["attack_type"].replace("", "rules / anomaly"),
        "Score": view["ensemble_score"],
        "Engine": view["top_engine"],
        "Rules": view["rules"],
        "MITRE": view["mitre"],
        "Country": view["country"],
        "Asset": view["asset"],
        "Ack": view["acknowledged"],
        "Verdict": view["label"],
        "Incident": view["incident_id"],
    }).reset_index(drop=True)
    event = st.dataframe(
        shown, hide_index=True, use_container_width=True, height=420,
        on_select="rerun", selection_mode="multi-row", key="alerts_table",
        column_config={
            "Score": st.column_config.ProgressColumn("Score", min_value=0.0, max_value=1.0, format="%.2f"),
            "Ack": st.column_config.CheckboxColumn("Ack"),
            "Incident": st.column_config.NumberColumn("Incident", format="#%d"),
        },
    )
    rows = event.selection.rows if event and event.selection else []
    return [int(view["id"].iloc[r]) for r in rows if r < len(view)]


def _selection_panel(view: pd.DataFrame, ids: list) -> None:
    if not ids:
        st.caption("Select one or more rows to triage them or open the full detail.")
        return
    chosen = view[view["id"].isin(ids)]
    a, b, c, d = st.columns(4)
    if a.button(f"✅ Acknowledge ({len(ids)})", use_container_width=True):
        if all(common.update_alert(i, acknowledged=True) for i in ids):
            st.rerun(scope="fragment")
    if b.button("🎯 Mark true positive", use_container_width=True):
        if all(common.update_alert(i, label="tp") for i in ids):
            st.rerun(scope="fragment")
    if c.button("🚫 Mark false positive", use_container_width=True):
        if all(common.update_alert(i, label="fp") for i in ids):
            st.rerun(scope="fragment")
    if len(ids) == 1 and d.button("🔎 Open full detail", type="primary", use_container_width=True):
        _open_detail(ids[0])
    if len(ids) == 1:
        row = chosen.iloc[0]
        st.markdown(
            f"**#{row['id']}** · {data.SEVERITY_ICON.get(row['severity'], '')} **{row['severity']}** · "
            f"{row['attack_type'] or 'rules / anomaly'} · `{row['flow']}` · score {row['ensemble_score']:.2f}"
            + (f" · rules: {row['rules']}" if row["rules"] else "")
            + (f" · MITRE: {row['mitre']}" if row["mitre"] else "")
        )


@st.fragment(run_every=REFRESH_SECONDS)
def _body() -> None:
    limit = st.session_state.get("fetch_limit", 500)
    alerts = common.fetch_alerts(limit)
    df = data.alerts_to_frame(alerts)

    _kpi_row(df, common.fetch_stats())
    _timeline()
    if df.empty:
        st.info("No alerts yet." if alerts == [] else "No alerts.")
        return

    flt = _filters(df)
    view = data.apply_filters(df, **flt)
    st.caption(f"{len(view)} of {len(df)} loaded alerts match · refreshes every {REFRESH_SECONDS}s")
    ids = _table(view)
    _selection_panel(view, ids)

    left, right = st.columns(2)
    left.subheader("Top sources")
    left.bar_chart(data.top_values(view, "src_ip"), horizontal=True, height=260)
    right.subheader("Top triggered rules")
    rules = data.top_values(view, "rules", split=True)
    if rules.empty:
        right.caption("No rules triggered in the current selection.")
    else:
        right.bar_chart(rules, horizontal=True, height=260)


st.sidebar.selectbox("Alerts to load", [100, 250, 500], index=2, key="fetch_limit",
                     help="Most recent alerts fetched from the API; filters apply to these.")
_body()
