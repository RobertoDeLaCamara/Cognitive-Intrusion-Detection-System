"""Aggregate views over the loaded alerts: trends, talkers, engines, MITRE and geography."""

import pandas as pd
import pydeck as pdk
import streamlit as st

try:
    import common
    import data
except ImportError:                           # imported as a package
    from dashboard import common, data

SEVERITY_RGBA = {"critical": [214, 39, 40, 190], "high": [255, 127, 14, 180],
                 "medium": [242, 192, 55, 170], "low": [44, 160, 44, 150]}

st.title("📊 Analytics")

alerts = common.fetch_alerts(500)
df = data.alerts_to_frame(alerts)
if df.empty:
    st.info("No alerts yet.")
    st.stop()

tab_trends, tab_talkers, tab_engines, tab_mitre, tab_geo = st.tabs(
    ["Trends", "Top talkers", "Engines", "MITRE ATT&CK", "Geography"])

with tab_trends:
    c1, c2 = st.columns(2)
    hours = c1.selectbox("Range", [24, 72, 168], format_func=lambda h: f"Last {h} hours")
    bucket = c2.radio("Bucket", ["hour", "day"], horizontal=True)
    frame = data.trends_frame(common.fetch_trends(hours, bucket))
    if frame.empty:
        st.info("No alerts in this range.")
    else:
        st.bar_chart(frame, color=["#d62728", "#ff7f0e", "#f2c037", "#2ca02c"])

with tab_talkers:
    c1, c2, c3 = st.columns(3)
    c1.subheader("Source IPs")
    c1.bar_chart(data.top_values(df, "src_ip"), horizontal=True)
    c2.subheader("Targeted IPs")
    c2.bar_chart(data.top_values(df, "dst_ip"), horizontal=True)
    c3.subheader("Destination ports")
    ports = df["dst_port"].dropna().astype(int).astype(str).value_counts().head(10)
    c3.bar_chart(ports, horizontal=True)

with tab_engines:
    st.subheader("Dominant engine per alert")
    st.bar_chart(data.top_values(df, "top_engine"))
    st.subheader("Score by severity")
    st.bar_chart(df.groupby("severity")["ensemble_score"].mean().reindex(data.SEVERITIES).dropna())

with tab_mitre:
    c1, c2 = st.columns(2)
    c1.subheader("Tactics")
    c1.bar_chart(data.top_values(df, "tactics", split=True), horizontal=True)
    c2.subheader("Techniques")
    c2.bar_chart(data.top_values(df, "mitre", split=True), horizontal=True)

with tab_geo:
    points = []
    for a in alerts:
        g = a.get("src_geo") or {}
        lat, lon = g.get("lat") or g.get("latitude"), g.get("lon") or g.get("longitude")
        if lat and lon:
            points.append({"src_ip": a["src_ip"], "attack": a.get("attack_type") or "rules / anomaly",
                           "severity": a.get("severity") or "low", "lat": float(lat), "lon": float(lon),
                           "color": SEVERITY_RGBA.get(a.get("severity") or "low", SEVERITY_RGBA["low"])})
    if not points:
        st.info("No geolocated alerts (GeoIP is only available for public source addresses).")
    else:
        layer = pdk.Layer("ScatterplotLayer", pd.DataFrame(points), get_position="[lon, lat]",
                          get_fill_color="color", get_radius=250000, pickable=True)
        st.pydeck_chart(pdk.Deck(
            layers=[layer], initial_view_state=pdk.ViewState(latitude=20, longitude=0, zoom=1),
            tooltip={"text": "{src_ip}\n{attack}\n{severity}"}))
