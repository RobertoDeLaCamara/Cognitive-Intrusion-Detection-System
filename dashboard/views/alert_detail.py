"""Alert detail: everything the system knows about one alert, plus triage actions."""

import json

import pandas as pd
import streamlit as st

try:
    import common
    import data
except ImportError:                           # imported as a package
    from dashboard import common, data

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}
LABELS = {"": "— no verdict —", "tp": "True positive", "fp": "False positive", "unknown": "Unknown"}

st.title("🔎 Alert detail")

alert_id = st.number_input("Alert ID", min_value=1, step=1, format="%d",
                           value=int(st.session_state.get("alert_id") or 1))
st.session_state["alert_id"] = int(alert_id)
alert = common.fetch_alert(int(alert_id))
if not alert:
    st.warning(f"Alert #{int(alert_id)} was not found (or the API is unreachable).")
    st.stop()

ts = pd.to_datetime(alert["timestamp"], utc=True)
sev = alert.get("severity") or "low"
st.header(f"{data.SEVERITY_ICON.get(sev, '')} #{alert['id']} · {alert.get('attack_type') or 'Rules / anomaly detection'}")
st.caption(f"{ts:%Y-%m-%d %H:%M:%S} UTC ({data.relative_time(ts)}) · source: {alert.get('source') or 'n/a'}")

m = st.columns(5)
m[0].metric("Severity", sev.upper())
m[1].metric("Ensemble score", f"{(alert.get('ensemble_score') or 0) * 100:.1f}%")
m[2].metric("Status", "Acknowledged" if alert.get("acknowledged") else "Open")
m[3].metric("Analyst verdict", LABELS.get(alert.get("label") or "", alert.get("label")))
m[4].metric("Incident", f"#{alert['incident_id']}" if alert.get("incident_id") else "—")

net, det = st.columns(2)

with net:
    st.subheader("Network")
    geo = alert.get("src_geo") or {}
    proto = alert.get("protocol")
    st.table(pd.DataFrame([
        ("Source", f"{alert.get('src_ip')}" + (f":{alert['src_port']}" if alert.get("src_port") else "")),
        ("Destination", f"{alert.get('dst_ip') or '?'}" + (f":{alert['dst_port']}" if alert.get("dst_port") else "")),
        ("Protocol", PROTOCOLS.get(proto, str(proto)) if proto is not None else "—"),
        ("Source asset type", alert.get("src_asset_type") or "unknown"),
        ("Location", ", ".join(str(v) for v in (geo.get("city"), geo.get("country")) if v) or "—"),
        ("JA3 hash", alert.get("ja3_hash") or "—"),
    ], columns=["Field", "Value"]).set_index("Field"))
    lat, lon = geo.get("lat") or geo.get("latitude"), geo.get("lon") or geo.get("longitude")
    if lat and lon:
        st.map(pd.DataFrame({"lat": [float(lat)], "lon": [float(lon)]}), zoom=3, height=200)
    if alert.get("ja3_string"):
        with st.expander("JA3 string"):
            st.code(alert["ja3_string"])

with det:
    st.subheader("Detection")
    rows = data.engine_rows(alert.get("engine_scores"))
    if rows:
        scores = pd.DataFrame(rows)
        st.dataframe(scores, hide_index=True, use_container_width=True, column_config={
            "score": st.column_config.ProgressColumn("Score", min_value=0.0, max_value=1.0, format="%.3f")})
    else:
        st.caption("No per-engine scores stored.")
    rules = alert.get("triggered_rules") or []
    st.markdown("**Triggered rules:** " + (", ".join(f"`{r}`" for r in rules) if rules else "none"))
    matches = alert.get("payload_matches") or []
    st.markdown("**Payload matches:** " + (", ".join(f"`{p}`" for p in matches) if matches else "none"))
    techniques = alert.get("mitre_techniques") or []
    if techniques:
        st.markdown("**MITRE ATT&CK**")
        st.dataframe(pd.DataFrame(techniques), hide_index=True, use_container_width=True)

st.divider()
st.subheader("Triage")
incidents = common.fetch_incidents()
by_id = {i["id"]: i for i in incidents}
with st.form("triage"):
    c1, c2, c3 = st.columns(3)
    ack = c1.checkbox("Acknowledged", value=bool(alert.get("acknowledged")))
    label_keys = list(LABELS)
    label = c2.selectbox("Verdict", label_keys, format_func=LABELS.get,
                         index=label_keys.index(alert.get("label") or ""))
    inc_options = [None, *by_id]
    current_inc = alert.get("incident_id")
    incident = c3.selectbox(
        "Incident", inc_options, index=inc_options.index(current_inc) if current_inc in inc_options else 0,
        format_func=lambda i: "— none —" if i is None else f"#{i} · {by_id[i]['title']} ({by_id[i]['status']})")
    notes = st.text_area("Analyst notes", value=alert.get("notes") or "")
    if st.form_submit_button("Save", type="primary"):
        fields = {"acknowledged": ack, "notes": notes}
        if label:
            fields["label"] = label
        if incident is not None:
            fields["incident_id"] = incident
        if common.update_alert(alert["id"], **fields):
            st.success("Saved.")
            st.rerun()

with st.expander("Open a new incident from this alert"):
    title = st.text_input("Title", value=f"{alert.get('attack_type') or 'Suspicious activity'} from {alert.get('src_ip')}")
    if st.button("Create incident and link alert"):
        new_id = common.create_incident(title, sev, f"Opened from alert #{alert['id']}.")
        if new_id and common.update_alert(alert["id"], incident_id=new_id):
            st.success(f"Incident #{new_id} created and linked.")
            st.rerun()

if alert.get("incident_id") in by_id:
    inc = by_id[alert["incident_id"]]
    st.info(f"**Incident #{inc['id']}** — {inc['title']} · {inc['status']} · severity {inc['severity']}"
            + (f" · assigned to {inc['assigned_to']}" if inc.get("assigned_to") else ""))

st.divider()
st.subheader(f"Other alerts from {alert.get('src_ip')}")
related = data.alerts_to_frame([a for a in common.fetch_related(alert["src_ip"]) if a["id"] != alert["id"]])
if related.empty:
    st.caption("No other alerts from this source.")
else:
    st.dataframe(
        related[["id", "timestamp", "severity", "dst_ip", "dst_port", "attack_type", "ensemble_score", "rules"]],
        hide_index=True, use_container_width=True,
        column_config={"ensemble_score": st.column_config.ProgressColumn("Score", min_value=0.0, max_value=1.0)})
    first, last = related["timestamp"].min(), related["timestamp"].max()
    st.caption(f"{len(related)} other alerts between {first:%Y-%m-%d %H:%M} and {last:%Y-%m-%d %H:%M} UTC · "
               f"{related['dst_ip'].nunique()} distinct targets · {related['dst_port'].nunique()} distinct ports")

st.divider()
st.subheader("Raw features")
for key, names_key, title in (("flow_features", "flow_feature_names", "Flow features (CICFlowMeter)"),
                              ("host_features", "host_feature_names", "Host features")):
    values = alert.get(key)
    with st.expander(title):
        if not values:
            st.caption("Not stored for this alert.")
            continue
        names = alert.get(names_key) or [f"feature_{i}" for i in range(len(values))]
        st.dataframe(pd.DataFrame({"feature": names[:len(values)], "value": values}),
                     hide_index=True, use_container_width=True, height=300)

with st.expander("Raw API response"):
    st.code(json.dumps(alert, indent=2, default=str), language="json")
