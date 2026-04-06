"""CNDS Real-time Dashboard (v3.0 Intelligent System).

Connects to the CNDS API for live alert monitoring and cyber-intelligence.
"""

import os
import requests
import streamlit as st
import pandas as pd
from datetime import datetime

API_URL = os.getenv("CNDS_API_URL", "http://localhost:8000")

st.set_page_config(page_title="CNDS Cyber-Intelligence Dashboard", layout="wide", page_icon="🛡️")
st.title("🛡️ CNDS: Cyber-Intelligence Dashboard")

@st.cache_data(ttl=5)
def fetch_stats():
    try: return requests.get(f"{API_URL}/api/stats", timeout=5).json()
    except: return None

@st.cache_data(ttl=5)
def fetch_alerts(limit=500):
    try: return requests.get(f"{API_URL}/api/alerts", params={"limit": limit}, timeout=5).json()
    except: return []

@st.cache_data(ttl=10)
def fetch_health():
    try: return requests.get(f"{API_URL}/health", timeout=5).json()
    except: return None

@st.cache_data(ttl=30)
def fetch_trends(hours=24):
    try: return requests.get(f"{API_URL}/api/alerts/trends", params={"hours": hours}, timeout=5).json()
    except: return None

# ── Header Stats ──────────────────────────────────────────────────────────────
health = fetch_health()
stats = fetch_stats()

if health:
    h_cols = st.columns(len(health.get("engines", {})) + 1)
    h_cols[0].markdown("**Engine Status:**")
    for i, (engine, active) in enumerate(health.get("engines", {}).items()):
        h_cols[i+1].caption(f"{engine.upper()}: {'✅' if active else '❌'}")

if stats:
    s_cols = st.columns(4)
    s_cols[0].metric("Total Alerts", stats.get("total_alerts", 0))
    s_cols[1].metric("Unacknowledged", stats.get("unacknowledged", 0))
    s_cols[2].metric("🔴 Critical", stats.get("by_severity", {}).get("critical", 0))
    s_cols[3].metric("🟠 High", stats.get("by_severity", {}).get("high", 0))

st.divider()

# ── Tabs ──
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📋 Alertas", "📊 Línea Temporal", "🎯 Top Talkers", "🔍 Tipos de Ataque", "🔬 Analítica", "🌐 Inteligencia"
])

alerts = fetch_alerts()
df = pd.DataFrame(alerts) if alerts else pd.DataFrame()

# ── Tab 1: Alerts Table ───────────────────────────────────────────────────────
with tab1:
    if not df.empty:
        # Checkbox interactivity
        df["acknowledged"] = df["acknowledged"].astype(bool)
        display_cols = ["id", "timestamp", "src_ip", "dst_ip", "attack_type", "severity", "ensemble_score", "acknowledged"]
        available = [c for c in display_cols if c in df.columns]
        
        edited = st.data_editor(df[available], use_container_width=True, hide_index=True,
                               disabled=[c for c in available if c != "acknowledged"],
                               key="editor_main", column_config={"acknowledged": st.column_config.CheckboxColumn("Reconocida")})
        
        if not edited.equals(df[available]):
            for i in range(len(edited)):
                if edited.iloc[i]["acknowledged"] != df.iloc[i]["acknowledged"]:
                    a_id = int(edited.iloc[i]["id"])
                    new_s = bool(edited.iloc[i]["acknowledged"])
                    requests.patch(f"{API_URL}/api/alerts/{a_id}", json={"acknowledged": new_s})
                    st.rerun()
    else: st.info("No hay alertas.")

# ── Tab 2: Timeline ──────────────────────────────────────────────────────────
with tab2:
    trends = fetch_trends()
    if trends and trends.get("data"):
        t_df = pd.DataFrame([{"hour": k, "total": v["total"]} for k, v in sorted(trends["data"].items())])
        t_df["hour"] = pd.to_datetime(t_df["hour"])
        st.line_chart(t_df.set_index("hour"))
    else: st.info("Sin datos de tendencias.")

# ── Tab 3: Talkers & Ports ────────────────────────────────────────────────────
with tab3:
    if not df.empty:
        c1, c2 = st.columns(2)
        c1.subheader("Top IPs Origen")
        c1.bar_chart(df["src_ip"].value_counts().head(10))
        c2.subheader("Top Puertos Destino")
        if "dst_port" in df.columns:
            c2.bar_chart(df["dst_port"].value_counts().head(10))
        
        st.subheader("🎯 Matriz de Conexiones (Origen -> Destino)")
        st.dataframe(pd.crosstab(df["src_ip"], df["dst_ip"].fillna("N/A")), use_container_width=True)

# ── Tab 4: Attack Types & Protocols ───────────────────────────────────────────
with tab4:
    if not df.empty:
        c1, c2 = st.columns(2)
        c1.subheader("Clasificación ML")
        c1.bar_chart(df["attack_type"].fillna("Firma/Regla").value_counts())
        c2.subheader("Protocolos")
        if "protocol" in df.columns:
            p_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
            st.bar_chart(df["protocol"].map(lambda x: p_map.get(x, f"P-{x}")).value_counts())
        
        st.subheader("🛡️ Tácticas MITRE ATT&CK Detectadas")
        tactics = []
        for tl in df.get("mitre_techniques", []):
            if isinstance(tl, list):
                for t in tl: tactics.append(t.get("tactic"))
        if tactics: st.bar_chart(pd.Series(tactics).value_counts())

# ── Tab 5: Model Analytics ────────────────────────────────────────────────────
with tab5:
    if not df.empty:
        st.subheader("Balance de Motores")
        e_list = []
        for _, r in df.iterrows():
            es = r.get("engine_scores", {})
            if isinstance(es, dict):
                e_list.append({"ID": str(r["id"]), "IA": es.get("supervised") or 0, 
                               "Anomaly": es.get("isolation_forest") or 0, "Rules": es.get("rules") or 0, 
                               "Final": r["ensemble_score"]})
        if e_list:
            e_df = pd.DataFrame(e_list).set_index("ID")
            st.bar_chart(e_df[["IA", "Anomaly", "Rules"]].mean())
            st.line_chart(e_df[["Total"]] if "Total" in e_df else e_df[["Final"]])

# ── Tab 6: Intelligence & GeoIP ───────────────────────────────────────────────
with tab6:
    st.subheader("🌍 Mapa de Amenazas (Geolocalización)")
    m_data = []
    for g in df.get("src_geo", []):
        if isinstance(g, dict) and g.get("lat"):
            m_data.append({"lat": g["lat"], "lon": g["lon"]})
    if m_data: st.map(pd.DataFrame(m_data))
    else: st.info("No se han detectado coordenadas externas todavía.")

    st.subheader("🔍 Inteligencia de Firmas (Reglas Disparadas)")
    if "triggered_rules" in df.columns:
        tr = []
        for rl in df["triggered_rules"].dropna(): tr.extend(rl)
        if tr: st.bar_chart(pd.Series(tr).value_counts().head(15))

st.divider()
st.caption(f"Dashboard v3.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Antigravity AI Defense")
st.markdown('<meta http-equiv="refresh" content="10">', unsafe_allow_html=True)
