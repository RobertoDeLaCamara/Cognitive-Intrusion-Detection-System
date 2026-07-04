"""CNDS Real-time Dashboard (v5.0 Advanced Intelligence).

Features Pydeck Interactive Map with Tooltips and Incident Reports.
"""

import os
import requests
import streamlit as st
import pandas as pd
import pydeck as pdk
from datetime import datetime

API_URL = os.getenv("CNDS_API_URL", "http://localhost:8000")

st.set_page_config(page_title="CNDS Intelligence Command Centre", layout="wide", page_icon="🕵️")
st.title("🛡️ CNDS: Intelligence Command Centre (v5.0)")

@st.cache_data(ttl=5)
def fetch_stats():
    try: return requests.get(f"{API_URL}/api/stats", timeout=5).json()
    except: return None

@st.cache_data(ttl=5)
def fetch_alerts(limit=500):
    try: return requests.get(f"{API_URL}/api/alerts", params={"limit": limit}, timeout=5).json()
    except: return []

@st.cache_data(ttl=30)
def fetch_trends(hours=24):
    try: return requests.get(f"{API_URL}/api/alerts/trends", params={"hours": hours}, timeout=5).json()
    except: return None

# ── Header Stats ──────────────────────────────────────────────────────────────
stats = fetch_stats()
if stats:
    s_cols = st.columns(4)
    total_alerts = stats.get("total_alerts", 0)
    ack_rate = (total_alerts - stats.get("unacknowledged", 0)) / total_alerts * 100 if total_alerts else 0.0
    s_cols[0].metric("Total Alerts", total_alerts)
    s_cols[1].metric("🔴 Críticas", stats.get("by_severity", {}).get("critical", 0))
    s_cols[2].metric("🟢 Benigno", stats.get("by_severity", {}).get("low", 0), delta_color="inverse")
    s_cols[3].metric("Acknowledge Rate", f"{ack_rate:.1f}%")

st.divider()
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📋 Alertas", "📊 Tendencias", "🎯 Talkers", "🔬 Motores", "🛡️ MITRE", "🌐 Intel-Geo"
])

alerts = fetch_alerts()
df = pd.DataFrame(alerts) if isinstance(alerts, list) and alerts else pd.DataFrame()

# (Tabs 1-5 logic remains consistent)
with tab1:
    if not df.empty:
        df["acknowledged"] = df["acknowledged"].astype(bool)
        edited = st.data_editor(df[["id", "timestamp", "src_ip", "attack_type", "severity", "acknowledged"]], use_container_width=True, hide_index=True,
                               disabled=["id", "timestamp", "src_ip", "attack_type", "severity"],
                               column_config={"acknowledged": st.column_config.CheckboxColumn("Reconocida")})
        if not edited.equals(df[["id", "timestamp", "src_ip", "attack_type", "severity", "acknowledged"]]):
            for i in range(len(edited)):
                if edited.iloc[i]["acknowledged"] != df.iloc[i]["acknowledged"]:
                    requests.patch(f"{API_URL}/api/alerts/{int(edited.iloc[i]['id'])}", json={"acknowledged": bool(edited.iloc[i]['acknowledged'])})
                    st.rerun()
    else: st.info("No hay alertas.")

with tab2:
    trends = fetch_trends()
    if trends and trends.get("data"):
        t_df = pd.DataFrame([{"h": k, "c": v["total"]} for k,v in sorted(trends["data"].items())])
        st.area_chart(t_df.set_index("h"))

with tab3:
    if not df.empty:
        c1, c2 = st.columns(2)
        c1.bar_chart(df["src_ip"].value_counts().head(10))
        c2.subheader("Puertos de Destino")
        if "dst_port" in df.columns: c2.bar_chart(df["dst_port"].value_counts().head(10))

with tab4:
    if not df.empty:
        st.subheader("Rendimiento del Ensemble")
        el = []
        for _, r in df.iterrows():
            es = r.get("engine_scores", {})
            if isinstance(es, dict):
                el.append({"ID": str(r["id"]), "IA": es.get("supervised") or 0, "Anomaly": es.get("isolation_forest") or 0, "Rules": es.get("rules") or 0, "Final": r["ensemble_score"]})
        if el:
            edf = pd.DataFrame(el).set_index("ID")
            st.bar_chart(edf[["IA", "Anomaly", "Rules"]].mean())
            st.line_chart(edf[["IA", "Anomaly", "Rules"]])

with tab5:
    if not df.empty:
        st.subheader("Mapeo MITRE ATT&CK")
        ts = []
        for tl in df.get("mitre_techniques", []):
            if isinstance(tl, list):
                for t in tl: ts.append(t.get("tactic"))
        if ts: st.bar_chart(pd.Series(ts).value_counts())

# ── Tab 6: Advanced Intelligence (GEO + Summary) ──────────────────────────────
with tab6:
    st.subheader("🌍 Mapa Interactivo de Amenazas")
    map_data = []
    for _, row in df.iterrows():
        g = row.get("src_geo")
        if isinstance(g, dict):
            lat = g.get("lat") or g.get("latitude")
            lon = g.get("lon") or g.get("longitude")
            if lat and lon:
                map_data.append({
                    "src_ip": row["src_ip"],
                    "attack_type": row.get("attack_type") or "Reglas/Payload",
                    "severity": row["severity"],
                    "score": row["ensemble_score"],
                    "lat": float(lat), "lon": float(lon)
                })
    
    if map_data:
        m_df = pd.DataFrame(map_data).fillna("Detección por Reglas")
        # Pre-formatear para Pydeck
        m_df["score_pct"] = (m_df["score"] * 100).round(2).astype(str) + "%"
        
        # Pydeck Layer definition
        layer = pdk.Layer(
            "ScatterplotLayer",
            m_df,
            get_position="[lon, lat]",
            get_color="[200, 30, 0, 160]" if not m_df[m_df["severity"] == "critical"].empty else "[250, 100, 0, 160]",
            get_radius=300000,
            pickable=True,
            auto_highlight=True,
        )
        
        view_state = pdk.ViewState(latitude=20, longitude=0, zoom=1, pitch=0)
        
        st.pydeck_chart(pdk.Deck(
            layers=[layer],
            initial_view_state=view_state,
            tooltip={"text": "IP: {src_ip}\nAtaque: {attack_type}\nSeveridad: {severity}\nConfianza: {score_pct}"}
        ))
        
        st.divider()
        st.header("🕵️ Generador de Informes de Inteligencia")
        selected_ip = st.selectbox("Selecciona una IP detectada para análisis profundo:", m_df["src_ip"].unique())
        
        if selected_ip:
            target = m_df[m_df["src_ip"] == selected_ip].iloc[0]
            with st.expander(f"Ver Informe de Inteligencia para {selected_ip}", expanded=True):
                st.markdown(f"""
                ### 📄 TECHNICAL INCIDENT REPORT
                **Host Origen:** `{selected_ip}`
                **Estrategia de Ataque:** {target['attack_type']}
                **Severidad:** `{target['severity'].upper()}`
                **Nivel de Confianza IA:** `{target['score']*100:.1f}%`
                
                ---
                #### Análisis de Amenaza
                El sistema CNDS ha identificado una coincidencia de firmas de nivel {target['severity']} para esta IP. La geolocalización sitúa el origen de la amenaza en las coordenadas `({target['lat']}, {target['lon']})`. 
                
                **Acciones Recomendadas:**
                1.  Bloquear el tráfico de entrada de `{selected_ip}` en el firewall perimetral.
                2.  Revisar los logs de servicios en los puertos de destino asociados.
                3.  Iniciar un escaneo de malware en los hosts internos que interactuaron con este origen.
                """)
    else:
        st.info("No hay datos geográficos disponibles.")

st.divider()
st.caption(f"v5.0 Advanced Intel | {datetime.now().strftime('%H:%M:%S')}")
st.markdown('<meta http-equiv="refresh" content="15">', unsafe_allow_html=True)
