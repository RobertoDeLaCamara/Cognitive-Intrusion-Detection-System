"""CNDS dashboard entry point: sets up the page and the navigation between views."""

import streamlit as st

st.set_page_config(page_title="CNDS Command Centre", layout="wide", page_icon="🛡️")

pages = [
    st.Page("views/overview.py", title="Alerts overview", icon="📋", default=True),
    st.Page("views/alert_detail.py", title="Alert detail", icon="🔎", url_path="alert"),
    st.Page("views/analytics.py", title="Analytics", icon="📊"),
]
st.navigation(pages).run()
