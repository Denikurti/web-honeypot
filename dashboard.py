import streamlit as st
import pandas as pd
import altair as alt
from datetime import datetime

st.set_page_config(page_title="Honeypot Dashboard", layout="wide")

# Load the honeypot log data
@st.cache_data
def load_data():
    try:
        df = pd.read_csv("hits.csv")
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df = df.dropna(subset=["timestamp"])
        return df
    except Exception as e:
        st.error(f"Failed to load hits.csv: {e}")
        return pd.DataFrame()

df = load_data()

st.title("🛡️ Web Honeypot Dashboard")
st.markdown("Live threat intelligence view powered by your honeypot logs.")

if df.empty:
    st.warning("No data found yet. Trigger the honeypot to generate logs.")
    st.stop()

# Sidebar filters
st.sidebar.header("🔎 Filters")
alert_types = df["alert"].dropna().unique().tolist()
countries = df["country"].dropna().unique().tolist()
paths = df["path"].dropna().unique().tolist()

selected_alerts = st.sidebar.multiselect("Filter by Alert Type", options=alert_types)
selected_countries = st.sidebar.multiselect("Filter by Country", options=countries)
selected_paths = st.sidebar.multiselect("Filter by Endpoint", options=paths)

filtered_df = df.copy()
if selected_alerts:
    filtered_df = filtered_df[filtered_df["alert"].isin(selected_alerts)]
if selected_countries:
    filtered_df = filtered_df[filtered_df["country"].isin(selected_countries)]
if selected_paths:
    filtered_df = filtered_df[filtered_df["path"].isin(selected_paths)]

# Cards
col1, col2, col3 = st.columns(3)
col1.metric("🔍 Total Requests", len(filtered_df))
col2.metric("⚠️ Total Alerts", filtered_df["alert"].notna().sum())
col3.metric("🌍 Unique IPs", filtered_df["remote_ip"].nunique())

# Charts
st.subheader("📊 Alert Frequency")
alert_chart = filtered_df["alert"].value_counts().head(10)
st.bar_chart(alert_chart)

st.subheader("🌐 Country Distribution")
country_chart = filtered_df["country"].value_counts().head(10)
st.bar_chart(country_chart)

st.subheader("🏢 ISP Breakdown")
isp_chart = filtered_df["isp"].value_counts().head(10)
st.bar_chart(isp_chart)

st.subheader("📈 Activity Over Time")
timeline = filtered_df.groupby(filtered_df["timestamp"].dt.date).size().reset_index(name="count")
line = alt.Chart(timeline).mark_line(point=True).encode(
    x="timestamp:T", y="count:Q"
).properties(height=300)
st.altair_chart(line, use_container_width=True)

# Full Data Table
st.subheader("🧾 Full Log Table")
st.dataframe(filtered_df, use_container_width=True)

# Export
st.download_button("📥 Download CSV", data=filtered_df.to_csv(index=False), file_name="filtered_hits.csv")
