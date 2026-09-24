import streamlit as st
from app import db
import time
import pandas as pd

st.set_page_config(page_title="Mirage Dashboard", layout="wide", page_icon="🪞")

# Custom CSS for Dark Theme
st.markdown("""
    <style>
    .stApp { background-color: #0e1117; color: #fafafa; }
    .metric-card { background-color: #262730; padding: 20px; border-radius: 10px; }
    </style>
""", unsafe_allow_html=True)

st.title("🪞 Mirage Honeypot Dashboard")

# Auto-refresh checkbox
auto_refresh = st.checkbox("Auto Refresh", value=True)
if auto_refresh:
    time.sleep(2)
    st.rerun()

# Initialize DB (in case dashboard started before main)
db.init_db()

# Metrics
sessions = db.get_all_sessions()
events = db.get_all_events()
logs = db.get_all_logs()

high_threat_sessions = [s for s in sessions if s['threat_level'] == "High"]
honeytoken_events = [e for e in events if e['event_type'] == "HONEYTOKEN_ACCESS"]

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Sessions", len(sessions))
col2.metric("Active Sessions", len([s for s in sessions if time.time() - s['last_seen'] < 300]))
col3.metric("High Threat Actors", len(high_threat_sessions))
col4.metric("Honeytoken Trips", len(honeytoken_events))

st.divider()

# Threat Map / Session List
st.subheader("🚩 Active Sessions & Threat Levels")

if sessions:
    import pandas as pd

    df = pd.DataFrame({
        "Session ID": [s['session_id'] for s in sessions],
        "CWD": [s['cwd'] for s in sessions],
        "Threat Score": [s['threat_score'] for s in sessions],
        "Level": [s['threat_level'] for s in sessions],
        "Last Seen": [time.strftime('%H:%M:%S', time.localtime(s['last_seen'])) for s in sessions]
    })

    def color_level(val):
        if val == "High":
            return "color: red; font-weight: bold;"
        elif val == "Medium":
            return "color: orange; font-weight: bold;"
        else:
            return "color: lime; font-weight: bold;"

    styled_df = df.style.applymap(color_level, subset=["Level"])

    st.dataframe(styled_df, use_container_width=True)

else:
    st.info("No active sessions detected.")

st.divider()


# Honeytoken Events
st.subheader("🍯 Honeytoken Access Events")
if honeytoken_events:
    event_data = {
        "Timestamp": [time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(e['timestamp'])) for e in honeytoken_events],
        "Session ID": [e['session_id'] for e in honeytoken_events],
        "Details": [e['details'] for e in honeytoken_events]
    }
    st.dataframe(event_data, use_container_width=True)
else:
    st.success("No honeytokens accessed yet.")

st.divider()

# Live Logs
st.subheader("📜 Command Logs")
if logs:
    log_data = {
        "Time": [time.strftime('%H:%M:%S', time.localtime(l['timestamp'])) for l in logs],
        "Session": [l['session_id'] for l in logs],
        "Command": [l['command'] for l in logs],
        "Source": [l['source'] for l in logs],
        "Output": [l['output'] for l in logs]
    }
    st.dataframe(log_data, use_container_width=True)
else:
    st.info("No commands logged yet.")