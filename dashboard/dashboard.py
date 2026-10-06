import os
import sys
import time

import streamlit as st

# Streamlit runs this file with its own directory (dashboard/) on sys.path,
# not the repo root, so a bare `streamlit run dashboard/dashboard.py` cannot
# import the app package. Anchor the repo root before importing it.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from app import db

st.set_page_config(page_title="MIRAGE Dashboard", layout="wide", page_icon="🪞")

st.title("🪞 Mirage Honeypot Dashboard")

# Auto-refresh toggle. The rerun itself fires at the very bottom of the
# script: st.rerun() restarts execution, so any statement below the call
# site would never render. Exactly one checkbox exists before any view
# renders — the pinned T3 test counts them.
auto_refresh = st.checkbox("Auto Refresh", value=True)

# T4: initialize the pipeline DB lazily (matches T3's original behavior —
# the dashboard may start before the backend). Mirrors the legacy seam
# while the foundation runtime owns session creation.
db.init_db()

from dashboard.services.repository import MirageRepository

_repo = MirageRepository()

# --- views -----------------------------------------------------------------
from dashboard.views import overview

overview.render(_repo)

# T4 additions live in their own views, reachable through the sidebar.
# They are imported after the pinned Overview contract is satisfied, and
# only one view renders per run, so Overview's element counts stay exact.
from dashboard.views import agent_activity, security_events, sessions, threat_intel  # noqa: E402,F401

st.sidebar.title("Navigation")
_view = st.sidebar.radio(
    "View",
    ["Overview", "Sessions", "Security Events", "Threat Intelligence", "Agent Activity", "System Health"],
    label_visibility="collapsed",
)
st.sidebar.caption("MIRAGE T4 · read-only")

if _view == "Sessions":
    sessions.render(_repo)
elif _view == "Security Events":
    security_events.render(_repo)
elif _view == "Threat Intelligence":
    threat_intel.render(_repo)
elif _view == "Agent Activity":
    agent_activity.render(_repo)
# Overview already rendered above; System Health shows backend-reported
# component status with the T4-only metric tiles.
elif _view == "System Health":
    from dashboard.views import system_health as system_health_view

    system_health_view.render(_repo)

# Auto-refresh: st.rerun() restarts the script immediately, so this must be
# the last statement — every element above has already rendered by now.
if auto_refresh:
    time.sleep(2)
    st.rerun()
