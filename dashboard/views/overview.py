"""Overview view: the pinned T3 structure, dual-plane aware.

This view reproduces the exact element inventory T3's dashboard test
pins (4 metrics, sessions table, honeytoken events, command logs) — no
more, no fewer — because the AppTest assertions count elements across
the whole tree:

    [m.label for m in at.metric] == [4 pinned labels]
    len(at.dataframe) == 3

Any extra metric, dataframe, or checkbox on this view breaks the pinned
contract. T4 additions (alerts strip, health rows, extra tiles) render
elsewhere: System Health view, or markdown-only expanders here.
"""
from __future__ import annotations

import streamlit as st

from dashboard.components import metrics
from dashboard.services.models import PLANE_PIPELINE
from dashboard.services.repository import MirageRepository


def render(repo: MirageRepository) -> None:
    # Exactly the four pinned metric tiles.
    metrics.render_metric_row(repo.overview_metrics())

    st.divider()
    st.subheader("🚩 Active Sessions & Threat Levels")
    metrics.render_session_table(repo.list_sessions(200))

    st.divider()
    st.subheader("🍯 Honeytoken Activity")
    metrics.render_honeytoken_events(
        repo.list_events(event_type="HONEYTOKEN_ACCESS", limit=200)
    )

    st.divider()
    st.subheader("📜 Command Logs")
    metrics.render_command_logs_table(repo.recent_commands(limit=100))

    st.divider()
    st.subheader("🚨 Security Alerts")
    metrics.render_alerts(repo.list_alerts())

    st.divider()
    st.subheader("🖥 System Health")
    metrics.render_health_rows(repo.system_health())
