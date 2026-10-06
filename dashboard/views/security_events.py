"""Security events view: filterable event stream from both planes."""
from __future__ import annotations

import streamlit as st

from dashboard.components import charts, metrics
from dashboard.services.repository import MirageRepository


def render(repo: MirageRepository) -> None:
    col1, col2 = st.columns(2)
    with col1:
        plane_filter = st.radio(
            "Data plane",
            ["all", "foundation", "pipeline"],
            horizontal=True,
        )
    with col2:
        types = sorted({e.event_type for e in repo.list_events(limit=1000)})
        type_filter = st.selectbox(
            "Event type",
            ["all"] + types,
        )

    sessions = repo.list_sessions(200)
    session_filter = st.selectbox(
        "Session",
        ["all"] + [s.session_id for s in sessions],
    )

    severity_rank = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2, "MEDIUM": 2, "INFO": 3, "DEBUG": 4}
    events = repo.list_events(limit=1000)
    filtered = [
        e
        for e in events
        if (plane_filter == "all" or e.plane == plane_filter)
        and (type_filter == "all" or e.event_type == type_filter)
        and (session_filter == "all" or e.session_id == session_filter)
    ]
    filtered.sort(key=lambda e: severity_rank.get(e.severity, 3))

    st.markdown(f"### {len(filtered)} event(s)")
    if not filtered:
        st.info("No events match the filters.")
        return
    charts.render_timeline_chart(filtered)
    rows = [
        {
            "Time (UTC)": _fmt(e.timestamp),
            "Event": e.event_type,
            "Severity": e.severity,
            "Session": e.session_id[:24],
            "Plane": "T1" if e.plane == "foundation" else "T3",
            "Details": metrics.esc(e.details[:160]),
        }
        for e in filtered[:200]
    ]
    st.dataframe(rows, use_container_width=True, hide_index=True)


def _fmt(ts) -> str:
    if ts is None:
        return "—"
    import datetime

    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%m-%d %H:%M:%S")
