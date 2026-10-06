"""Sessions view: inventory table + per-session drilldown with replay."""
from __future__ import annotations

import streamlit as st

from dashboard.components import charts, metrics
from dashboard.services.models import PLANE_FOUNDATION, PLANE_PIPELINE
from dashboard.services.repository import MirageRepository


def render(repo: MirageRepository) -> None:
    sessions = repo.list_sessions(200)
    metrics.render_session_table(sessions)
    if not sessions:
        return

    st.markdown("### Session detail")
    options = {s.session_id: s for s in sessions}
    selected = st.selectbox(
        "Session",
        list(options),
        format_func=lambda sid: f"{sid} · {options[sid].threat_level} threat · {options[sid].command_count} cmd",
    )
    if not selected:
        return
    session = options[selected]

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Threat level", session.threat_level)
    col2.metric("Threat score", session.threat_score)
    col3.metric("Commands", session.command_count)
    col4.metric("Contained", "yes" if session.containment_active else "no")

    st.markdown("#### Command categories (T3 classifier)")
    commands = repo.list_commands(selected, 300)
    charts.render_category_chart(commands, repo.classify_command)
    # `classify` is passed explicitly, so the view never imports app code.

    st.markdown("#### Session replay")
    if not commands:
        st.info("No commands recorded for this session.")
    else:
        play = st.checkbox("Play as animated replay", value=False)
        if play:
            _render_animated_replay(commands)
        else:
            metrics.render_recent_commands(commands, limit=40)


def _render_animated_replay(commands) -> None:
    """Step through the attack session like a screen-recording."""
    if len(commands) < 2:
        st.info("Need ≥ 2 commands for an animated replay.")
        return
    step = st.slider(
        "Replay position",
        min_value=1,
        max_value=len(commands),
        value=len(commands),
    )
    shown = commands[:step]
    st.caption(f"Command {step} of {len(commands)}")
    metrics.render_recent_commands(shown, limit=1)
    if step > 1:
        with st.expander(f"Previous {step - 1} command(s)", expanded=False):
            metrics.render_recent_commands(commands[: step - 1], limit=step - 1)
