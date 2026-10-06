"""Altair charts for the MIRAGE dashboard.

Altair 6.3 ships with Streamlit — no extra dependency. All charts consume
view models only. Chart text (labels) is trusted dashboard text; data
values are attacker-derived but Altair renders them as text/mark geometry,
not code.
"""
from __future__ import annotations

import altair as alt
import pandas as pd

# MIRAGE semantic palette — one color per meaning, consistent across all
# charts so a color always means the same thing on every view.
COLOR_SAFE = "#2E7D32"         # green
COLOR_RECON = "#F9A825"        # amber
COLOR_SENSITIVE = "#EF6C00"   # orange
COLOR_DESTRUCTIVE = "#C62828"  # red
COLOR_HONEYTOKEN = "#6A1B9A"  # purple
COLOR_AGENT = "#1565C0"       # blue
COLOR_NEUTRAL = "#78909C"     # grey

CATEGORY_COLOR = {
    "SAFE": COLOR_SAFE,
    "RECON": COLOR_RECON,
    "SENSITIVE": COLOR_SENSITIVE,
    "DESTRUCTIVE": COLOR_DESTRUCTIVE,
    "UNKNOWN": COLOR_NEUTRAL,
}
THREAT_LEVEL_COLOR = {
    "Low": COLOR_SAFE,
    "Medium": COLOR_RECON,
    "High": COLOR_DESTRUCTIVE,
}
EVENT_COLOR = {
    "HONEYTOKEN_ACCESS": COLOR_HONEYTOKEN,
    "HONEYTOKEN_PLANTED": COLOR_NEUTRAL,
    "SANDBOX_BLOCK": COLOR_DESTRUCTIVE,
    "CONTAINMENT_ACTIVATED": COLOR_DESTRUCTIVE,
    "AGENT_DECISION": COLOR_AGENT,
    "AGENT_FALLBACK": COLOR_NEUTRAL,
    "AGENT_GUARDRAIL_REJECT": COLOR_DESTRUCTIVE,
    "AGENT_INPUT_FLAG": COLOR_RECON,
}


def render_timeline_chart(events) -> None:
    """Event timeline — when MIRAGE saw what (both planes merged)."""
    import streamlit as st

    if not events:
        st.info("No events recorded yet — timeline is empty.")
        return
    df = pd.DataFrame(
        [
            {
                "time": pd.Timestamp(e.timestamp, unit="s", tz="UTC"),
                "event_type": e.event_type,
                "plane": e.plane,
            }
            for e in events
            if e.timestamp is not None
        ]
    )
    if df.empty:
        st.info("No timestamped events yet.")
        return
    known = [k for k in EVENT_COLOR if k in set(df["event_type"])]
    chart = (
        alt.Chart(df)
        .mark_circle(size=60)
        .encode(
            x=alt.X("time:T", title="Time (UTC)"),
            y=alt.Y("event_type:N", title="Event type"),
            color=alt.Color(
                "event_type:N",
                scale=alt.Scale(
                    domain=known,
                    range=[EVENT_COLOR[k] for k in known],
                ),
                legend=None,
            ),
            tooltip=[
                alt.Tooltip("time:T", title="Time"),
                alt.Tooltip("event_type:N", title="Event"),
                alt.Tooltip("plane:N", title="Data plane"),
            ],
        )
        .interactive()
    )
    st.altair_chart(chart, use_container_width=True)


def render_category_chart(commands, classify) -> None:
    """Command categories as computed by T3's classifier (passed in —
    the repository owns the call, this chart never imports app code)."""
    import streamlit as st

    if not commands:
        st.info("No commands recorded yet — category breakdown is empty.")
        return
    rows = [{"category": classify(c.raw_command)} for c in commands]
    df = pd.DataFrame(rows).value_counts(subset=["category"]).reset_index(name="count")
    if df.empty:
        st.info("No classifiable commands yet.")
        return
    known = [k for k in CATEGORY_COLOR if k in set(df["category"])]
    chart = (
        alt.Chart(df)
        .mark_bar()
        .encode(
            x=alt.X("count:Q", title="Commands"),
            y=alt.Y("category:N", sort="-x", title="Category"),
            color=alt.Color(
                "category:N",
                scale=alt.Scale(
                    domain=known,
                    range=[CATEGORY_COLOR[k] for k in known],
                ),
                legend=None,
            ),
            tooltip=["category", "count"],
        )
        .properties(height=min(220, 40 * len(df)))
    )
    st.altair_chart(chart, use_container_width=True)


def render_threat_distribution(sessions) -> None:
    """Sessions by threat level (backend-assigned levels only)."""
    import streamlit as st

    if not sessions:
        st.info("No sessions to score yet.")
        return
    counts: dict[str, int] = {}
    for s in sessions:
        counts[s.threat_level] = counts.get(s.threat_level, 0) + 1
    df = pd.DataFrame(
        [{"threat_level": level, "sessions": count} for level, count in counts.items()]
    )
    known = [k for k in THREAT_LEVEL_COLOR if k in set(df["threat_level"])]
    chart = (
        alt.Chart(df)
        .mark_bar()
        .encode(
            x=alt.X("sessions:Q", title="Sessions"),
            y=alt.Y(
                "threat_level:N",
                sort=[l for l in ("Low", "Medium", "High") if l in set(df["threat_level"])],
                title="Threat level",
            ),
            color=alt.Color(
                "threat_level:N",
                scale=alt.Scale(
                    domain=known,
                    range=[THREAT_LEVEL_COLOR[k] for k in known],
                ),
                legend=None,
            ),
            tooltip=["threat_level", "sessions"],
        )
        .properties(height=140)
    )
    st.altair_chart(chart, use_container_width=True)


def render_command_volume_chart(commands) -> None:
    """Commands over time — attacker pressure on the timeline."""
    import streamlit as st

    if not commands:
        st.info("No commands recorded yet — volume chart is empty.")
        return
    df = pd.DataFrame(
        [
            {"time": pd.Timestamp(c.timestamp, unit="s", tz="UTC")}
            for c in commands
            if c.timestamp is not None
        ]
    )
    if df.empty:
        st.info("No timestamped commands yet.")
        return
    chart = (
        alt.Chart(df)
        .mark_line(point=True)
        .encode(
            x=alt.X("time:T", title="Time (UTC)"),
            y=alt.Y("count()", title="Commands"),
        )
        .interactive()
    )
    st.altair_chart(chart, use_container_width=True)


def render_agent_activity_chart(agent_observations) -> None:
    """T2 agent decisions / fallbacks / guardrail rejections over time."""
    import streamlit as st

    if not agent_observations:
        st.info("No agent events recorded yet — the T2 layer has not run.")
        return
    df = pd.DataFrame(
        [
            {
                "time": pd.Timestamp(o.timestamp, unit="s", tz="UTC"),
                "event_type": o.event_type,
            }
            for o in agent_observations
            if o.timestamp is not None
        ]
    )
    if df.empty:
        st.info("No timestamped agent events yet.")
        return
    known = [k for k in EVENT_COLOR if k in set(df["event_type"])]
    chart = (
        alt.Chart(df)
        .mark_circle(size=60)
        .encode(
            x=alt.X("time:T", title="Time (UTC)"),
            y=alt.Y("event_type:N", title="Agent event type"),
            color=alt.Color(
                "event_type:N",
                scale=alt.Scale(
                    domain=known,
                    range=[EVENT_COLOR[k] for k in known],
                ),
                legend=None,
            ),
            tooltip=["event_type:N", "time:T"],
        )
        .interactive()
    )
    st.altair_chart(chart, use_container_width=True)
