"""Metric tiles and small display helpers.

Every tile value comes from :meth:`MirageRepository.overview_metrics`,
which counts backend rows — empty backend means zero, never a placeholder
number.
"""
from __future__ import annotations

import html
from typing import Any

import streamlit as st

from dashboard.services.models import (
    PLANE_FOUNDATION,
    PLANE_PIPELINE,
    DashboardCommand,
    DashboardSecurityEvent,
    DashboardSession,
    SystemHealth,
)


def esc(text: str) -> str:
    """Escape untrusted attacker-derived text before display."""
    return html.escape(str(text), quote=True)


def render_metric_row(metrics: dict[str, Any]) -> None:
    """The four headline tiles — the exact set T3's pinned dashboard test
    asserts (labels AND count). Extra T4 tiles live only on the System
    Health view, never here."""
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Sessions", metrics.get("total_sessions", 0))
    c2.metric("Active Sessions", metrics.get("active_sessions", 0))
    c3.metric("High Threat Actors", metrics.get("high_risk_sessions", 0))
    c4.metric("Honeytoken Trips", metrics.get("honeytoken_triggers", 0))


def render_extra_metric_row(metrics: dict[str, Any]) -> None:
    """T4-only tiles (commands/blocks/agent decisions) for the System
    Health view — deliberately never rendered on Overview."""
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Commands Observed", metrics.get("commands_observed", 0))
    c2.metric("Blocked Operations", metrics.get("blocked_operations", 0))
    c3.metric("Agent Decisions", metrics.get("llm_requests", 0))
    c4.metric("Security Alerts", metrics.get("metrics_alerts", 0))


def render_session_table(sessions: list[DashboardSession]) -> None:
    """Session inventory with honest provenance (plane tag) and status."""
    if not sessions:
        st.info("No sessions recorded yet. Run MIRAGE or its test suite first.")
        return
    rows = []
    for s in sessions:
        rows.append(
            {
                "Session ID": s.session_id,
                "Data Plane": "T1 foundation" if s.plane == PLANE_FOUNDATION else "T3 pipeline",
                "Status": s.status,
                "Commands": s.command_count,
                "Threat Level": s.threat_level,
                "Threat Score": s.threat_score,
                "Contained": "yes" if s.containment_active else "—",
                "CWD": esc(s.cwd),
                "Last Seen": _fmt_ts(s.last_seen),
            }
        )
    st.dataframe(rows, use_container_width=True, hide_index=True)


def render_honeytoken_events(events: list[DashboardSecurityEvent]) -> None:
    """Honeytoken-access events (one of the 3 pinned Overview dataframes)."""
    if not events:
        st.success("No honeytokens accessed yet.")
        return
    rows = [
        {
            "Timestamp": _fmt_ts(e.timestamp),
            "Session ID": e.session_id,
            "Details": esc(e.details),
        }
        for e in events
    ]
    st.dataframe(rows, use_container_width=True, hide_index=True)


def render_command_logs_table(commands: list[DashboardCommand]) -> None:
    """Command logs (one of the 3 pinned Overview dataframes)."""
    if not commands:
        st.info("No commands logged yet.")
        return
    rows = [
        {
            "Time": _fmt_ts(c.timestamp),
            "Session": c.session_id,
            "Command": esc(c.raw_command),
            "Source": c.source,
            "Output": esc(c.truncated_output(200)),
        }
        for c in commands
    ]
    st.dataframe(rows, use_container_width=True, hide_index=True)


def render_recent_commands(commands: list[DashboardCommand], limit: int = 40) -> None:
    """Recent commands as chat-style rows (session drilldown / replay)."""
    for c in commands[-limit:]:
        icon = {"llm": "🤖", "sandbox": "⌨️", "fallback": "🧯", "foundation": "🏛"}.get(
            (c.source or "").lower(), "⌨️"
        )
        st.markdown(
            f"`{_fmt_ts(c.timestamp)}` {icon} **{esc(c.raw_command)}**"
            f"{' · ' + esc(c.source) if c.source else ''}"
        )
        out = c.truncated_output(400)
        if out:
            st.code(out, language="text")
        else:
            st.caption("no output recorded")


def render_alerts(events: list[DashboardSecurityEvent], limit: int = 10) -> None:
    """High-signal backend events, newest first (markdown only — no
    metrics/dataframes, so Overview's pinned counts stay exact)."""
    if not events:
        st.success("No security alerts.")
        return
    st.markdown(f"**{len(events)} security alert(s)** — backend-flagged events only")
    for e in events[:limit]:
        icon = "🚨" if e.severity == "HIGH" else "⚠️"
        st.markdown(
            f"{icon} `{esc(e.event_type)}` · session `{esc(e.session_id[:18])}`"
            f" · {_fmt_ts(e.timestamp)}\n\n{esc(e.details)}"
        )


def render_health_rows(components: list[SystemHealth]) -> None:
    """Health as markdown rows — a dataframe here would break Overview's
    pinned 3-dataframe contract, so the health view uses plain rows."""
    icon = {"up": "🟢", "degraded": "🟠", "down": "🔴", "unknown": "⚪"}
    for c in components:
        latency = f"{c.latency_ms:.0f} ms" if c.latency_ms is not None else ""
        st.markdown(
            f"{icon.get(c.status, '⚪')} **{esc(c.component)}** — `{c.status}` {latency}"
            f"{(' · ' + esc(c.detail)) if c.detail else ''}"
        )


def _fmt_ts(ts: float | None) -> str:
    if ts is None:
        return "—"
    import datetime

    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
