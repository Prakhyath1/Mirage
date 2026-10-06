"""Agent activity view: T2 decisions, fallbacks, guardrails."""
from __future__ import annotations

import streamlit as st

from dashboard.components import charts
from dashboard.services.repository import MirageRepository


def render(repo: MirageRepository) -> None:
    observations = repo.list_agent_observations(limit=300)
    charts.render_agent_activity_chart(observations)

    if not observations:
        st.info(
            "No AGENT_* events recorded yet. The T2 agentic layer emits "
            "AGENT_DECISION / AGENT_FALLBACK / AGENT_GUARDRAIL_REJECT / "
            "AGENT_INPUT_FLAG events when it runs."
        )
        return

    st.markdown("### Agent decisions")
    for o in observations[:60]:
        icon = {
            "AGENT_DECISION": "🤖",
            "AGENT_FALLBACK": "↩️",
            "AGENT_GUARDRAIL_REJECT": "🛑",
            "AGENT_INPUT_FLAG": "🚩",
        }.get(o.event_type, "•")
        st.markdown(
            f"{icon} `{o.event_type}` · session `{o.session_id[:18]}`"
            f" · {_fmt(o.timestamp)}"
        )
        with st.expander("details (redacted)", expanded=False):
            st.code(o.details[:600], language="json")

    decisions = sum(1 for o in observations if o.event_type == "AGENT_DECISION")
    fallbacks = sum(1 for o in observations if o.event_type == "AGENT_FALLBACK")
    rejects = sum(1 for o in observations if o.event_type == "AGENT_GUARDRAIL_REJECT")
    c1, c2, c3 = st.columns(3)
    c1.metric("Decisions", decisions)
    c2.metric("Fallbacks", fallbacks)
    c3.metric("Guardrail rejections", rejects)


def _fmt(ts) -> str:
    if ts is None:
        return "—"
    import datetime

    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%m-%d %H:%M:%S")
