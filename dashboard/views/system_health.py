"""System Health view: backend-reported component status + T4-only tiles."""
from __future__ import annotations

import streamlit as st

from dashboard.components import metrics
from dashboard.services.repository import MirageRepository


def render(repo: MirageRepository) -> None:
    st.subheader("🖥 System Health")
    metrics.render_health_rows(repo.system_health())
    st.divider()
    metrics.render_extra_metric_row(repo.overview_metrics())
    st.caption(
        "Commands Observed counts both planes; Blocked Operations counts "
        "containment-blocked commands and guardrail rejections; Agent "
        "Decisions counts T2 LLM request events; Security Alerts counts "
        "backend-flagged alert-worthy events."
    )
