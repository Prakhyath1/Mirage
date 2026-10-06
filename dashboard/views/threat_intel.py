"""Threat intelligence view: MITRE mapping, honeytokens, exports."""
from __future__ import annotations

import streamlit as st

from dashboard.components import metrics
from dashboard.services.exports import JsonFileExporter, WebhookExporter, to_json_events
from dashboard.services.repository import MirageRepository


def render(repo: MirageRepository) -> None:
    st.markdown("### MITRE ATT&CK observations")
    mitre = repo.list_mitre_observations()
    if not mitre:
        st.info(
            "No technique-mapped activity yet. Techniques appear once the "
            "pipeline records RECON/SENSITIVE/DESTRUCTIVE commands or a "
            "honeytoken is tripped."
        )
    else:
        rows = [
            {
                "Technique": f"{m.technique_id} — {m.technique_name}",
                "Sessions": m.session_count,
                "Examples (T3-classified)": "; ".join(
                    metrics.esc(c) for c in m.command_examples[:3]
                ),
                "First seen": _fmt(m.first_seen),
                "Last seen": _fmt(m.last_seen),
                "Confidence": f"{m.confidence:.2f}",
            }
            for m in mitre
        ]
        st.dataframe(rows, use_container_width=True, hide_index=True)
        st.caption(
            "Technique IDs are rendered from T3's command classification "
            "(see docs/integration/T4_API_CONTRACT.md §4). T3 categories "
            "are authoritative; this map only presents them as ATT&CK."
        )

    st.markdown("### Honeytokens (metadata only)")
    tokens = repo.list_honeytokens()
    if not tokens:
        st.info("No canaries planted yet.")
    else:
        tripped = [t for t in tokens if t.tripped]
        st.markdown(
            f"**{len(tripped)} of {len(tokens)} canary file(s) tripped** — "
            "content is never displayed, by contract."
        )
        rows = [
            {
                "Path (virtual)": metrics.esc(t.path),
                "Type": t.token_type,
                "Status": "🚨 TRIPPED" if t.tripped else "dormant",
                "Session": metrics.esc(t.session_id[:18]),
            }
            for t in tokens
        ]
        st.dataframe(rows, use_container_width=True, hide_index=True)

    st.markdown("### Exports")
    observations = repo.list_threat_observations()
    st.markdown(f"**{len(observations)} normalized threat observation(s)** ready for export")
    preview = st.checkbox("Preview JSON export")
    if preview:
        st.code(to_json_events(observations[:5]), language="json")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Download observations as JSON"):
            _download_json(observations)
    with col2:
        st.caption("SIEM/STIX exporters are adapter interfaces — see the contract doc.")


def _download_json(observations) -> None:
    import json as _json

    payload = _json.dumps([o.to_export_dict() for o in observations], indent=2)
    st.download_button(
        "Save mirage_observations.json",
        data=payload,
        file_name="mirage_observations.json",
        mime="application/json",
    )


def _fmt(ts) -> str:
    if ts is None:
        return "—"
    import datetime

    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%m-%d %H:%M:%S")
