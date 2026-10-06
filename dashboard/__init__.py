"""MIRAGE T4 dashboard package.

The dashboard is a *consumer* of MIRAGE events and APIs — it never
re-implements backend logic (T1 runtime, T2 agent, T3 security are
authoritative for their domains).

Layout:
    dashboard.py        Streamlit entry point (repo-root anchored)
    services/           read-only data adapters + view models
    components/         small UI helpers (metrics, charts, alerts, replay)
    views/              one module per dashboard view

Note: view modules deliberately do NOT live in a ``pages/`` directory —
Streamlit auto-discovers ``pages/`` next to the entry script and would
turn the dashboard into filesystem-driven multipage navigation; the
sidebar-switched views keep everything testable through one entry point.
"""
