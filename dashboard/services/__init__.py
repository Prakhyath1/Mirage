"""Service layer for the MIRAGE dashboard (T4).

Read-only adapters over the two MIRAGE data planes:

- the T1 foundation runtime store (``app.storage`` via T1's ``Settings``)
- the T3 deception pipeline database (legacy ``app.db``)

Everything the UI renders flows through :mod:`dashboard.services` so that
(a) backend failure states are handled in one place, (b) no component
opens a database connection itself, and (c) every displayed value traces
to an actual backend row — the dashboard invents nothing.
"""
from dashboard.services.models import (  # noqa: F401
    AgentObservation,
    DashboardCommand,
    DashboardSecurityEvent,
    DashboardSession,
    HoneytokenEvent,
    MitreObservation,
    SystemHealth,
    ThreatObservation,
)
from dashboard.services.repository import (  # noqa: F401
    MirageDataUnavailable,
    MirageRepository,
)

__all__ = [
    "AgentObservation",
    "DashboardCommand",
    "DashboardSecurityEvent",
    "DashboardSession",
    "HoneytokenEvent",
    "MitreObservation",
    "MirageDataUnavailable",
    "MirageRepository",
    "SystemHealth",
    "ThreatObservation",
]
