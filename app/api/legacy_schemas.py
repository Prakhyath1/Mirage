"""Pydantic shapes for the T3-era (legacy) API surface.

The T3 pipeline endpoints mounted by ``app.main._mount_t3_routes`` —
``/command``, ``/session_summary/{id}``, ``/session/{id}``,
``/session/{id}/events``, ``/session/{id}/honeytokens`` — predate the T1
foundation's schema discipline but are load-bearing for the T4 dashboard
and existing consumers, so their request/response shapes are kept
verbatim here (``docs/integration/T4_API_CONTRACT.md`` pins them).

Honeytoken metadata only ever travels through these models; file
contents never leave the pipeline.
"""
from typing import Optional

from pydantic import BaseModel, Field


class CommandRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=128)
    command: str = Field(min_length=1, max_length=512)


class CommandResponse(BaseModel):
    output: str


class SessionSummaryResponse(BaseModel):
    session_id: str
    stored_summary: str
    live_summary: str


class SessionInfo(BaseModel):
    """Session state as exposed to downstream consumers (T4)."""

    session_id: str
    cwd: str
    threat_score: int
    threat_level: str
    containment_active: bool
    created_at: Optional[float] = None
    last_seen: Optional[float] = None


class EventInfo(BaseModel):
    """A security/audit event as exposed to downstream consumers (T4)."""

    timestamp: float
    session_id: str
    event_type: str
    details: str


class HoneytokenInfo(BaseModel):
    """A canary file's metadata (never its content) as exposed to T4."""

    path: str
    is_honeytoken: bool = True
    tripped: bool = False
    last_accessed: Optional[float] = None
