"""Shared Pydantic models for Mirage.

The API surface (app/main.py) and the T4 contracts (docs/CONTRACTS.md)
both use these so request/response shapes stay in one place.
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
