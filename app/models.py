"""Typed foundation contracts for MIRAGE.

These dataclasses are the stable public contracts between T1 (runtime
foundation) and T2 (agentic engine), T3 (security/VFS), and T4 (dashboard,
testing, integration). They are frozen: once constructed they are treated
as immutable. Other teams must consume these models and must not depend on
private implementation details of the runtime.

All identifiers are server-generated (see ``app.core.ids``); untrusted
inputs are validated before instances are created.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Optional

from .core.ids import new_command_id, new_event_id, new_session_id


def utc_now() -> float:
    """Monotonic-enough wall clock seconds since epoch (UTC)."""
    return time.time()


# --- Session lifecycle -------------------------------------------------

class SessionStatus(str, Enum):
    CREATED = "CREATED"
    ACTIVE = "ACTIVE"
    CLOSED = "CLOSED"


@dataclass(frozen=True, slots=True)
class Session:
    """A single attacker interaction (one SSH connection, one REST identity).

    ``source_address`` and auth fields are recorded for research purposes.
    Do not store passwords or raw credentials: ``auth_method`` and
    ``auth_success`` are the only authentication facts we keep.
    """

    session_id: str
    created_at: float
    updated_at: float
    status: SessionStatus = SessionStatus.CREATED
    source_address: str = ""
    source_port: int = 0
    username: str = ""
    auth_method: str = ""
    auth_success: bool = False
    cwd: str = "/home/admin"
    metadata: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def new(
        source_address: str = "",
        source_port: int = 0,
        username: str = "",
        auth_method: str = "",
        auth_success: bool = False,
        cwd: str = "/home/admin",
        metadata: Optional[dict[str, Any]] = None,
        session_id: Optional[str] = None,
    ) -> "Session":
        now = utc_now()
        return Session(
            session_id=session_id or new_session_id(),
            created_at=now,
            updated_at=now,
            status=SessionStatus.CREATED,
            source_address=source_address,
            source_port=source_port,
            username=username,
            auth_method=auth_method,
            auth_success=auth_success,
            cwd=cwd,
            metadata=dict(metadata or {}),
        )


    def with_changes(self, **changes: Any) -> "Session":
        """Return a copy with the given fields changed and ``updated_at``
        refreshed. Only the SessionManager may construct modified
        sessions; callers elsewhere must treat instances as immutable.
        """
        return replace(self, updated_at=utc_now(), **changes)

    def to_summary(
        self,
        command_count: int = 0,
        last_command: Optional[str] = None,
        metrics: Optional[dict[str, Any]] = None,
    ) -> "SessionSummary":
        return SessionSummary.from_session(
            self,
            command_count=command_count,
            last_command=last_command,
            metrics=metrics,
        )


# --- Command lifecycle ---------------------------------------------------

@dataclass(frozen=True, slots=True)
class CommandRequest:
    """A command submitted during a session, already validated at intake."""

    command_id: str
    session_id: str
    raw_command: str
    timestamp: float
    working_directory: str = "/home/admin"
    terminal: Optional[dict[str, Any]] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def new(
        session_id: str,
        raw_command: str,
        working_directory: str = "/home/admin",
        terminal: Optional[dict[str, Any]] = None,
        metadata: Optional[dict[str, Any]] = None,
        command_id: Optional[str] = None,
    ) -> "CommandRequest":
        return CommandRequest(
            command_id=command_id or new_command_id(),
            session_id=session_id,
            raw_command=raw_command,
            timestamp=utc_now(),
            working_directory=working_directory,
            terminal=dict(terminal or {}),
            metadata=dict(metadata or {}),
        )


class ResultType(str, Enum):
    """What kind of subsystem produced a CommandResult."""

    FALLBACK = "fallback"        # T1 safe stub: simulated, nothing executed
    VFS = "vfs"                 # T3 virtual filesystem
    SECURITY = "security"       # T3 security decision
    AGENTIC = "agentic"         # T2 agentic engine
    CONTAINMENT = "containment" # T3 containment response
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Result returned by a handler for a CommandRequest."""

    command_id: str
    stdout: str
    stderr: str
    exit_code: int
    duration: float
    result_type: ResultType = ResultType.FALLBACK
    metadata: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def new(
        command_id: str,
        stdout: str = "",
        stderr: str = "",
        exit_code: int = 0,
        duration: float = 0.0,
        result_type: ResultType = ResultType.FALLBACK,
        metadata: Optional[dict[str, Any]] = None,
    ) -> "CommandResult":
        return CommandResult(
            command_id=command_id,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            duration=duration,
            result_type=result_type,
            metadata=dict(metadata or {}),
        )


# --- Events ---------------------------------------------------------------

class Severity(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
    """Canonical event types emitted by the MIRAGE runtime.

    Extensible: T2/T3 may add their own string values; the bus does not
    restrict the type, this enum only standardises the common ones.
    """

    SESSION_CREATED = "session.created"
    SESSION_STATUS_CHANGED = "session.status_changed"
    SESSION_CLOSED = "session.closed"
    COMMAND_SUBMITTED = "command.submitted"
    COMMAND_DISPATCHED = "command.dispatched"
    COMMAND_COMPLETED = "command.completed"
    SECURITY_DECISION = "security.decision"
    HONEYTOKEN_ACCESS = "security.honeytoken_access"
    CONTAINMENT_TRIGGERED = "security.containment_triggered"
    RUNTIME_ERROR = "runtime.error"


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """Immutable structured event emitted by the MIRAGE runtime."""

    event_id: str
    session_id: str
    event_type: str
    timestamp: float
    severity: Severity = Severity.INFO
    source: str = "runtime"
    payload: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def new(
        session_id: str,
        event_type: str,
        severity: Severity = Severity.INFO,
        source: str = "runtime",
        payload: Optional[dict[str, Any]] = None,
        metadata: Optional[dict[str, Any]] = None,
        event_id: Optional[str] = None,
        timestamp: Optional[float] = None,
    ) -> "SecurityEvent":
        return SecurityEvent(
            event_id=event_id or new_event_id(),
            session_id=session_id,
            event_type=event_type,
            timestamp=timestamp if timestamp is not None else utc_now(),
            severity=severity,
            source=source,
            payload=dict(payload or {}),
            metadata=dict(metadata or {}),
        )


# --- Summaries & health ---------------------------------------------------

@dataclass(frozen=True, slots=True)
class SessionSummary:
    """Summarized session state for T4 / dashboards.

    Extensible via ``metrics``; T2 may add threat scores and T3 may add
    containment flags without changing this shape.
    """

    session_id: str
    created_at: float
    updated_at: float
    status: SessionStatus
    source_address: str
    username: str
    command_count: int = 0
    last_command: Optional[str] = None
    metrics: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def from_session(
        session: Session,
        command_count: int = 0,
        last_command: Optional[str] = None,
        metrics: Optional[dict[str, Any]] = None,
    ) -> "SessionSummary":
        return SessionSummary(
            session_id=session.session_id,
            created_at=session.created_at,
            updated_at=session.updated_at,
            status=session.status,
            source_address=session.source_address,
            username=session.username,
            command_count=command_count,
            last_command=last_command,
            metrics=dict(metrics or {}),
        )


@dataclass(frozen=True, slots=True)
class HealthStatus:
    """Service health/readiness. No secrets, no internal paths."""

    status: str                    # "ok" | "degraded" | "error"
    version: str = "0.2.0"
    environment: str = "development"
    security_mode: str = "strict"
    database_connected: bool = False
    event_bus_running: bool = False
    uptime_seconds: float = 0.0
    active_sessions: int = 0
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def is_ready(self) -> bool:
        return self.status == "ok"
