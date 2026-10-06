"""Pydantic request/response schemas for the MIRAGE API.

The runtime speaks frozen dataclasses; the API speaks these pydantic
models. Serialization is explicit and whitelisted so a future field
added to a dataclass never leaks into a response unreviewed (e.g.
credentials or internal paths).

Requests are validated here at the HTTP boundary so the runtime's own
limits (``Settings.max_command_length`` etc.) are enforced before a
request ever reaches the funnel.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..config import Settings
from ..models import CommandResult, HealthStatus, Session, SessionSummary


def _max_command_length() -> int:
    return Settings().max_command_length


# -- requests --------------------------------------------------------------


class SessionCreateRequest(BaseModel):
    """Development-only session creation. No authentication is simulated
    here and no field is ever executed; everything is stored as data."""

    model_config = ConfigDict(extra="forbid")

    source_address: str = Field(default="", max_length=64)
    source_port: int = Field(default=0, ge=0, le=65535)
    username: str = Field(default="", max_length=64)
    metadata: dict[str, str] | None = None


class CommandRequestBody(BaseModel):
    """One attacker-supplied command line (development entry point)."""

    model_config = ConfigDict(extra="forbid")

    command: str = Field(
        ...,
        min_length=1,
        max_length=_max_command_length(),
        description="Raw command line; stored and simulated, never executed.",
    )

    @field_validator("command")
    @classmethod
    def _command_not_blank(cls, v: str) -> str:
        # min_length=1 alone admits whitespace-only strings, which would
        # defer rejection to the runtime. Enforce the "non-empty command"
        # boundary rule here, before the request reaches the funnel. The
        # runtime's own `command.empty` check remains as defense-in-depth.
        if not v.strip():
            raise ValueError("command must not be empty or whitespace-only")
        return v


# -- responses -------------------------------------------------------------


class ErrorResponse(BaseModel):
    """Consistent error envelope: machine-readable code + human message.
    Never contains stack traces or internal paths."""

    error: str
    message: str
    session_id: str | None = None
    command_id: str | None = None


class SessionDetailResponse(BaseModel):
    session_id: str
    created_at: float
    updated_at: float
    status: str
    source_address: str
    source_port: int
    username: str
    auth_method: str
    auth_success: bool
    cwd: str
    metadata: dict = Field(default_factory=dict)

    @staticmethod
    def from_session(session: Session) -> "SessionDetailResponse":
        return SessionDetailResponse(
            session_id=session.session_id,
            created_at=session.created_at,
            updated_at=session.updated_at,
            status=session.status.value,
            source_address=session.source_address,
            source_port=session.source_port,
            username=session.username,
            auth_method=session.auth_method,
            auth_success=session.auth_success,
            cwd=session.cwd,
            metadata=dict(session.metadata),
        )


class SessionSummaryResponse(BaseModel):
    session_id: str
    created_at: float
    updated_at: float
    status: str
    source_address: str
    username: str
    command_count: int
    last_command: str | None
    metrics: dict = Field(default_factory=dict)

    @staticmethod
    def from_summary(summary: SessionSummary) -> "SessionSummaryResponse":
        return SessionSummaryResponse(
            session_id=summary.session_id,
            created_at=summary.created_at,
            updated_at=summary.updated_at,
            status=summary.status.value
            if hasattr(summary.status, "value")
            else str(summary.status),
            source_address=summary.source_address,
            username=summary.username,
            command_count=summary.command_count,
            last_command=summary.last_command,
            metrics=dict(summary.metrics),
        )


class CommandResultResponse(BaseModel):
    command_id: str
    session_id: str | None = None
    stdout: str
    stderr: str
    exit_code: int
    duration: float
    result_type: str
    simulated: bool
    metadata: dict = Field(default_factory=dict)

    @staticmethod
    def from_result(
        result: CommandResult, session_id: str | None = None
    ) -> "CommandResultResponse":
        return CommandResultResponse(
            command_id=result.command_id,
            session_id=session_id,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            duration=result.duration,
            result_type=result.result_type.value
            if hasattr(result.result_type, "value")
            else str(result.result_type),
            simulated=bool(result.metadata.get("simulated", False)),
            metadata=dict(result.metadata),
        )


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    security_mode: str
    database_connected: bool
    event_bus_running: bool
    uptime_seconds: float
    active_sessions: int
    details: dict = Field(default_factory=dict)

    @staticmethod
    def from_health(health: HealthStatus) -> "HealthResponse":
        return HealthResponse(
            status=health.status,
            version=health.version,
            environment=health.environment,
            security_mode=health.security_mode,
            database_connected=health.database_connected,
            event_bus_running=health.event_bus_running,
            uptime_seconds=health.uptime_seconds,
            active_sessions=health.active_sessions,
            details=dict(health.details),
        )
