"""Thin FastAPI routes over MirageRuntime.

Every route:
- validates input at this boundary (typed pydantic bodies, ID format
  checks) and never trusts client-supplied identifiers;
- delegates to the runtime — no route touches storage, the bus, or a
  repository directly;
- returns a consistent error envelope instead of stack traces.

Development entry points live under ``/dev/``. The production SSH
surface (T3/T4 era) will drive the same runtime calls through the
SSH adapter, never through these routes.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from ..core.ids import is_valid_id
from .schemas import (
    CommandRequestBody,
    CommandResultResponse,
    HealthResponse,
    SessionCreateRequest,
    SessionDetailResponse,
    SessionSummaryResponse,
)

router = APIRouter()


def _runtime(request: Request):
    """Fetch the runtime the app wired at startup. Routes never build it."""
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None:
        # Startup hasn't completed (or this is a misconfigured host).
        raise HTTPException(status_code=503, detail="runtime unavailable")
    return runtime


def _require_valid_session_id(session_id: str) -> str:
    """Reject malformed IDs before any lookup: identifiers from the
    network are untrusted and never reach the database unchecked."""
    if not isinstance(session_id, str) or not is_valid_id(session_id):
        raise HTTPException(status_code=400, detail="invalid session id")
    return session_id


# -- health ---------------------------------------------------------------


@router.get("/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    """Liveness probe."""
    runtime = _runtime(request)
    return HealthResponse.from_health(await runtime.health())


@router.get("/ready", response_model=HealthResponse)
async def ready(request: Request) -> HealthResponse:
    """Readiness probe: storage reachable, schema applied, bus running."""
    runtime = _runtime(request)
    return HealthResponse.from_health(await runtime.readiness())


# -- development surface ----------------------------------------------------


@router.post(
    "/dev/sessions",
    response_model=SessionDetailResponse,
    status_code=201,
)
async def create_session(
    body: SessionCreateRequest, request: Request
) -> SessionDetailResponse:
    """Create and activate a honeypot session (development path)."""
    runtime = _runtime(request)
    session = await runtime.create_session(
        source_address=body.source_address,
        source_port=body.source_port,
        username=body.username,
        metadata=body.metadata,
    )
    return SessionDetailResponse.from_session(session)


@router.get("/dev/sessions/{session_id}", response_model=SessionSummaryResponse)
async def session_summary(
    session_id: str, request: Request
) -> SessionSummaryResponse:
    runtime = _runtime(request)
    _require_valid_session_id(session_id)
    summary = await runtime.storage.sessions.summary(session_id)
    if summary is None:
        raise HTTPException(status_code=404, detail="session not found")
    return SessionSummaryResponse.from_summary(summary)


@router.delete(
    "/dev/sessions/{session_id}", response_model=SessionDetailResponse
)
async def close_session(
    session_id: str, request: Request
) -> SessionDetailResponse:
    runtime = _runtime(request)
    _require_valid_session_id(session_id)
    result = await runtime.close_session(session_id)
    if not result.ok:
        raise HTTPException(status_code=404, detail="session not found")
    return SessionDetailResponse.from_session(result.value)


@router.post(
    "/dev/sessions/{session_id}/commands",
    response_model=CommandResultResponse,
)
async def submit_command(
    session_id: str, body: CommandRequestBody, request: Request
) -> CommandResultResponse:
    """Vertical slice: submit one command, get the simulated result.

    SECURITY: ``body.command`` is attacker-controlled data. It is
    validated, persisted, and simulated — never executed on the host.
    """
    runtime = _runtime(request)
    _require_valid_session_id(session_id)
    result = await runtime.submit_command(session_id, body.command)
    if not result.ok:
        # Map runtime failure codes to HTTP semantics without leaking
        # internal details.
        status = 404 if result.error_code == "session.missing" else 400
        raise HTTPException(status_code=status, detail=result.error_code)
    return CommandResultResponse.from_result(result.value, session_id=session_id)
