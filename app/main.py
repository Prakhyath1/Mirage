"""MIRAGE application entry point (T4 integrated build).

Union of the three team entry points:

- T1 foundation: :func:`create_app`, the FastAPI factory wiring the
  runtime (storage + event bus + session manager + dispatcher), with
  ``/health``, ``/ready`` and the development surface under ``/dev/``;
- T3 pipeline endpoints, kept for the dashboard and existing users:
  ``/command``, ``/session_summary/{id}``, ``/session/{id}``,
  ``/session/{id}/events``, ``/session/{id}/honeytokens`` (legacy
  shapes preserved);
- T4 integration: on startup the T3 deception pipeline is registered as
  a T1 ``CommandHandler`` (``app/integration/pipeline_handler.py``), so
  the foundation runtime executes commands through T3's single choke
  point (parse → classify → score → sandbox / LLM) — no host execution
  anywhere.

The runtime lives on ``app.state.runtime``; routes only ever talk to it.
Legacy prototype commands stay under ``/legacy`` (T1 layout).
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .api.routes import router as foundation_router
from .config import Settings
from .logger import configure_logging, get_logger
from .runtime.service import MirageRuntime

log = get_logger("app.main")

# Legacy prototype imports are deferred to route bodies so a missing or
# broken optional dependency there never blocks the foundation from
# serving health checks.


@asynccontextmanager
async def _lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    runtime: MirageRuntime = app.state.runtime
    await runtime.initialize()

    # T4: make the T3 deception pipeline serve foundation commands. The
    # handler claims every command and executes it inside T3's sandbox /
    # LLM stack; T1's SafeFallbackHandler stays registered behind it.
    try:
        from .integration import attach_default_handlers

        attach_default_handlers(runtime)
        log.info("t3 pipeline handler attached to foundation runtime")
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("pipeline handler attach failed", error=str(exc)[:200])

    # T3 pipeline DB: ensure schema + honeytokens exist for legacy routes.
    try:
        from . import db as legacy_db

        legacy_db.init_db()
        legacy_db.migrate_add_threat_summary()
        legacy_db.migrate_add_containment_active()
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("legacy pipeline db init failed", error=str(exc)[:200])

    log.info("mirage api ready", **settings.safe_summary())
    try:
        yield
    finally:
        await runtime.shutdown()
        log.info("mirage api stopped")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the FastAPI application.

    A fresh runtime is constructed per app instance; tests can pass
    their own ``Settings`` (e.g. a temp database path).
    """
    settings = settings or Settings()
    configure_logging(settings)

    app = FastAPI(
        title="MIRAGE Honeypot",
        description=(
            "Deceptive mirage for adversary engagement. This build runs the "
            "T1 foundation runtime with the T3 deception pipeline attached "
            "as the primary command handler (T4 integration)."
        ),
        version="2.0.0-t4",
        lifespan=_lifespan,
    )
    app.state.settings = settings
    app.state.runtime = MirageRuntime(settings)

    app.include_router(foundation_router)

    _mount_t3_routes(app)
    _mount_legacy(app)
    _install_error_handlers(app)
    return app


def _mount_t3_routes(app: FastAPI) -> None:
    """T3's dashboard-facing endpoints, best-effort on the merged app.

    Kept as-is so the T4 dashboard and any existing T3 consumers keep
    working against the integrated build. The route bodies use the T3
    pipeline modules directly (their own storage), independent of the
    foundation store.
    """
    try:
        from . import db
        from . import threat_summary
        from .api.legacy_schemas import (
            CommandRequest,
            CommandResponse,
            EventInfo,
            HoneytokenInfo,
            SessionInfo,
            SessionSummaryResponse,
        )
    except Exception as exc:  # pragma: no cover - import-time env issues
        log.warning("t3 pipeline modules unavailable", error=str(exc)[:200])
        return

    @app.post("/command", response_model=CommandResponse)
    async def handle_command(req: CommandRequest):
        try:
            from . import router as legacy_router

            output = await legacy_router.process_command(req.session_id, req.command)
            return {"output": output}
        except Exception as e:
            log.error("command failed for session %s: %s", req.session_id, e)
            raise HTTPException(status_code=500, detail="internal error")

    @app.get("/session_summary/{session_id}", response_model=SessionSummaryResponse)
    async def get_session_summary(session_id: str):
        session = db.get_session_by_id(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        stored_summary = threat_summary.get_stored_summary(session_id)
        live_summary = threat_summary.get_live_summary(session_id)
        return {
            "session_id": session_id,
            "stored_summary": stored_summary or "No summary available",
            "live_summary": live_summary,
        }

    @app.get("/session/{session_id}", response_model=SessionInfo)
    async def get_session(session_id: str):
        """Session state for the T4 dashboard: threat score, containment, cwd."""
        session = db.get_session_by_id(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        return {
            "session_id": session_id,
            "threat_score": session.get("threat_score", 0),
            "threat_level": session.get("threat_level", "Low"),
            "containment_active": bool(session.get("containment_active", 0)),
            "cwd": session.get("cwd", "/"),
            "created_at": session.get("created_at"),
            "last_seen": session.get("last_seen"),
        }

    @app.get("/session/{session_id}/events", response_model=list[EventInfo])
    async def get_session_events(session_id: str, limit: int = 50):
        """Security events (containment blocks, honeytoken trips) for T4."""
        if not db.get_session_by_id(session_id):
            raise HTTPException(status_code=404, detail="Session not found")
        events = db.get_session_events(session_id, limit=limit) or []
        return [
            {
                "event_type": e.get("event_type", ""),
                "session_id": session_id,
                "details": e.get("details", ""),
                "timestamp": e.get("timestamp"),
            }
            for e in events
        ]

    @app.get("/session/{session_id}/honeytokens", response_model=list[HoneytokenInfo])
    async def get_session_honeytokens(session_id: str):
        """Honeytoken status for T4: which canaries exist and whether they tripped."""
        if not db.get_session_by_id(session_id):
            raise HTTPException(status_code=404, detail="Session not found")
        # Trip status comes from HONEYTOKEN_ACCESS events (details:
        # "Path: <p>"), newest first — a canary merely existing is not a
        # trip, and there is no last_accessed column to read.
        accesses = {}
        for e in db.get_session_events(session_id, limit=500):
            details = e.get("details") or ""
            if e.get("event_type") == "HONEYTOKEN_ACCESS" and details.startswith("Path: "):
                accesses.setdefault(details[len("Path: "):], e.get("timestamp"))
        # Canaries are planted at the session root; scan there only.
        honeytokens = db.list_virtual_files(session_id, "/") or []
        return [
            {
                "path": f["path"],
                "tripped": f["path"] in accesses,
                "last_accessed": accesses.get(f["path"]),
            }
            for f in honeytokens
            if f.get("is_honeytoken")
        ]

    log.info("t3 pipeline routes mounted")


def _mount_legacy(app: FastAPI) -> None:
    """Mount the prototype endpoints under /legacy, best-effort.

    The prototype predates the foundation and is owned by other tasks;
    if its imports fail, the foundation keeps serving without it.
    """
    try:
        from . import db as legacy_db
        from . import threat_summary as legacy_threat
    except Exception as exc:  # pragma: no cover - import-time env issues
        log.warning("legacy prototype unavailable", error=str(exc)[:200])
        return

    @app.post("/legacy/command")
    async def legacy_command(session_id: str, command: str):
        legacy_db.init_db()
        from . import router as legacy_router

        output = legacy_router.process_command(session_id, command)
        return {"output": output}

    @app.get("/legacy/session_summary/{session_id}")
    async def legacy_summary(session_id: str):
        legacy_db.init_db()
        return legacy_threat.generate_threat_summary(session_id)

    log.info("legacy prototype mounted under /legacy")


def _install_error_handlers(app: FastAPI) -> None:
    """Uniform error envelopes; no stack traces in any response."""

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, exc: StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": "http_error", "message": str(exc.detail)},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=422,
            content={
                "error": "validation_error",
                "message": "request body failed validation",
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_error(_: Request, exc: Exception):
        logging.exception("unhandled error")
        return JSONResponse(
            status_code=500,
            content={"error": "internal_error", "message": "internal server error"},
        )
