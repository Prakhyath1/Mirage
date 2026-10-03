"""MIRAGE application entry point.

Exposes :func:`create_app`, a FastAPI application factory that wires the
T1 foundation runtime (storage + event bus + session manager + command
dispatcher) and mounts:

- ``/health``, ``/ready`` and the development surface under ``/dev/``
  (app/api/routes.py) — the foundation API;
- ``/legacy`` — the previous prototype routes (router.process_command,
  session summaries) so existing users and the Streamlit dashboard keep
  working until their owners migrate them onto the foundation.

The runtime lives on ``app.state.runtime``; routes only ever talk to it.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
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
            "Multi-layered Intelligent Responsive Adaptive Generative "
            "Environment — deceptive SSH honeypot foundation. All attacker "
            "commands are simulated; nothing executes on the host."
        ),
        version="0.2.0",
        lifespan=_lifespan,
        # Stack traces never leave the process, in any environment.
        debug=False,
    )
    app.state.settings = settings
    app.state.runtime = MirageRuntime(settings)

    app.include_router(foundation_router)

    _mount_legacy(app)
    _install_error_handlers(app)
    return app


def _mount_legacy(app: FastAPI) -> None:
    """Mount the prototype endpoints under /legacy, best-effort.

    The prototype predates the foundation and is owned by other tasks;
    if its imports fail, the foundation keeps serving without it.
    """
    try:
        from . import db as legacy_db
        from . import router as legacy_router
        from . import threat_summary as legacy_threat
    except Exception as exc:  # pragma: no cover - import-time env issues
        log.warning("legacy prototype unavailable", error=str(exc)[:200])
        return

    @app.post("/legacy/command")
    async def legacy_command(session_id: str, command: str):
        await legacy_db.init_db()
        return await legacy_router.process_command(session_id, command)

    @app.get("/legacy/session_summary/{session_id}")
    async def legacy_summary(session_id: str):
        await legacy_db.init_db()
        return await legacy_threat.generate_summary(session_id)

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
    async def unhandled_error(request: Request, exc: Exception):
        # Log with traceback internally; expose only a generic message.
        logging.getLogger("app.main").exception(
            "unhandled error on %s %s", request.method, request.url.path
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_error",
                "message": "an internal error occurred",
            },
        )


# Uvicorn points here: `uvicorn app.main:app`
app = create_app()
