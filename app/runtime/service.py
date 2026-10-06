"""MirageRuntime: wires storage, bus, sessions and dispatching together.

This is the composition root of the T1 foundation. The API layer (and,
later, the SSH adapter) talks only to :class:`MirageRuntime` — never to
repositories or the bus directly.

Vertical slice performed by :meth:`submit_command`:

    POST /dev/command
      -> validate command (boundary checks)
      -> resolve session (server-generated ID, ACTIVE required)
      -> CommandRequest constructed server-side
      -> SessionManager state machine consulted
      -> CommandDispatcher.dispatch (persist intake, run handler or the
         safe fallback, persist result, emit events)
      -> SecurityEvent published on the bus (persisted by the bus's
         storage subscriber)
      -> CommandResult returned; everything retrievable from storage.

SECURITY: ``submit_command`` is the single funnel for untrusted command
text. It performs the boundary validation once, and never executes
anything on the host.
"""
from __future__ import annotations

import time
from typing import Optional

from ..config import Settings
from ..core.result import RuntimeResult
from ..events.bus import EventBus
from ..logger import get_logger
from ..models import (
    CommandRequest,
    CommandResult,
    EventType,
    HealthStatus,
    SecurityEvent,
    Session,
    SessionStatus,
    Severity,
    utc_now,
)
from ..storage.database import Storage
from .dispatcher import CommandDispatcher
from .session_manager import SessionManager

log = get_logger("runtime.service")


class MirageRuntime:
    """Owns every T1 component and exposes one safe entry point."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.storage = Storage(settings)
        self.bus = EventBus(name="mirage")
        self.sessions = SessionManager(self.storage, self.bus)
        self.dispatcher = CommandDispatcher(self.storage, self.bus, settings)
        self._started_at = time.monotonic()
        self._ready = False

        # Bus subscriber: persist every event so T4/tests can query them.
        self.bus.subscribe(self._persist_event)

    # -- lifecycle ------------------------------------------------------

    async def initialize(self) -> None:
        """Open storage and mark the runtime ready."""
        await self.storage.initialize()
        self._ready = True
        log.info("runtime initialized", **self.settings.safe_summary())

    async def shutdown(self) -> None:
        """Idempotent shutdown. Does not discard pending state."""
        self._ready = False
        await self.storage.close()
        self.bus.close()
        log.info("runtime shut down")

    # -- vertical slice ---------------------------------------------------

    async def create_session(
        self,
        source_address: str = "",
        source_port: int = 0,
        username: str = "",
        auth_method: str = "",
        auth_success: bool = False,
        metadata: Optional[dict] = None,
    ) -> Session:
        """Create a session (CREATED) and immediately activate it.

        The dev/REST path has no authentication step, so sessions move
        straight to ACTIVE; the SSH adapter will activate explicitly
        after a successful authentication attempt instead.
        """
        session = await self.sessions.create(
            source_address=source_address,
            source_port=source_port,
            username=username,
            auth_method=auth_method,
            auth_success=auth_success,
            metadata=metadata,
        )
        result = await self.sessions.activate(session.session_id)
        if not result.ok:
            # activate cannot legitimately fail here; treat as internal
            # error and close the just-created session for consistency.
            await self.sessions.close(session.session_id)
            raise RuntimeError(f"session activation failed: {result.error_code}")
        return result.value

    async def submit_command(
        self, session_id: str, raw_command: str
    ) -> RuntimeResult[CommandResult]:
        """Run one attacker-supplied command through the safe pipeline."""
        if not self._ready:
            return RuntimeResult.failure(
                "runtime.not_ready", "runtime is not initialized"
            )

        session = await self.sessions.get(session_id)
        session_check = await self.dispatcher.validate_session(session)
        if not session_check.ok:
            return session_check
        session = session_check.value

        command_check = self.dispatcher.validate_command(raw_command)
        if not command_check.ok:
            return command_check
        raw_command = command_check.value

        request = CommandRequest.new(
            session_id=session.session_id,
            raw_command=raw_command,
            working_directory=session.cwd,
        )
        await self._emit_submitted(request, session)
        result = await self.dispatcher.dispatch(request, session)
        return RuntimeResult.success(result)

    async def get_session(self, session_id: str) -> Optional[Session]:
        return await self.sessions.get(session_id)

    async def close_session(self, session_id: str) -> RuntimeResult[Session]:
        return await self.sessions.close(session_id)

    # -- health -----------------------------------------------------------

    async def health(self) -> HealthStatus:
        """Liveness: process is up and the event loop is responsive."""
        return HealthStatus(
            status="ok" if self._ready else "degraded",
            environment=self.settings.environment.value,
            security_mode=self.settings.security_mode.value,
            event_bus_running=self.bus.running,
            uptime_seconds=round(time.monotonic() - self._started_at, 2),
        )

    async def readiness(self) -> HealthStatus:
        """Readiness: storage reachable, schema applied, bus running."""
        db_ok = await self.storage.health_check()
        status = "ok" if (self._ready and db_ok) else "degraded"
        return HealthStatus(
            status=status,
            environment=self.settings.environment.value,
            security_mode=self.settings.security_mode.value,
            database_connected=db_ok,
            event_bus_running=self.bus.running,
            uptime_seconds=round(time.monotonic() - self._started_at, 2),
            active_sessions=await self.storage.sessions.count_by_status(
                SessionStatus.ACTIVE
            ),
            details=self.bus.stats,
        )

    # -- internals ---------------------------------------------------------

    async def _persist_event(self, event: SecurityEvent) -> None:
        """Bus subscriber that mirrors every event into storage."""
        try:
            await self.storage.events.save(event)
        except Exception as exc:
            # Isolation: a persistence failure must never break the
            # publisher or other subscribers.
            log.error(
                "event persistence failed",
                event_id=event.event_id,
                event_type=event.event_type,
                error=str(exc)[:200],
            )

    async def _emit_submitted(
        self, request: CommandRequest, session: Session
    ) -> None:
        event = SecurityEvent.new(
            session_id=session.session_id,
            event_type=EventType.COMMAND_SUBMITTED.value,
            severity=Severity.INFO,
            source="runtime.service",
            payload={
                "raw_command": request.raw_command[:256],
                "working_directory": request.working_directory,
            },
            metadata={"command_id": request.command_id},
        )
        await self.bus.publish(event)
