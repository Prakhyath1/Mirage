"""Session lifecycle management for the MIRAGE foundation.

The SessionManager owns the explicit session state machine:

    CREATED --> ACTIVE --> CLOSED
       |                      |
       +----------------------+
       (CREATED -> CLOSED allowed: connection dropped pre-auth or
        the peer never issued a PTY request)

Rules enforced here (and nowhere else):
- Session IDs are always server-generated and unguessable
  (:func:`app.core.ids.new_session_id`); client-supplied IDs are never
  trusted at any boundary.
- Invalid transitions (CLOSED -> ACTIVE, CLOSED -> CLOSED via update,
  unknown states) raise :class:`SessionStateError`. Double-close is
  deliberately idempotent because peers disconnecting twice is normal.
- Session mutation and persistence happen together: every accepted
  transition updates the repository and emits the corresponding event
  (SESSION_CREATED / SESSION_STATUS_CHANGED / SESSION_CLOSED) on the bus
  before the caller sees the result. Handler failures are isolated by
  the bus and never corrupt session state.
- Attacker-controlled values (username, source address, metadata) are
  stored as data only; nothing here executes or interprets them.
"""
from __future__ import annotations

from typing import Optional

from ..core.result import RuntimeResult
from ..events.bus import EventPublisher
from ..logger import get_logger
from ..models import (
    EventType,
    SecurityEvent,
    Session,
    SessionStatus,
    Severity,
    utc_now,
)
from ..storage.database import Storage
from ..core.ids import is_valid_id

log = get_logger("runtime.session_manager")

# Explicit state machine: allowed transitions.
_ALLOWED_TRANSITIONS: dict[SessionStatus, frozenset[SessionStatus]] = {
    SessionStatus.CREATED: frozenset({SessionStatus.ACTIVE, SessionStatus.CLOSED}),
    SessionStatus.ACTIVE: frozenset({SessionStatus.CLOSED}),
    SessionStatus.CLOSED: frozenset(),
}


class SessionStateError(RuntimeError):
    """Raised for invalid session state transitions."""


class SessionManager:
    """Creates, resolves, mutates and closes honeypot sessions."""

    def __init__(self, storage: Storage, bus: EventPublisher) -> None:
        self._storage = storage
        self._bus = bus
        self._in_flight: dict[str, Session] = {}

    # -- creation ----------------------------------------------------

    async def create(
        self,
        source_address: str = "",
        source_port: int = 0,
        username: str = "",
        auth_method: str = "",
        auth_success: bool = False,
        metadata: Optional[dict] = None,
    ) -> Session:
        """Create and persist a new session in the CREATED state.

        The session ID is server-generated; ``metadata`` may carry
        attacker-supplied context but is stored verbatim, never executed.
        """
        session = Session.new(
            source_address=str(source_address or "")[:64],
            source_port=int(source_port or 0),
            username=str(username or "")[:64],
            auth_method=str(auth_method or "")[:32],
            auth_success=bool(auth_success),
            metadata=dict(metadata or {}),
        )
        await self._storage.sessions.create(session)
        self._in_flight[session.session_id] = session
        await self._emit(
            EventType.SESSION_CREATED,
            session,
            Severity.INFO,
            {
                "source_address": session.source_address,
                "username": session.username,
                "auth_method": session.auth_method,
                "auth_success": session.auth_success,
            },
        )
        log.info(
            "session created",
            session_id=session.session_id,
            source_address=session.source_address,
        )
        return session

    # -- resolution --------------------------------------------------

    async def get(self, session_id: str) -> Optional[Session]:
        """Resolve a session by ID (in-memory first, then repository).

        Malformed IDs are rejected before touching the database: an
        attacker-supplied identifier is never trusted at this boundary.
        """
        if not isinstance(session_id, str) or not session_id:
            return None
        session = self._in_flight.get(session_id)
        if session is not None:
            return session
        if not is_valid_id(session_id):
            return None
        return await self._storage.sessions.get(session_id)

    async def record_auth(
        self,
        session_id: str,
        username: str = "",
        auth_method: str = "",
        auth_success: bool = False,
    ) -> RuntimeResult[Session]:
        """Record authentication facts on a session (no credentials, ever).

        Intended for the SSH adapter. A successful attempt activates the
        session; a failed attempt leaves it in CREATED so the attacker can
        keep trying. Only the verdict, method and username are stored —
        passwords never enter this path.
        """
        session = await self.get(session_id)
        if session is None:
            return RuntimeResult.failure(
                "session.not_found", f"unknown session: {session_id!r}"
            )
        if session.status is SessionStatus.CLOSED:
            raise SessionStateError(
                f"cannot record auth on closed session {session.session_id}"
            )
        updated = session.with_changes(
            username=str(username or "")[:64],
            auth_method=str(auth_method or "")[:32],
            auth_success=bool(auth_success),
        )
        await self._storage.sessions.update(updated)
        self._in_flight[session.session_id] = updated
        await self._emit(
            EventType.SESSION_STATUS_CHANGED,
            updated,
            Severity.INFO,
            {
                "change": "authentication",
                "auth_method": updated.auth_method,
                "auth_success": updated.auth_success,
            },
        )
        if auth_success and updated.status is SessionStatus.CREATED:
            return await self._transition(session_id, SessionStatus.ACTIVE)
        return RuntimeResult.success(updated)

    # -- transitions ---------------------------------------------------

    async def activate(self, session_id: str) -> RuntimeResult[Session]:
        """CREATED -> ACTIVE (authentication/PTY established)."""
        return await self._transition(session_id, SessionStatus.ACTIVE)

    async def close(self, session_id: str) -> RuntimeResult[Session]:
        """Close a session (CREATED/ACTIVE -> CLOSED). Idempotent."""
        existing = await self.get(session_id)
        if existing is None:
            return RuntimeResult.failure(
                "session.not_found", f"unknown session: {session_id!r}"
            )
        if existing.status is SessionStatus.CLOSED:
            # Idempotent close — normal in SSH teardown.
            return RuntimeResult.success(existing)
        return await self._transition(session_id, SessionStatus.CLOSED)

    async def update_metadata(
        self, session_id: str, metadata: dict
    ) -> RuntimeResult[Session]:
        """Merge metadata without changing status (e.g. threat context).

        T2/T3 use this to attach research context (threat scores,
        containment flags) to a session without owning session state.
        """
        session = await self.get(session_id)
        if session is None:
            return RuntimeResult.failure(
                "session.not_found", f"unknown session: {session_id!r}"
            )
        if session.status is SessionStatus.CLOSED:
            raise SessionStateError(
                f"cannot update metadata on closed session {session.session_id}"
            )
        merged = {**session.metadata, **dict(metadata or {})}
        updated = session.with_changes(metadata=merged)
        await self._storage.sessions.update(updated)
        self._in_flight[session.session_id] = updated
        await self._emit(
            EventType.SESSION_STATUS_CHANGED,
            updated,
            Severity.DEBUG,
            {"change": "metadata", "metadata_keys": sorted(merged.keys())[:32]},
        )
        return RuntimeResult.success(updated)

    # -- internals -----------------------------------------------------

    async def _transition(
        self, session_id: str, target: SessionStatus
    ) -> RuntimeResult[Session]:
        session = await self.get(session_id)
        if session is None:
            return RuntimeResult.failure(
                "session.not_found", f"unknown session: {session_id!r}"
            )
        allowed = _ALLOWED_TRANSITIONS.get(session.status, frozenset())
        if target not in allowed:
            raise SessionStateError(
                f"invalid transition {session.status.value} -> {target.value} "
                f"for session {session.session_id}"
            )
        updated = session.with_changes(status=target)
        await self._storage.sessions.update(updated)
        if target is SessionStatus.CLOSED:
            self._in_flight.pop(session.session_id, None)
        else:
            self._in_flight[session.session_id] = updated
        await self._emit(EventType.SESSION_STATUS_CHANGED, updated, Severity.INFO, {"to_status": target.value})
        if target is SessionStatus.CLOSED:
            await self._emit(EventType.SESSION_CLOSED, updated, Severity.INFO, None)
        return RuntimeResult.success(updated)

    async def _emit(
        self,
        event_type: EventType,
        session: Session,
        severity: Severity,
        payload: Optional[dict],
    ) -> None:
        event = SecurityEvent.new(
            session_id=session.session_id,
            event_type=event_type.value,
            severity=severity,
            source="runtime.session_manager",
            payload=dict(payload or {}),
            timestamp=utc_now(),
        )
        await self._bus.publish(event)
