"""SSH interface preparation (interface only — no SSH implementation).

The real SSH server (AsyncSSH or equivalent) will be added in a later
task. T1 provides this adapter contract so the transport can be plugged
in without touching the runtime: an SSH adapter observes transport
events and drives the same runtime APIs the dev/REST path uses.

Lifecycle an adapter must translate into runtime calls:

    connection accepted      -> SessionManager.create(source_address,
                                                      source_port)
    authentication attempted -> session metadata (auth_method,
                                auth_success, username) — never passwords
    session created          -> SessionManager.activate(session_id)
    PTY requested            -> session metadata (terminal size/type)
    command received         -> MirageRuntime.submit_command(...)
    session closed           -> SessionManager.close(session_id)

SECURITY: adapters receive fully attacker-controlled data. They must
treat every field as untrusted input: validate lengths at this boundary,
never trust client-supplied session IDs (the runtime always uses its
own server-generated IDs), and never pass credentials (even rejected
ones) into logs or events.
"""
from __future__ import annotations

from typing import Any, Optional, Protocol, runtime_checkable

from .session_manager import SessionManager
from .dispatcher import CommandDispatcher


@runtime_checkable
class SSHTransportObserver(Protocol):
    """Callback surface an SSH server implementation uses to drive the
    runtime. T1 defines it; the AsyncSSH task implements it."""

    def on_connection_accepted(
        self, source_address: str, source_port: int
    ) -> None:
        """A TCP connection arrived (pre-authentication)."""
        ...

    def on_authentication_attempt(
        self,
        session_id: str,
        username: str,
        auth_method: str,
        auth_success: bool,
    ) -> None:
        """An authentication attempt completed. Passwords are never
        included here — only the verdict and the method."""
        ...

    def on_pty_requested(
        self, session_id: str, term: str, width: int, height: int
    ) -> None:
        """The client requested a PTY."""
        ...

    def on_command_received(self, session_id: str, raw_command: str) -> None:
        """A command line arrived on the channel."""
        ...

    def on_session_closed(self, session_id: str) -> None:
        """The connection or channel closed."""
        ...


class SSHAdapterBase:
    """Reference skeleton for a future AsyncSSH-backed adapter.

    Subclasses translate transport callbacks into the runtime calls
    shown in each method. Everything below is already safe: it only
    forwards data into the validated runtime funnel — nothing executes
    on the host and client-supplied identifiers are never trusted.
    """

    def __init__(
        self,
        session_manager: SessionManager,
        dispatcher: CommandDispatcher,
        runtime: Any = None,
    ) -> None:
        self._sessions = session_manager
        self._dispatcher = dispatcher
        self._runtime = runtime

    async def connection_accepted(
        self, source_address: str, source_port: int
    ) -> str:
        session = await self._sessions.create(
            source_address=str(source_address or "")[:64],
            source_port=int(source_port or 0),
        )
        return session.session_id

    async def authentication_attempt(
        self,
        session_id: str,
        username: str,
        auth_method: str,
        auth_success: bool,
    ) -> None:
        # Delegate to the session manager: records the verdict and method
        # (no credentials, ever) and activates on success.
        await self._sessions.record_auth(
            session_id,
            username=str(username or "")[:64],
            auth_method=str(auth_method or "")[:32],
            auth_success=bool(auth_success),
        )

    async def pty_requested(
        self, session_id: str, term: str, width: int, height: int
    ) -> None:
        session = await self._sessions.get(session_id)
        if session is None:
            return
        terminal = {
            "term": str(term or "xterm-256color")[:32],
            "width": max(1, min(int(width or 80), 1000)),
            "height": max(1, min(int(height or 24), 1000)),
        }
        await self._sessions.update_metadata(
            session_id, {"terminal": terminal}
        )

    async def command_received(self, session_id: str, raw_command: str) -> None:
        """Forward to the runtime funnel if a runtime is attached."""
        if self._runtime is None:
            return
        await self._runtime.submit_command(session_id, raw_command)

    async def session_closed(self, session_id: str) -> None:
        await self._sessions.close(session_id)
