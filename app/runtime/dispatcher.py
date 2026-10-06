"""Command pipeline: intake -> dispatch -> handler -> result -> event.

The dispatcher is the single funnel through which attacker input flows.
It never executes anything itself: it selects a registered
:class:`CommandHandler` and hands it a :class:`CommandRequest`. If no
handler claims the command, the :class:`SafeFallbackHandler` produces a
simulated response. Either way, a :class:`CommandResult` and a
:class:`SecurityEvent` are produced and persisted.

SECURITY BOUNDARY (non-negotiable):
- No code in this module (or in any handler) may execute attacker input
  on the host: no ``os.system``, no ``subprocess`` with attacker-derived
  strings, no ``shell=True``, no ``eval``/``exec``.
- Command strings are data. They are stored, logged (truncated), and
  passed to handlers as values — never interpreted by the host shell.
- The fallback handler *simulates* output (static, prefix-derived
  text). It must never touch the real filesystem, network, or processes.

Handler registration is how T2 (agentic) and T3 (VFS/security) plug in:
they call :meth:`CommandDispatcher.register` with a name and a handler.
T1 keeps no knowledge of their internals — only the
:class:`CommandHandler` protocol below.
"""
from __future__ import annotations

import time
from typing import Optional, Protocol, runtime_checkable

from .. import config
from ..config import Settings
from ..core.ids import is_valid_id
from ..core.result import RuntimeResult
from ..events.bus import EventPublisher
from ..logger import get_logger
from ..models import (
    CommandRequest,
    CommandResult,
    EventType,
    ResultType,
    SecurityEvent,
    Session,
    SessionStatus,
    Severity,
    utc_now,
)
from ..storage.database import Storage

log = get_logger("runtime.dispatcher")

# Commands that fall through to the safe fallback when no T3 VFS handler
# is registered. Anything a handler claims never reaches the fallback.
_FALLBACK_HINTS: tuple[tuple[str, str], ...] = (
    # (prefix, simulated response) — static text only, nothing executed.
    # Identity lines use the T3 decoy identity (config.DEFAULT_USER),
    # never the host user: the fallback must present the same fake
    # identity as the pipeline so a handler outage cannot leak it.
    ("whoami", f"{config.DEFAULT_USER}\n"),
    ("hostname", "mirage-host\n"),
    ("uname", "Linux mirage-host 5.15.0-generic #1 SMP x86_64 GNU/Linux\n"),
    ("id", f"uid=1000({config.DEFAULT_USER}) gid=1000({config.DEFAULT_USER}) "
           f"groups=1000({config.DEFAULT_USER})\n"),
    ("pwd", f"{config.DEFAULT_HOME}\n"),
    ("ls", "Desktop  Documents  Downloads  examples.desktop\n"),
    ("cat /etc/passwd",
     "root:x:0:0:root:/root:/bin/bash\n"
     f"{config.DEFAULT_USER}:x:1000:1000:Admin:{config.DEFAULT_HOME}:/bin/bash\n"),
    ("cat /etc/os-release",
     'NAME="Ubuntu"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\n'),
    ("uptime", " 14:23:11 up 3 days,  2:41,  1 user,  load average: 0.08, 0.03, 0.01\n"),
    ("w", " 14:23 up 3 days, 2:41, 1 user, load average: 0.08, 0.03, 0.01\n"),
    ("ps", "  PID TTY          TIME CMD\n 1234 pts/0    00:00:00 bash\n"),
    ("netstat", "Active Internet connections (w/o servers)\n"),
    ("ifconfig", "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu: 1500\n"),
    ("crontab", f"no crontab for {config.DEFAULT_USER}\n"),
    ("sudo", "sudo: unable to resolve host mirage-host: Name or service not known\n"
             f"{config.DEFAULT_USER} is not in the sudoers file.  This incident will be reported.\n"),
)
_UNRECOGNISED = (
    "bash: {first}: command not found\n"
)


@runtime_checkable
class CommandHandler(Protocol):
    """A pluggable consumer of commands (T2 agentic, T3 VFS/security).

    Implementations MUST:
    - never execute the raw command on the host,
    - return a :class:`CommandResult` (never raise for expected
      conditions; raise only for genuine internal failures, which the
    dispatcher converts into an error result).
    """

    name: str

    async def handle(self, request: CommandRequest) -> CommandResult:
        ...


class SafeFallbackHandler:
    """Simulates command output without any host interaction.

    Used when no other handler claims a command. SECURITY: this class
    contains no subprocess, filesystem or network calls; the response
    for a command is derived from a static lookup table plus literal
    text of the command's first token (echoed back as data only).
    """

    name = "safe_fallback"

    async def handle(self, request: CommandRequest) -> CommandResult:
        started = time.monotonic()
        command = request.raw_command
        first = command.split(" ", 1)[0] if command else ""
        stdout = ""
        exit_code = 0
        for prefix, response in _FALLBACK_HINTS:
            if command == prefix or command.startswith(prefix + " "):
                stdout = response
                break
        else:
            stdout = _UNRECOGNISED.format(first=first[:32])
            exit_code = 127
        return CommandResult.new(
            command_id=request.command_id,
            stdout=stdout,
            stderr="",
            exit_code=exit_code,
            duration=time.monotonic() - started,
            result_type=ResultType.FALLBACK,
            metadata={"simulated": True, "note": "host execution not performed"},
        )


class CommandDispatcher:
    """Routes validated CommandRequests to registered handlers.

    Selection strategy (deliberately simple and deterministic):
    1. Handlers are consulted in registration order via ``claims``;
       the first to claim the command handles it. T2/T3 own their claim
       logic; T1 only enforces the protocol.
    2. If nothing claims it, the SafeFallbackHandler runs.

    The dispatcher owns result persistence and event emission so every
    command, regardless of handler, leaves the same audit trail.
    """

    def __init__(
        self,
        storage: Storage,
        bus: EventPublisher,
        settings: Settings,
        fallback: Optional[CommandHandler] = None,
    ) -> None:
        self._storage = storage
        self._bus = bus
        self._settings = settings
        self._handlers: list[CommandHandler] = []
        self._fallback = fallback or SafeFallbackHandler()
        self._processed_count = 0
        self._fallback_count = 0

    # -- registration (T2/T3 integration point) ----------------------

    def register(self, handler: CommandHandler) -> None:
        """Register a handler. Later registrations are consulted first
        (LIFO) so newer subsystems override older ones for overlapping
        commands."""
        if handler not in self._handlers:
            self._handlers.insert(0, handler)
            log.info("command handler registered", handler=handler.name)

    def unregister(self, name: str) -> None:
        self._handlers = [h for h in self._handlers if h.name != name]

    def registered_handlers(self) -> list[str]:
        return [h.name for h in self._handlers]

    # -- pipeline ------------------------------------------------------

    async def dispatch(
        self, request: CommandRequest, session: Session
    ) -> CommandResult:
        """Run one command through the pipeline and persist everything."""
        self._processed_count += 1

        # Persist intake first so the command is on record even if a
        # handler hangs or the process dies mid-dispatch.
        await self._storage.commands.create(request)

        await self._emit(
            EventType.COMMAND_DISPATCHED,
            request,
            session,
            Severity.INFO,
            {"handler": None, "status": "selecting"},
        )

        handler, result = await self._run_handlers(request)

        await self._storage.commands.save_result(result, session.session_id)
        await self._emit(
            EventType.COMMAND_COMPLETED,
            request,
            session,
            Severity.INFO,
            {
                "handler": handler.name,
                "result_type": result.result_type.value,
                "exit_code": result.exit_code,
                "duration_ms": round(result.duration * 1000, 2),
            },
        )
        log.info(
            "command dispatched",
            session_id=session.session_id,
            command_id=request.command_id,
            handler=handler.name,
            result_type=result.result_type.value,
        )
        return result

    async def _run_handlers(
        self, request: CommandRequest
    ) -> tuple[CommandHandler, CommandResult]:
        for handler in self._handlers:
            try:
                claims = bool(getattr(handler, "claims", None))
                if claims and not handler.claims(request):  # type: ignore[attr-defined]
                    continue
                result = await handler.handle(request)
                if result is None:
                    continue
                return handler, result
            except Exception as exc:
                # One broken handler must not take down the pipeline;
                # log and fall through to the next (or the fallback).
                log.error(
                    "command handler raised; isolating failure",
                    session_id=request.session_id,
                    command_id=request.command_id,
                    handler=handler.name,
                    error=str(exc)[:200],
                )
                await self._emit_runtime_error(
                    request, f"handler {handler.name!r} raised: {exc!r}"
                )
                continue
        self._fallback_count += 1
        result = await self._fallback.handle(request)
        return self._fallback, result

    # -- intake validation ---------------------------------------------

    def validate_command(self, raw_command: str) -> RuntimeResult[str]:
        """Boundary validation of a raw command string.

        Attacker-supplied: length-capped, must be text, must not contain
        NUL bytes (which would smuggle content past truncation). Note we
        do NOT attempt to parse or "sanitise" the command — it is stored
        as data and only ever reaches simulators as data.
        """
        if not isinstance(raw_command, str) or not raw_command.strip():
            return RuntimeResult.failure(
                "command.empty", "command must be non-empty text"
            )
        if "\x00" in raw_command:
            return RuntimeResult.failure(
                "command.nul_byte", "command contains NUL byte"
            )
        limit = self._settings.max_command_length
        if len(raw_command) > limit:
            return RuntimeResult.failure(
                "command.too_long",
                f"command exceeds {limit} characters",
            )
        return RuntimeResult.success(raw_command.strip())

    async def validate_session(self, session: Session) -> RuntimeResult[Session]:
        if session is None:
            return RuntimeResult.failure("session.missing", "no session given")
        if not is_valid_id(session.session_id):
            return RuntimeResult.failure(
                "session.invalid_id", "session id failed validation"
            )
        if session.status is not SessionStatus.ACTIVE:
            return RuntimeResult.failure(
                "session.not_active",
                f"session is {session.status.value}, commands require ACTIVE",
            )
        return RuntimeResult.success(session)

    # -- events ----------------------------------------------------------

    async def _emit(
        self,
        event_type: EventType,
        request: CommandRequest,
        session: Session,
        severity: Severity,
        payload: dict,
    ) -> None:
        event = SecurityEvent.new(
            session_id=session.session_id,
            event_type=event_type.value,
            severity=severity,
            source="runtime.dispatcher",
            payload=dict(payload),
            metadata={"command_id": request.command_id},
        )
        await self._bus.publish(event)

    async def _emit_runtime_error(self, request: CommandRequest, detail: str) -> None:
        event = SecurityEvent.new(
            session_id=request.session_id,
            event_type=EventType.RUNTIME_ERROR.value,
            severity=Severity.HIGH,
            source="runtime.dispatcher",
            payload={"detail": detail[:512]},
            metadata={"command_id": request.command_id},
        )
        await self._bus.publish(event)

    @property
    def stats(self) -> dict:
        return {
            "processed": self._processed_count,
            "fallback": self._fallback_count,
            "handlers": self.registered_handlers(),
        }
