"""Centralized async persistence for the MIRAGE foundation.

This module is the ONLY place in the codebase that opens database
connections. Repositories expose typed, async methods over the contracts
in :mod:`app.models`; call sites never see SQL or connections.

Concurrency model:
- SQLite in WAL mode, one connection per database (async access is
  serialised through a single asyncio lock plus ``asyncio.to_thread``).
  This is the simplest architecture that is safe under concurrent async
  access and keeps a future PostgreSQL migration to swapping the engine
  (the repository method signatures are the migration contract).
- JSON fields are encoded/decoded here with strict size limits so no
  unbounded blob ever reaches the database.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from typing import Any, Optional

from ..config import Settings
from ..logger import get_logger
from ..models import (
    CommandRequest,
    CommandResult,
    EventType,
    SecurityEvent,
    Session,
    SessionStatus,
    SessionSummary,
    Severity,
)
from .schema import SCHEMA_VERSION, apply_schema

log = get_logger("storage.database")

_MAX_JSON_FIELD_BYTES = 256 * 1024  # hard cap for any JSON column


class DatabaseError(RuntimeError):
    """Raised for unexpected persistence failures."""


def _dump_json(value: Any, limit: int = _MAX_JSON_FIELD_BYTES) -> str:
    text = json.dumps(value, default=str, separators=(",", ":"))
    if len(text.encode("utf-8")) > limit:
        text = json.dumps({"truncated": True, "size": len(text)})
    return text


def _load_json(text: str, default: Any = None) -> Any:
    if not text:
        return {} if default is None else default
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return {} if default is None else default


def _row_to_session(row: sqlite3.Row) -> Session:
    return Session(
        session_id=row["session_id"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        status=SessionStatus(row["status"]),
        source_address=row["source_address"],
        source_port=row["source_port"],
        username=row["username"],
        auth_method=row["auth_method"],
        auth_success=bool(row["auth_success"]),
        cwd=row["cwd"],
        metadata=_load_json(row["metadata"]),
    )


def _row_to_command(row: sqlite3.Row) -> CommandRequest:
    return CommandRequest(
        command_id=row["command_id"],
        session_id=row["session_id"],
        raw_command=row["raw_command"],
        timestamp=row["timestamp"],
        working_directory=row["working_directory"],
        terminal=_load_json(row["terminal"]),
        metadata=_load_json(row["metadata"]),
    )


def _row_to_result(row: sqlite3.Row) -> CommandResult:
    from ..models import ResultType

    return CommandResult(
        command_id=row["command_id"],
        stdout=row["stdout"],
        stderr=row["stderr"],
        exit_code=row["exit_code"],
        duration=row["duration"],
        result_type=ResultType(row["result_type"]),
        metadata=_load_json(row["metadata"]),
    )


def _row_to_event(row: sqlite3.Row) -> SecurityEvent:
    return SecurityEvent(
        event_id=row["event_id"],
        session_id=row["session_id"],
        event_type=row["event_type"],
        timestamp=row["timestamp"],
        severity=Severity(row["severity"]),
        source=row["source"],
        payload=_load_json(row["payload"]),
        metadata=_load_json(row["metadata"]),
    )


class Database:
    """Async facade over a single SQLite connection (WAL mode)."""

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._lock = asyncio.Lock()
        self._conn: sqlite3.Connection | None = None
        self._initialized = False

    # -- lifecycle ---------------------------------------------------

    async def initialize(self) -> None:
        """Create the database file (parent dirs included) and schema.

        Deterministic: safe to call repeatedly; statements are idempotent.
        """
        async with self._lock:
            if self._initialized:
                return
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = await asyncio.to_thread(self._open_connection)
            await asyncio.to_thread(self._init_schema)
            self._initialized = True
            log.info(
                "database initialized",
                path=str(self._path),
                schema_version=SCHEMA_VERSION,
            )

    def _open_connection(self) -> sqlite3.Connection:
        # Every operation runs via asyncio.to_thread, so the executor
        # thread is not guaranteed to be the one that opened the handle.
        # All access is serialized by the single asyncio.Lock above, so
        # disabling sqlite's own thread-affinity check is safe here.
        conn = sqlite3.connect(
            self._path, timeout=30.0, check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        assert self._conn is not None
        cur = self._conn.cursor()
        try:
            apply_schema(cur)
            self._conn.commit()
        except sqlite3.Error:
            self._conn.rollback()
            raise

    async def close(self) -> None:
        async with self._lock:
            if self._conn is not None:
                await asyncio.to_thread(self._conn.close)
                self._conn = None
            self._initialized = False

    async def health_check(self) -> bool:
        try:
            row = await self.execute_readone("SELECT 1")
            return row is not None
        except Exception:
            return False

    # -- low-level execution (private; repositories use typed methods) --

    async def execute(
        self, sql: str, params: tuple = ()
    ) -> int:
        if not self._initialized or self._conn is None:
            raise DatabaseError("database not initialized")
        async with self._lock:
            def _run() -> int:
                assert self._conn is not None
                cur = self._conn.execute(sql, params)  # type: ignore[union-attr]
                self._conn.commit()  # type: ignore[union-attr]
                return cur.rowcount
            return await asyncio.to_thread(_run)

    async def execute_readone(
        self, sql: str, params: tuple = ()
    ) -> Optional[sqlite3.Row]:
        if not self._initialized or self._conn is None:
            raise DatabaseError("database not initialized")
        async with self._lock:
            def _run() -> Optional[sqlite3.Row]:
                assert self._conn is not None
                cur = self._conn.execute(sql, params)  # type: ignore[union-attr]
                return cur.fetchone()
            return await asyncio.to_thread(_run)

    async def execute_readall(
        self, sql: str, params: tuple = ()
    ) -> list[sqlite3.Row]:
        if not self._initialized or self._conn is None:
            raise DatabaseError("database not initialized")
        async with self._lock:
            def _run() -> list[sqlite3.Row]:
                assert self._conn is not None
                cur = self._conn.execute(sql, params)  # type: ignore[union-attr]
                return cur.fetchall()
            return await asyncio.to_thread(_run)


class SessionRepository:
    """Persistence for :class:`Session` objects."""

    def __init__(self, db: Database) -> None:
        self._db = db

    async def create(self, session: Session) -> None:
        await self._db.execute(
            """
            INSERT INTO sessions
                (session_id, created_at, updated_at, status, source_address,
                 source_port, username, auth_method, auth_success, cwd, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session.session_id,
                session.created_at,
                session.updated_at,
                session.status.value,
                session.source_address,
                session.source_port,
                session.username,
                session.auth_method,
                int(session.auth_success),
                session.cwd,
                _dump_json(session.metadata),
            ),
        )

    async def get(self, session_id: str) -> Optional[Session]:
        row = await self._db.execute_readone(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        )
        return _row_to_session(row) if row else None

    async def update(self, session: Session) -> None:
        """Persist the full state of ``session`` (state transitions are
        validated upstream by the SessionManager)."""
        await self._db.execute(
            """
            UPDATE sessions SET
                updated_at = ?, status = ?, source_address = ?, source_port = ?,
                username = ?, auth_method = ?, auth_success = ?, cwd = ?, metadata = ?
            WHERE session_id = ?
            """,
            (
                session.updated_at,
                session.status.value,
                session.source_address,
                session.source_port,
                session.username,
                session.auth_method,
                int(session.auth_success),
                session.cwd,
                _dump_json(session.metadata),
                session.session_id,
            ),
        )

    async def close_status(self, session_id: str, closed_at: float) -> None:
        await self._db.execute(
            "UPDATE sessions SET status = ?, updated_at = ? WHERE session_id = ?",
            (SessionStatus.CLOSED.value, closed_at, session_id),
        )

    async def count_by_status(self, status: SessionStatus) -> int:
        row = await self._db.execute_readone(
            "SELECT COUNT(*) AS n FROM sessions WHERE status = ?",
            (status.value,),
        )
        return int(row["n"]) if row else 0

    async def list_recent(self, limit: int = 50) -> list[Session]:
        rows = await self._db.execute_readall(
            "SELECT * FROM sessions ORDER BY updated_at DESC LIMIT ?", (limit,)
        )
        return [_row_to_session(r) for r in rows]

    async def summary(
        self, session_id: str, command_count: int | None = None
    ) -> Optional[SessionSummary]:
        session = await self.get(session_id)
        if session is None:
            return None
        if command_count is None:
            row = await self._db.execute_readone(
                "SELECT COUNT(*) AS n FROM commands WHERE session_id = ?",
                (session_id,),
            )
            command_count = int(row["n"]) if row else 0
        last = await self._db.execute_readone(
            """
            SELECT raw_command FROM commands
            WHERE session_id = ? ORDER BY timestamp DESC LIMIT 1
            """,
            (session_id,),
        )
        return SessionSummary.from_session(
            session,
            command_count=command_count,
            last_command=last["raw_command"] if last else None,
            metrics={"status": session.status.value},
        )


class CommandRepository:
    """Persistence for commands and their results."""

    def __init__(self, db: Database) -> None:
        self._db = db

    async def create(self, request: CommandRequest) -> None:
        await self._db.execute(
            """
            INSERT INTO commands
                (command_id, session_id, raw_command, timestamp,
                 working_directory, terminal, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.command_id,
                request.session_id,
                request.raw_command,
                request.timestamp,
                request.working_directory,
                _dump_json(request.terminal),
                _dump_json(request.metadata),
            ),
        )

    async def save_result(self, result: CommandResult, session_id: str) -> None:
        from ..models import utc_now

        await self._db.execute(
            """
            INSERT OR REPLACE INTO command_results
                (command_id, session_id, stdout, stderr, exit_code,
                 duration, result_type, metadata, completed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.command_id,
                session_id,
                result.stdout,
                result.stderr,
                result.exit_code,
                result.duration,
                result.result_type.value,
                _dump_json(result.metadata),
                utc_now(),
            ),
        )

    async def get(self, command_id: str) -> Optional[CommandRequest]:
        row = await self._db.execute_readone(
            "SELECT * FROM commands WHERE command_id = ?", (command_id,)
        )
        return _row_to_command(row) if row else None

    async def get_result(self, command_id: str) -> Optional[CommandResult]:
        row = await self._db.execute_readone(
            "SELECT * FROM command_results WHERE command_id = ?", (command_id,)
        )
        return _row_to_result(row) if row else None

    async def list_for_session(
        self, session_id: str, limit: int = 100
    ) -> list[CommandRequest]:
        rows = await self._db.execute_readall(
            """
            SELECT * FROM commands WHERE session_id = ?
            ORDER BY timestamp DESC LIMIT ?
            """,
            (session_id, limit),
        )
        return [_row_to_command(r) for r in rows]

    async def count_for_session(self, session_id: str) -> int:
        row = await self._db.execute_readone(
            "SELECT COUNT(*) AS n FROM commands WHERE session_id = ?",
            (session_id,),
        )
        return int(row["n"]) if row else 0


class EventRepository:
    """Persistence for :class:`SecurityEvent` objects."""

    def __init__(self, db: Database) -> None:
        self._db = db

    async def save(self, event: SecurityEvent) -> None:
        await self._db.execute(
            """
            INSERT INTO events
                (event_id, session_id, event_type, timestamp, severity,
                 source, payload, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                event.session_id,
                event.event_type,
                event.timestamp,
                event.severity.value,
                event.source,
                _dump_json(event.payload),
                _dump_json(event.metadata),
            ),
        )

    async def get(self, event_id: str) -> Optional[SecurityEvent]:
        row = await self._db.execute_readone(
            "SELECT * FROM events WHERE event_id = ?", (event_id,)
        )
        return _row_to_event(row) if row else None

    async def list_for_session(
        self, session_id: str, limit: int = 100
    ) -> list[SecurityEvent]:
        rows = await self._db.execute_readall(
            """
            SELECT * FROM events WHERE session_id = ?
            ORDER BY timestamp DESC LIMIT ?
            """,
            (session_id, limit),
        )
        return [_row_to_event(r) for r in rows]

    async def list_recent(
        self, limit: int = 100, event_type: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> list[SecurityEvent]:
        clauses, params = [], []
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        rows = await self._db.execute_readall(
            f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ?",
            tuple(params),
        )
        return [_row_to_event(r) for r in rows]


class Storage:
    """Aggregate root over the database and its repositories.

    Components receive a :class:`Storage` instance; they never touch the
    raw connection. Construction is cheap; call :meth:`initialize` once
    at startup.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.database = Database(settings.database_path)
        self.sessions = SessionRepository(self.database)
        self.commands = CommandRepository(self.database)
        self.events = EventRepository(self.database)

    async def initialize(self) -> None:
        await self.database.initialize()

    async def close(self) -> None:
        await self.database.close()

    async def health_check(self) -> bool:
        return await self.database.health_check()
