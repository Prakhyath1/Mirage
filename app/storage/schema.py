"""Deterministic SQLite schema for the MIRAGE foundation.

Only this module owns SQL DDL. The storage layer (storage/database.py) is
the single place where connections are created; no other module may open
a database connection directly.

Schema decisions:
- SQLite for local development. The database module exposes a small,
  typed repository interface so a PostgreSQL migration later means
  swapping the engine and dialect, not rewriting call sites.
- JSON columns store structured payloads with size limits enforced at the
  boundary (see repositories), not by the database.
- Indexes cover every frequently queried identifier and timestamp.
"""
from __future__ import annotations

SCHEMA_VERSION = 2

DDL_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS schema_info (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'CREATED',
        source_address TEXT NOT NULL DEFAULT '',
        source_port INTEGER NOT NULL DEFAULT 0,
        username TEXT NOT NULL DEFAULT '',
        auth_method TEXT NOT NULL DEFAULT '',
        auth_success INTEGER NOT NULL DEFAULT 0,
        cwd TEXT NOT NULL DEFAULT '/home/admin',
        metadata TEXT NOT NULL DEFAULT '{}'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS commands (
        command_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        raw_command TEXT NOT NULL,
        timestamp REAL NOT NULL,
        working_directory TEXT NOT NULL DEFAULT '/home/admin',
        terminal TEXT NOT NULL DEFAULT '{}',
        metadata TEXT NOT NULL DEFAULT '{}',
        FOREIGN KEY (session_id) REFERENCES sessions(session_id)
    )
    """,
    # Result columns live on the commands row: every command in this
    # table has completed processing (results are persisted together
    # with intake via update_command_result).
    """
    CREATE TABLE IF NOT EXISTS command_results (
        command_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        stdout TEXT NOT NULL DEFAULT '',
        stderr TEXT NOT NULL DEFAULT '',
        exit_code INTEGER NOT NULL DEFAULT 0,
        duration REAL NOT NULL DEFAULT 0,
        result_type TEXT NOT NULL DEFAULT 'fallback',
        metadata TEXT NOT NULL DEFAULT '{}',
        completed_at REAL NOT NULL,
        FOREIGN KEY (command_id) REFERENCES commands(command_id),
        FOREIGN KEY (session_id) REFERENCES sessions(session_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS events (
        event_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        timestamp REAL NOT NULL,
        severity TEXT NOT NULL DEFAULT 'info',
        source TEXT NOT NULL DEFAULT 'runtime',
        payload TEXT NOT NULL DEFAULT '{}',
        metadata TEXT NOT NULL DEFAULT '{}'
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions (status)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions (created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_updated ON sessions (updated_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_commands_session ON commands (session_id)",
    "CREATE INDEX IF NOT EXISTS idx_commands_timestamp ON commands (timestamp DESC)",
    "CREATE INDEX IF NOT EXISTS idx_command_results_session ON command_results (session_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_session ON events (session_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_type ON events (event_type)",
    "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp DESC)",
    "CREATE INDEX IF NOT EXISTS idx_events_severity ON events (severity)",
)

def apply_schema(cursor) -> None:
    """Apply DDL deterministically and stamp the schema version."""
    for stmt in DDL_STATEMENTS:
        cursor.execute(stmt)
    cursor.execute(
        "INSERT INTO schema_info (key, value) VALUES ('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(SCHEMA_VERSION),),
    )
