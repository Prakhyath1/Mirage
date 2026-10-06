"""Application configuration for MIRAGE.

All configuration is read from the environment (optionally seeded from a
local ``.env`` file via python-dotenv if present). Secrets are never
hardcoded and never logged or included in ``model_dump`` output.

Safe defaults target local development: SQLite under ``data/``, an
explicitly permissive ``development`` environment, and strict input
limits so a hostile peer cannot balloon memory or the database.
"""
from __future__ import annotations

import os
from enum import Enum
from functools import lru_cache
from pathlib import Path

try:  # optional, keeps local dev convenient
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover - optional dependency
    pass

BASE_DIR = Path(__file__).resolve().parent.parent

# Values that must never appear in logs, errors, or config dumps.
_SECRET_MARKERS = ("password", "secret", "token", "key")


class Environment(str, Enum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"


class SecurityMode(str, Enum):
    """How strictly untrusted input is treated.

    ``strict`` is the only safe default: every command is simulated, never
    executed. ``degraded`` exists so a future sandbox owner (T3) can flag
    reduced-observability operation; it never permits host execution.
    """

    STRICT = "strict"
    DEGRADED = "degraded"


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class Settings:
    """Runtime settings. Immutable after construction."""

    __slots__ = (
        "environment",
        "host",
        "port",
        "database_path",
        "database_url",
        "log_level",
        "llm_endpoint_url",
        "llm_model",
        "llm_timeout_seconds",
        "max_sessions",
        "max_concurrent_sessions",
        "max_command_length",
        "max_commands_per_session",
        "max_command_output_bytes",
        "max_event_payload_bytes",
        "session_idle_timeout_seconds",
        "security_mode",
        "debug",
    )

    def __init__(self) -> None:
        self.environment = Environment(
            os.getenv("MIRAGE_ENV", Environment.DEVELOPMENT.value)
        )
        self.host = os.getenv("MIRAGE_HOST", "127.0.0.1")
        self.port = self._int("MIRAGE_PORT", 8000)
        # Separate file from the legacy prototype database (data/mirage.db):
        # both define `sessions`/`events` tables with incompatible shapes,
        # so sharing a file would corrupt one or the other.
        self.database_path = Path(
            os.getenv("MIRAGE_DB_PATH", str(BASE_DIR / "data" / "mirage_foundation.db"))
        )
        self.database_url = os.getenv(
            "MIRAGE_DATABASE_URL", f"sqlite:///{self.database_path}"
        )
        self.log_level = LogLevel(
            os.getenv("MIRAGE_LOG_LEVEL", LogLevel.INFO.value)
        )
        # LLM placeholder: T2 owns the engine; T1 only carries connection
        # configuration so we do not hardcode endpoints in their modules.
        self.llm_endpoint_url = os.getenv("MIRAGE_LLM_ENDPOINT_URL", "")
        self.llm_model = os.getenv("MIRAGE_LLM_MODEL", "")
        self.llm_timeout_seconds = self._float("MIRAGE_LLM_TIMEOUT", 120.0)
        # Session limits
        self.max_sessions = self._int("MIRAGE_MAX_SESSIONS", 10_000)
        self.max_concurrent_sessions = self._int("MIRAGE_MAX_CONCURRENT_SESSIONS", 200)
        self.session_idle_timeout_seconds = self._int(
            "MIRAGE_SESSION_IDLE_TIMEOUT", 1800
        )
        # Command limits
        self.max_command_length = self._int("MIRAGE_MAX_COMMAND_LENGTH", 2048)
        self.max_commands_per_session = self._int(
            "MIRAGE_MAX_COMMANDS_PER_SESSION", 5_000
        )
        self.max_command_output_bytes = self._int(
            "MIRAGE_MAX_COMMAND_OUTPUT_BYTES", 65_536
        )
        # Event/storage limits
        self.max_event_payload_bytes = self._int("MIRAGE_MAX_EVENT_PAYLOAD_BYTES", 32_768)
        # Security
        self.security_mode = SecurityMode(
            os.getenv("MIRAGE_SECURITY_MODE", SecurityMode.STRICT.value)
        )
        self.debug = self._bool("MIRAGE_DEBUG", default=False)

    # -- helpers -----------------------------------------------------

    @staticmethod
    def _int(name: str, default: int) -> int:
        raw = os.getenv(name, "")
        try:
            return int(raw) if raw else default
        except ValueError:
            return default

    @staticmethod
    def _float(name: str, default: float) -> float:
        raw = os.getenv(name, "")
        try:
            return float(raw) if raw else default
        except ValueError:
            return default

    @staticmethod
    def _bool(name: str, default: bool) -> bool:
        raw = os.getenv(name, "")
        if not raw:
            return default
        return raw.strip().lower() in ("1", "true", "yes", "on")

    @property
    def is_production(self) -> bool:
        return self.environment is Environment.PRODUCTION

    def safe_summary(self) -> dict:
        """Configuration summary safe for logs and /health responses.

        Deliberately whitelisted: any future secret-bearing setting is
        excluded unless explicitly added here.
        """
        return {
            "environment": self.environment.value,
            "host": self.host,
            "port": self.port,
            "database_url": self.database_url if not self._db_has_secret() else "[redacted]",
            "log_level": self.log_level.value,
            "security_mode": self.security_mode.value,
            "debug": self.debug,
            "max_sessions": self.max_sessions,
            "max_concurrent_sessions": self.max_concurrent_sessions,
            "max_command_length": self.max_command_length,
            "max_commands_per_session": self.max_commands_per_session,
            "max_command_output_bytes": self.max_command_output_bytes,
            "max_event_payload_bytes": self.max_event_payload_bytes,
        }

    def _db_has_secret(self) -> bool:
        url = self.database_url.lower()
        return any(m in url for m in ("password=", "://:", "@"))
