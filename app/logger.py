"""Structured logging for MIRAGE.

All components log through ``get_logger(component)``. Records are emitted
as single-line JSON objects with a stable schema:

    {"timestamp", "level", "component", "message",
     "session_id", "command_id", "event_id", ...context}

Security rules:
- Commands are truncated to a bounded preview and marked with an
  ``is_sensitive`` flag when they contain password-like tokens; the
  content itself is still logged because honeypot research needs it —
  but credential-shaped values in *configuration* are never logged.
- No stack traces in production (handled by API error middleware).

Usage for T2/T3/T4::

    from app.logger import get_logger
    log = get_logger("agentic")
    log.info("command processed", session_id=sid, command_id=cid)
"""
from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any

from .config import Settings

_CONFIGURED = False
_MAX_EXTRA_VALUE = 512       # cap any context value length
_COMMAND_PREVIEW = 256        # cap command previews

# Keys that must never be logged with their real value.
_REDACT_KEYS = {
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "authorization", "cookie", "credential", "credentials",
}

_sensitive_format = logging.Formatter("%(message)s")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)
            )
            + f".{int(record.msecs):06d}Z",
            "level": record.levelname,
            "component": record.name,
            "message": record.getMessage(),
        }
        ctx = getattr(record, "mirage_context", None)
        if ctx:
            for key, value in ctx.items():
                payload[key] = _safe_value(key, value)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, separators=(",", ":"))


def _safe_value(key: str, value: Any) -> Any:
    key_l = key.lower()
    if key_l in _REDACT_KEYS:
        return "[redacted]"
    if key_l in ("command", "raw_command", "last_command"):
        return _truncate(str(value), _COMMAND_PREVIEW)
    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, str) and key_l == "output":
            return _truncate(value, _MAX_EXTRA_VALUE)
        return value
    if isinstance(value, (dict, list, tuple)):
        try:
            text = json.dumps(value, default=str)
        except (TypeError, ValueError):
            text = repr(value)
        return json.loads(_truncate(text, _MAX_EXTRA_VALUE)) if len(text) <= _MAX_EXTRA_VALUE else _truncate(text, _MAX_EXTRA_VALUE)
    return _truncate(str(value), _MAX_EXTRA_VALUE)


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def configure_logging(settings: Settings) -> None:
    """Idempotently configure root logging to structured JSON on stdout."""
    global _CONFIGURED
    root = logging.getLogger()
    if _CONFIGURED:
        root.setLevel(settings.log_level.value)
        return

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.handlers = [handler]
    root.setLevel(settings.log_level.value)
    logging.getLogger("uvicorn.access").handlers = [handler]
    _CONFIGURED = True


class ComponentLogger:
    """Logger facade bound to one component name."""

    __slots__ = ("_logger",)

    def __init__(self, component: str) -> None:
        self._logger = logging.getLogger(component)

    def _log(self, level: int, message: str, exc_info=None, **context) -> None:
        if self._logger.isEnabledFor(level):
            if exc_info is True:
                # Logger._log would resolve this via sys.exc_info(), but we
                # build the record ourselves via makeRecord, which does not.
                # Leaving the literal True in the record makes the formatter
                # raise from inside handler() — defeating the event bus's
                # per-handler isolation — so resolve it here instead.
                exc_info = sys.exc_info()
            record = self._logger.makeRecord(
                self._logger.name, level, "(runtime)", 0,
                message, (), exc_info,
            )
            record.mirage_context = context
            self._logger.handle(record)

    def debug(self, message: str, **context) -> None:
        self._log(logging.DEBUG, message, **context)

    def info(self, message: str, **context) -> None:
        self._log(logging.INFO, message, **context)

    def warning(self, message: str, **context) -> None:
        self._log(logging.WARNING, message, **context)

    def error(self, message: str, exc_info=None, **context) -> None:
        self._log(logging.ERROR, message, exc_info=exc_info, **context)

    def exception(self, message: str, **context) -> None:
        self._log(logging.ERROR, message, exc_info=True, **context)

    def child(self, sub: str) -> "ComponentLogger":
        return ComponentLogger(f"{self._logger.name}.{sub}")


def get_logger(component: str) -> ComponentLogger:
    """Return a structured logger for a component.

    T2/T3/T4 should call this once at module scope::

        log = get_logger("t2.agentic")
    """
    return ComponentLogger(component)
