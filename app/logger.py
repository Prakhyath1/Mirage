"""Structured logging for Mirage.

Mirage logs to two places:
  - stdout/stderr via the standard `logging` module (operator console)
  - the SQLite `events`/`logs` tables via app.db (audit trail, dashboard feed)

This module only wraps the console side; db.log_event / db.log_command
remain the audit-trail API. Security events (honeytoken trips, containment
blocks) should always go through both.
"""

import logging
import sys

_mirage_logger = logging.getLogger("mirage")
_mirage_logger.setLevel(logging.INFO)

if not _mirage_logger.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s"
    ))
    _mirage_logger.addHandler(_handler)


def get_logger(name: str = "mirage") -> logging.Logger:
    """Return a namespaced child of the mirage logger."""
    if name == "mirage":
        return _mirage_logger
    return _mirage_logger.getChild(name)


def info(message: str) -> None:
    _mirage_logger.info(message)


def warning(message: str) -> None:
    _mirage_logger.warning(message)


def error(message: str) -> None:
    _mirage_logger.error(message)


def security_event(event_type: str, session_id: str, details: str) -> None:
    """Log a security event to the console. Callers must also db.log_event()
    so the event reaches the audit trail / dashboard."""
    _mirage_logger.warning("%s session=%s %s", event_type, session_id, details)
