"""MIRAGE runtime foundation (T1).

Exposes the public runtime surface: the session manager, the command
dispatcher (with the safe fallback handler), the runtime service that
wires the full pipeline, and the SSH adapter interface used by a future
SSH transport.
"""
from __future__ import annotations

from .dispatcher import CommandDispatcher, CommandHandler, SafeFallbackHandler
from .service import MirageRuntime
from .session_manager import SessionManager, SessionStateError
from .ssh import SSHAdapterBase, SSHTransportObserver

__all__ = [
    "CommandDispatcher",
    "CommandHandler",
    "SafeFallbackHandler",
    "MirageRuntime",
    "SessionManager",
    "SessionStateError",
    "SSHAdapterBase",
    "SSHTransportObserver",
]
