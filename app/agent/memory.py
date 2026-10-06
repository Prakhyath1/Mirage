"""Bounded session memory for the deception agent.

The agent must be session-aware without shipping the whole conversation to
the LLM. This implementation is deterministic, in-process, and bounded by
both entry count and total characters. Persistence beyond the window is not
needed because T1 already stores every command in the ``logs`` table — the
engine rebuilds recent history from ``db.get_session_commands`` (bounded) and
augments it with agent observations for the current process.

An extension point for future semantic retrieval is exposed via
``retrieve()``; the initial implementation is a deterministic recency window.
"""

from __future__ import annotations

from collections import deque
from typing import Deque, Iterable, List, Optional

from .config import AgentConfig, get_agent_config
from .models import AgentMemoryEntry, MemoryEntryKind

# Tag marking an engine-visible id as a per-call ephemeral identity (no
# persistent session, no shared memory). T2-internal convention.
EPHEMERAL_MEMORY_PREFIX = "_ephemeral_"


def is_ephemeral_session(session_id: Optional[str]) -> bool:
    """True when an id names an ephemeral (session-less) caller."""
    return bool(session_id) and str(session_id).startswith(EPHEMERAL_MEMORY_PREFIX)


class SessionMemory:
    """A bounded, deterministic memory window for one session."""

    def __init__(self, session_id: str, config: Optional[AgentConfig] = None):
        self.session_id = session_id
        self._config = config or get_agent_config()
        max_entries = max(1, int(self._config.agent_max_memory))
        self._entries: Deque[AgentMemoryEntry] = deque(maxlen=max_entries)
        self._max_entry_chars = max(200, self._config.agent_max_response)

    # -- writes -------------------------------------------------------------
    def record(self, entry: AgentMemoryEntry) -> None:
        """Add an entry, enforcing the per-entry character bound."""
        bounded = entry.model_copy(update={
            "command": self._bound(entry.command),
            "output_summary": self._bound(entry.output_summary),
            "fact": self._bound(entry.fact),
        })
        self._entries.append(bounded)

    def record_command(self, command: str) -> None:
        if command:
            self.record(AgentMemoryEntry(kind=MemoryEntryKind.COMMAND, command=command))

    def record_output(self, output: str) -> None:
        if output:
            self.record(
                AgentMemoryEntry(kind=MemoryEntryKind.OUTPUT, output_summary=output)
            )

    def record_fact(self, fact: str) -> None:
        if fact:
            self.record(AgentMemoryEntry(kind=MemoryEntryKind.FACT, fact=fact))

    def record_observation(self, observation: str) -> None:
        if observation:
            self.record(
                AgentMemoryEntry(kind=MemoryEntryKind.OBSERVATION, fact=observation)
            )

    def record_security_event(self, description: str) -> None:
        if description:
            self.record(
                AgentMemoryEntry(kind=MemoryEntryKind.SECURITY_EVENT, fact=description)
            )

    def _bound(self, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        if len(value) <= self._max_entry_chars:
            return value
        return value[: self._max_entry_chars] + "…[truncated]"

    # -- reads --------------------------------------------------------------
    def recent(self, limit: Optional[int] = None) -> List[AgentMemoryEntry]:
        """Most recent entries in chronological order (oldest first)."""
        entries = list(self._entries)
        if limit is None or limit >= len(entries):
            return entries
        return entries[-limit:]

    def retrieve(self, query: str = "", limit: Optional[int] = None) -> List[AgentMemoryEntry]:
        """Retrieval extension point.

        Current implementation: deterministic recency window. A future
        semantic-retrieval implementation can replace this method without
        changing any caller (same signature, same return contract).
        """
        return self.recent(limit)

    def seed_history(self, entries: Iterable[AgentMemoryEntry]) -> None:
        """Pre-load bounded history (e.g. from T1's logs table), oldest first."""
        for entry in entries:
            self.record(entry)

    def summary_lines(self, limit: Optional[int] = None) -> List[str]:
        """Render memory as compact prompt lines (bounded, deterministic)."""
        lines = []
        for entry in self.recent(limit):
            text = entry.summary().strip()
            if not text:
                continue
            if entry.kind is MemoryEntryKind.COMMAND:
                lines.append(f"$ {text}")
            elif entry.kind is MemoryEntryKind.OUTPUT:
                lines.append(f"  -> {text}")
            elif entry.kind is MemoryEntryKind.SECURITY_EVENT:
                lines.append(f"  [security] {text}")
            else:
                lines.append(f"  [note] {text}")
        return lines

    # -- introspection -------------------------------------------------------
    def __len__(self) -> int:
        return len(self._entries)

    def total_chars(self) -> int:
        return sum(len(e.summary()) for e in self._entries)


class MemoryStore:
    """Process-wide registry of per-session memories (bounded by sessions).

    Sessions are few and short-lived in a honeypot context; the store is
    capped to keep memory usage deterministic (oldest sessions evicted).
    """

    MAX_SESSIONS = 256

    def __init__(self, config: Optional[AgentConfig] = None):
        self._config = config or get_agent_config()
        self._sessions: "deque[str]" = deque(maxlen=self.MAX_SESSIONS)
        self._memories: dict = {}

    def get(self, session_id: str) -> SessionMemory:
        if session_id not in self._memories:
            if len(self._sessions) == self._sessions.maxlen:
                evict = self._sessions[0]
                self._memories.pop(evict, None)
            self._sessions.append(session_id)
            self._memories[session_id] = SessionMemory(session_id, self._config)
        return self._memories[session_id]

    def get_ephemeral(self, session_id: str) -> SessionMemory:
        """A one-call memory: never cached, never shared with any other caller.

        Ephemeral ids (``EPHEMERAL_MEMORY_PREFIX``-tagged) must not enter the
        store — caching them would leak one containment caller's context into
        another's prompt. A fresh, bounded ``SessionMemory`` is built per call.
        """
        return SessionMemory(session_id, self._config)

    def drop(self, session_id: str) -> None:
        self._memories.pop(session_id, None)


_store: Optional[MemoryStore] = None


def get_memory_store() -> MemoryStore:
    global _store
    if _store is None:
        _store = MemoryStore()
    return _store


def reset_memory_store() -> None:
    """Test helper."""
    global _store
    _store = None
