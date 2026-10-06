"""Agent tool abstraction: a strict, read-only allowlist.

"Tools" here are typed interfaces over MIRAGE's own simulated data (VFS rows
in T1's DB, session history). They never execute anything on the host, and
the LLM cannot invent tool names — the registry resolves a fixed allowlist
and unknown names are rejected by construction.

T3 owns the authoritative VFS; these interfaces read only what T1's DB
already stores (``virtual_files`` rows that T3's vfs.py creates).
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel, Field

from ..models import AgentMemoryEntry, MemoryEntryKind


class AgentTool(BaseModel):
    """Registration record for a simulated (read-only) tool."""

    name: str
    description: str
    handler: Any = Field(exclude=True)  # callable; excluded from serialization
    read_only: bool = True

    model_config = {"arbitrary_types_allowed": True}


class ToolRegistry:
    """Fixed allowlist of tools the agent may reference or invoke."""

    def __init__(self) -> None:
        self._tools: Dict[str, AgentTool] = {}

    def register(self, tool: AgentTool) -> None:
        if not tool.read_only:
            raise ValueError(f"tool {tool.name!r} must be read-only")
        if tool.name in self._tools:
            raise ValueError(f"tool {tool.name!r} already registered")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[AgentTool]:
        return self._tools.get(name)

    def has(self, name: str) -> bool:
        return name in self._tools

    def names(self) -> List[str]:
        return sorted(self._tools)

    def descriptions(self) -> List[str]:
        return [
            f"{name}: {self._tools[name].description}" for name in self.names()
        ]

    def invoke(self, name: str, session_id: str, **kwargs) -> Any:
        """Invoke an allowlisted tool. Unknown names raise KeyError."""
        tool = self._tools.get(name)
        if tool is None:
            raise KeyError(f"unknown tool: {name!r}")
        if not tool.read_only:
            raise PermissionError(f"tool {name!r} is not invocable")
        return tool.handler(session_id, **kwargs)


def build_default_registry() -> ToolRegistry:
    """The simulated tool allowlist.

    Handlers read MIRAGE's own simulated data only. They are intentionally
    plain functions so they can be swapped for T3-provided implementations
    via ``register`` without touching agent logic.
    """

    def virtual_file_read(session_id: str, path: str = "") -> Optional[str]:
        """Read a simulated file from T1's virtual_files table (T3 data)."""
        if not path:
            return None
        from app import db  # late import: keeps the agent package importable standalone

        row = db.get_virtual_file(session_id, path)
        if not row:
            return None
        return row.get("content")

    def session_history_lookup(session_id: str, limit: int = 10) -> List[AgentMemoryEntry]:
        """Bounded recent command history from T1's logs table."""
        from app import db

        rows = db.get_session_commands(session_id, limit=max(1, min(int(limit), 50)))
        entries = []
        for row in reversed(rows):  # oldest first
            entries.append(
                AgentMemoryEntry(
                    kind=MemoryEntryKind.COMMAND,
                    command=row.get("command", ""),
                )
            )
        return entries

    def environment_state_lookup(session_id: str) -> Dict[str, Any]:
        """Simulated environment summary (persona-derived fallback).

        T3 will provide authoritative state; until then this returns the
        persona-driven environment without touching any real host API.
        """
        from ..persona import PersonaEngine

        env = PersonaEngine().build_environment_state()
        return env.model_dump()

    registry = ToolRegistry()
    registry.register(
        AgentTool(
            name="virtual_file_read",
            description="read a simulated file from the virtual filesystem",
            handler=virtual_file_read,
        )
    )
    registry.register(
        AgentTool(
            name="session_history_lookup",
            description="retrieve bounded recent command history for the session",
            handler=session_history_lookup,
        )
    )
    registry.register(
        AgentTool(
            name="environment_state_lookup",
            description="retrieve the simulated environment summary",
            handler=environment_state_lookup,
        )
    )
    return registry


_registry: Optional[ToolRegistry] = None


def get_tool_registry() -> ToolRegistry:
    global _registry
    if _registry is None:
        _registry = build_default_registry()
    return _registry


def reset_tool_registry() -> None:
    """Test helper: rebuild registry (also clears test-registered tools)."""
    global _registry
    _registry = None


__all__ = ["AgentTool", "ToolRegistry", "build_default_registry", "get_tool_registry"]
