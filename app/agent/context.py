"""Context builder: constructs the bounded ``AgentContext`` for a decision.

Sources (all bounded — never the whole DB or filesystem):
  * T1 session row (``db.get_or_create_session``) — cwd, threat state
  * T1 logs table via ``db.get_session_commands`` — recent history
  * persona engine — simulated identity (fallback environment state)
  * in-process session memory — agent observations for this process
  * T3 behavior signals (``behavior.calculate_score``-derived session row)
"""

from __future__ import annotations

from typing import List, Optional

from .config import AgentConfig, get_agent_config
from .memory import (
    MemoryStore,
    SessionMemory,
    get_memory_store,
    is_ephemeral_session,
)
from .models import (
    AgentContext,
    AgentMemoryEntry,
    BehaviorSignals,
    EnvironmentState,
    MemoryEntryKind,
    PersonaState,
    SimulatedUser,
    new_id,
)
from .persona import PersonaEngine
from .tools import ToolRegistry, get_tool_registry


class ContextBuilder:
    """Assembles the per-request agent context."""

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        persona_engine: Optional[PersonaEngine] = None,
        memory_store: Optional[MemoryStore] = None,
        tools: Optional[ToolRegistry] = None,
    ):
        self._config = config or get_agent_config()
        self._persona_engine = persona_engine or PersonaEngine(self._config)
        self._memory_store = memory_store or get_memory_store()
        self._tools = tools or get_tool_registry()

    # -- T1/T3 integration ---------------------------------------------------
    def _load_session(self, session_id: str) -> Optional[dict]:
        """Read T1's session row; returns None if the DB layer is unusable.

        Kept defensive: context construction must never crash the request
        path — the engine can decide with persona state alone.

        Ephemeral ids (session-less callers, e.g. T3 containment's legacy
        signature) never touch the DB here: reading would create a throwaway
        session row for a caller that has no persistent identity.
        """
        if is_ephemeral_session(session_id):
            return None
        try:
            from app import db

            return db.get_or_create_session(session_id)
        except Exception:
            return None

    def _load_recent_commands(self, session_id: str, limit: int) -> List[AgentMemoryEntry]:
        """Bounded recent history from T1's logs (oldest first)."""
        if is_ephemeral_session(session_id):
            return []  # no persistent identity -> no shared history to read
        try:
            from app import db

            rows = db.get_session_commands(session_id, limit=limit)
        except Exception:
            return []
        entries: List[AgentMemoryEntry] = []
        for row in reversed(rows):
            command = row.get("command") or ""
            if not command:
                continue
            entries.append(
                AgentMemoryEntry(kind=MemoryEntryKind.COMMAND, command=command)
            )
        return entries

    def _behavior_signals(
        self, session: Optional[dict], session_id: str, command: Optional[str] = None
    ) -> BehaviorSignals:
        """Derive T3-consumed behavior signals from T1's session row.

        T2 reads the threat state T3's ``behavior.update_session_threat``
        maintains; it never recomputes scores itself. Detected categories
        are likewise *consumed*, not invented: T3's own ``THREAT_KEYWORDS``
        table classifies the command text T2 has in hand.
        """
        if not session:
            return BehaviorSignals()
        return BehaviorSignals(
            risk_level=session.get("threat_level") or "Low",
            threat_score=int(session.get("threat_score") or 0),
            containment_active=bool(session.get("containment_active")),
            detected_categories=self._detected_categories(session_id, command),
        )

    def _detected_categories(
        self, session_id: str, command: Optional[str] = None
    ) -> List[str]:
        """Behavioral categories T3's keyword table matches for this command.

        T2 adds no keywords and computes no scores — it reads T3's
        authoritative ``THREAT_KEYWORDS`` table and reports which categories
        apply. Falls back to the session's most recent logged command when
        the current command text was not supplied to ``build()``.
        """
        text = command
        if not text:
            try:
                from app import db

                rows = db.get_session_commands(session_id, limit=1)
                text = rows[0].get("command") if rows else ""
            except Exception:
                return []
        if not text:
            return []
        try:
            from app import behavior  # T3's authoritative keyword table

            lowered = text.lower()
            return [
                keyword
                for keyword in behavior.THREAT_KEYWORDS
                if keyword in lowered
            ]
        except Exception:
            return []

    # -- public API ------------------------------------------------------------
    def build(
        self,
        session_id: str,
        command_id: Optional[str] = None,
        environment_state: Optional[EnvironmentState] = None,
        command: Optional[str] = None,
    ) -> AgentContext:
        session = self._load_session(session_id)
        persona: PersonaState = self._persona_engine.get_persona()

        cwd = (session or {}).get("cwd") or f"/home/{persona.username}"

        # Environment state: prefer T3-provided state; else persona fallback.
        if environment_state is not None:
            env = environment_state
        else:
            env = self._persona_engine.build_environment_state(cwd=cwd)
            # keep cwd authoritative from the session row
            env = env.model_copy(update={"cwd": cwd})

        user: SimulatedUser = self._persona_engine.build_user()

        # Bounded memory: DB history first, then in-process observations.
        # Ephemeral ids get a one-call memory — nothing is shared with any
        # other caller, and nothing persists after the decision returns.
        history_limit = max(1, self._config.agent_max_memory // 2)
        recent: List[AgentMemoryEntry] = self._load_recent_commands(
            session_id, history_limit
        )
        if is_ephemeral_session(session_id):
            memory: SessionMemory = self._memory_store.get_ephemeral(session_id)
        else:
            memory = self._memory_store.get(session_id)
        recent.extend(memory.recent(limit=self._config.agent_max_memory - len(recent)))
        recent = recent[-self._config.agent_max_memory :]

        return AgentContext(
            session_id=session_id,
            command_id=command_id or new_id("cmd"),
            current_working_directory=cwd,
            user_information=user,
            recent_commands=recent,
            environment_state=env,
            behavior_signals=self._behavior_signals(session, session_id, command),
            persona=persona,
            available_simulated_tools=self._tools.names(),
            metadata={
                "history_source": "t1_logs+memory",
                "environment_state_source": env.source,
            },
        )
