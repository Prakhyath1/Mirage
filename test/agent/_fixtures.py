"""Shared fixtures for the T2 agent test suite.

Everything here is offline: no Ollama, no network, no real-host introspection.
The test DB is a throwaway SQLite file so tests never touch production data.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# Isolate from the developer's environment before app modules read it.
_TEST_ENV = {
    "LLM_PROVIDER": "mock",
    "MIRAGE_PERSONA_HOSTNAME": "web-prod-01",
    "MIRAGE_PERSONA_ROLE": "nginx web application server",
    "MIRAGE_PERSONA_USERNAME": "admin",
    "MIRAGE_PERSONA_UID": "1000",
}
for key, value in _TEST_ENV.items():
    os.environ.setdefault(key, value)

import app.db as _db  # noqa: E402  (needs the env vars above first)
from app.agent.models import (  # noqa: E402
    AgentContext,
    AgentMemoryEntry,
    BehaviorSignals,
    EnvironmentState,
    MemoryEntryKind,
    PersonaState,
    SimulatedUser,
)

# Throwaway DB per test: db.DB_PATH is a module global read at every call,
# so redirecting it here isolates tests from real data.
TEST_DB_DIR = Path(__file__).resolve().parent / "_test_data"
TEST_DB_DIR.mkdir(parents=True, exist_ok=True)
TEST_DB_PATH = TEST_DB_DIR / "agent_test.db"


class AgentTestCase(unittest.TestCase):
    """Base class: fresh, isolated state for every test.

    * throwaway SQLite DB (db.DB_PATH redirected)
    * fresh process-wide singletons (config, memory store, tool registry)
    * deterministic persona env vars
    """

    _env_backup: dict = {}

    @classmethod
    def setUpClass(cls):
        cls._env_backup = {k: os.environ.get(k) for k in _TEST_ENV}
        for key, value in _TEST_ENV.items():
            os.environ[key] = value
        cls._reset_singletons()

    @classmethod
    def tearDownClass(cls):
        for key, old in cls._env_backup.items():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old
        cls._reset_singletons()

    @classmethod
    def _reset_singletons(cls):
        from app.agent.config import reset_agent_config
        from app.agent.memory import reset_memory_store
        from app.agent.tools import reset_tool_registry

        reset_agent_config()
        reset_memory_store()
        reset_tool_registry()

    def setUp(self):
        # Fresh DB file per test: no cross-test state leakage.
        _db.DB_PATH = str(TEST_DB_PATH)
        if TEST_DB_PATH.exists():
            TEST_DB_PATH.unlink()
        _db.init_db()

    def read_events(self, session_id: str):
        """Read raw event rows for assertions (db has no get_events API)."""
        conn = _db.get_connection()
        try:
            rows = conn.execute(
                "SELECT event_type, details FROM events "
                "WHERE session_id = ? ORDER BY timestamp",
                (session_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def _test_persona() -> PersonaState:
    return PersonaState(
        hostname="web-prod-01",
        distribution="Ubuntu 22.04.3 LTS",
        kernel="5.15.0-91-generic",
        arch="x86_64",
        username="admin",
        uid=1000,
        gid=1000,
        home="/home/admin",
        shell="/bin/bash",
        system_role="nginx web application server",
        organization="Acme Corp",
    )


def make_context(command: str = "", session_id: str = "sess_test") -> AgentContext:
    """A canonical AgentContext for prompt/guardrail/engine tests.

    Deterministic and persona-consistent with the environment set above:
    host web-prod-01, user admin, cwd /home/admin.
    """
    env = EnvironmentState(
        hostname="web-prod-01",
        os_name="Ubuntu 22.04.3 LTS",
        kernel="5.15.0-91-generic",
        arch="x86_64",
        user="admin",
        cwd="/home/admin",
        home="/home/admin",
        services=["ssh", "cron", "nginx"],
        processes=["root 1 0.0 0.1 /sbin/init"],
        interfaces=["eth0: 10.0.20.31/24"],
        installed_packages=["bash", "openssh-server"],
        source="fallback_persona",
    )
    history = [
        AgentMemoryEntry(kind=MemoryEntryKind.COMMAND, command="whoami"),
        AgentMemoryEntry(kind=MemoryEntryKind.OUTPUT, output_summary="admin"),
    ]
    return AgentContext(
        session_id=session_id,
        command_id="cmd_test",
        current_working_directory="/home/admin",
        user_information=SimulatedUser(
            username="admin", uid=1000, gid=1000,
            home="/home/admin", shell="/bin/bash",
        ),
        recent_commands=history,
        environment_state=env,
        behavior_signals=BehaviorSignals(),
        persona=_test_persona(),
        available_simulated_tools=["virtual_file_read", "session_history_lookup"],
    )
