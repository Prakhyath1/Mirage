"""T1 integration tests: the production path exercised end-to-end.

``router.process_command()`` is T1's real entry point — it routes to T3's
VFS for filesystem commands and to T2's agent facade for everything else,
then applies T3 behavior scoring and T1 logging/events. These tests run
that actual code against an isolated temporary database and the mock
provider, never the production DB and never a live Ollama.

The mock provider is wired through the engine the facade uses, via the
same singleton reset the rest of the suite applies, so the production
import path (``app.llm_engine`` -> ``app.agent``) is what executes.
"""

from __future__ import annotations

import unittest

from test.agent._fixtures import AgentTestCase

import app.db as _db


class _RouterHarness(AgentTestCase):
    """Common harness: fresh isolated DB + scripted agent engine."""

    def setUp(self):
        super().setUp()
        # Point the facade's engine singleton at the mock provider with a
        # repeatable response. Production imports happen lazily inside the
        # facade, so rebuilding the singleton here is enough.
        from app.agent import get_agent_engine
        from app.agent.engine import AgentEngine
        from app.agent.providers import MockProvider

        self.captured_prompts = []

        def on_prompt(prompt):
            self.captured_prompts.append(prompt)

        engine = AgentEngine(
            provider=MockProvider(
                model="mock",
                responses=[
                    {
                        "action": "RESPOND",
                        "response": "root       1  0.0  0.1  167  12 ? Ss  09:00   0:01 init",
                        "confidence": 0.9,
                        "reason": "test",
                        "deception_category": "none",
                        "simulated_effect": "NONE",
                        "latency_profile": "FAST",
                        "security_flags": [],
                    }
                ],
                on_prompt=on_prompt,
            ),
            emit_events=True,
        )
        import app.agent as agent_pkg

        agent_pkg._engine = engine

    def tearDown(self):
        import app.agent as agent_pkg

        agent_pkg._engine = None
        super().tearDown()


class RouterT1IntegrationTest(_RouterHarness):
    """§10: command -> router -> T2 -> decision -> response -> logging/events."""

    def test_llm_command_reaches_agent_and_returns_output(self):
        from app import router

        _db.get_or_create_session("t1-sess")
        output = router.process_command("t1-sess", "ps aux")
        self.assertIn("init", output)
        # the command reached the LLM path (not VFS, not containment)
        self.assertEqual(len(self.captured_prompts), 1)
        self.assertIn("ps aux", self.captured_prompts[0])

    def test_vfs_command_bypasses_llm(self):
        from app import router

        _db.get_or_create_session("t1-vfs")
        router.process_command("t1-vfs", "ls")
        # VFS-owned: the agent engine's LLM is never consulted
        self.assertEqual(self.captured_prompts, [])

    def test_agent_event_created_for_llm_command(self):
        from app import router

        _db.get_or_create_session("t1-evt")
        router.process_command("t1-evt", "ps aux")
        events = self.read_events("t1-evt")
        agent_events = [e for e in events if e["event_type"].startswith("AGENT_")]
        self.assertTrue(agent_events, "expected at least one AGENT_* event")

    def test_command_is_logged_with_source(self):
        from app import router

        _db.get_or_create_session("t1-log")
        router.process_command("t1-log", "ps aux")
        logs = _db.get_session_commands("t1-log")
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["command"], "ps aux")
        self.assertEqual(logs[0]["source"], "llm")

    def test_vfs_command_logged_with_vfs_source(self):
        from app import router

        _db.get_or_create_session("t1-logvfs")
        router.process_command("t1-logvfs", "echo hello")
        logs = _db.get_session_commands("t1-logvfs")
        self.assertEqual(logs[0]["source"], "vfs")
        self.assertEqual(logs[0]["output"], "hello")

    def test_production_database_not_modified(self):
        """The suite's isolated DB is the only thing these tests touch."""
        from app import router

        # The fixture already redirected db.DB_PATH; assert the redirect
        # held for the whole call path.
        from test.agent._fixtures import TEST_DB_PATH

        self.assertEqual(_db.DB_PATH, str(TEST_DB_PATH))
        _db.get_or_create_session("t1-prod")
        router.process_command("t1-prod", "ps aux")
        self.assertEqual(_db.DB_PATH, str(TEST_DB_PATH))

    def test_engine_failure_falls_back_safely(self):
        from app import router
        from app.agent.engine import AgentEngine
        from app.agent.providers import MockProvider

        # Swap the engine for one whose provider is down: the facade's
        # contract is a safe response, never an exception to T1.
        engine = AgentEngine(
            provider=MockProvider(
                model="mock",
                responses=[__import__("app.agent.providers.base", fromlist=["x"]).ProviderUnavailableError("down", "mock")]
            ),
            emit_events=True,
        )
        import app.agent as agent_pkg

        agent_pkg._engine = engine
        _db.get_or_create_session("t1-fail")
        output = router.process_command("t1-fail", "ps aux")
        self.assertIsInstance(output, str)
        self.assertTrue(len(output) > 0)

    def test_identity_command_answered_from_persona(self):
        from app import router

        _db.get_or_create_session("t1-ident")
        output = router.process_command("t1-ident", "whoami")
        self.assertEqual(output, "admin")


class FacadeSessionIsolationTest(_RouterHarness):
    """§4: named-session memory isolation, exercised through the facade."""

    def test_session_a_memory_differs_from_session_b(self):
        from app import llm_engine

        _db.get_or_create_session("sessA")
        _db.get_or_create_session("sessB")

        # Two LLM-owned commands, one per session
        llm_engine.generate_response("ps aux", "/home/admin", session_id="sessA")
        llm_engine.generate_response("whoami", "/home/admin", session_id="sessA")
        llm_engine.generate_response("ps aux", "/home/admin", session_id="sessB")

        from app.agent.memory import get_memory_store

        store = get_memory_store()
        a_entries = store.get("sessA").recent()
        b_entries = store.get("sessB").recent()
        self.assertGreater(len(a_entries), 0)
        self.assertGreater(len(b_entries), 0)
        # sessA saw two commands; sessB saw one — memory is per-session
        self.assertGreater(len(a_entries), len(b_entries))
        b_commands = [e.command for e in b_entries]
        self.assertNotIn("whoami", b_commands)

    def test_sessionless_call_creates_no_persistent_session(self):
        from app import llm_engine

        llm_engine.generate_response("whoami", "/home/admin")
        self.assertIsNone(_db.get_session_by_id(""))
        # and no session row was created for any ephemeral id
        conn = _db.get_connection()
        try:
            count = conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE session_id LIKE '\\_ephemeral%' ESCAPE '\\'"
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(count, 0)

    def test_named_session_retains_context_across_calls(self):
        from app import llm_engine

        _db.get_or_create_session("sess-keep")
        first = llm_engine.generate_response("ps aux", "/home/admin", session_id="sess-keep")
        second = llm_engine.generate_response("whoami", "/home/admin", session_id="sess-keep")
        # deterministic identity path still works and session persists
        self.assertEqual(second, "admin")
        self.assertIsInstance(first, str)
        # the session row survives (memory + threat state have a home)
        row = _db.get_session_by_id("sess-keep")
        self.assertIsNotNone(row)

    def test_sessionless_calls_do_not_share_context(self):
        from app import llm_engine
        from app.agent.memory import get_memory_store

        llm_engine.generate_response("ps aux", "/home/admin")  # call 1
        llm_engine.generate_response("whoami", "/home/admin")  # call 2
        store = get_memory_store()
        # no persistent memory rows were kept under any ephemeral id
        conn = _db.get_connection()
        try:
            n = conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE session_id LIKE '\\_ephemeral%' ESCAPE '\\'"
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(n, 0)
        # and the in-memory store cached nothing for ephemeral ids
        self.assertFalse(
            any(k.startswith("_ephemeral") for k in getattr(store, "_memories", {}))
        )


if __name__ == "__main__":
    unittest.main()
