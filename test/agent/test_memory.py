"""Memory tests: bounding, session isolation, eviction, extension point."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from test.agent._fixtures import AgentTestCase  # noqa: E402


class SessionMemoryTest(AgentTestCase):
    def _memory(self, max_entries: int = 5, max_chars: int = 200):
        from app.agent.config import AgentConfig
        from app.agent.memory import SessionMemory

        return SessionMemory(
            session_id="s",
            config=AgentConfig(
                agent_max_memory=max_entries, agent_max_response=max_chars
            ),
        )

    def test_record_and_recency_order(self):
        from app.agent.models import MemoryEntryKind

        mem = self._memory()
        mem.record_command("one")
        mem.record_output("out-one")
        entries = mem.recent()
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].kind, MemoryEntryKind.COMMAND)
        self.assertEqual(entries[0].command, "one")
        self.assertEqual(entries[1].output_summary, "out-one")

    def test_entry_count_is_bounded(self):
        mem = self._memory(max_entries=3)
        for i in range(10):
            mem.record_command(f"cmd-{i}")
        entries = mem.recent()
        self.assertEqual(len(entries), 3)
        # most recent kept, oldest evicted
        self.assertEqual(entries[-1].command, "cmd-9")
        self.assertEqual(entries[0].command, "cmd-7")

    def test_entry_chars_are_bounded(self):
        # SessionMemory floors max_entry_chars at 200 (max(200, config)), so
        # exercise the bound at its minimum viable setting.
        mem = self._memory(max_entries=5, max_chars=200)
        mem.record_command("x" * 500)
        stored = mem.recent()[0].command
        self.assertLessEqual(len(stored), 200 + len("…[truncated]"))
        self.assertTrue(stored.endswith("…[truncated]"))

    def test_empty_records_are_ignored(self):
        mem = self._memory()
        mem.record_command("")
        mem.record_output("")
        mem.record_fact(None)
        self.assertEqual(len(mem.recent()), 0)

    def test_recent_limit_selects_tail(self):
        mem = self._memory(max_entries=10)
        for i in range(5):
            mem.record_command(f"c{i}")
        tail = mem.recent(limit=2)
        self.assertEqual([e.command for e in tail], ["c3", "c4"])

    def test_retrieve_is_extension_point_with_same_contract(self):
        mem = self._memory()
        mem.record_command("known-command")
        # retrieve() must behave like recent(): oldest-first bounded window
        self.assertEqual(mem.retrieve(), mem.recent())
        self.assertEqual(mem.retrieve(query="anything"), mem.recent())


class MemoryStoreTest(AgentTestCase):
    def test_sessions_are_isolated(self):
        from app.agent.memory import MemoryStore

        store = MemoryStore()
        store.get("a").record_command("in-a")
        store.get("b").record_command("in-b")
        self.assertEqual(len(store.get("a")), 1)
        self.assertEqual(store.get("a").recent()[0].command, "in-a")
        self.assertEqual(len(store.get("b")), 1)

    def test_eviction_when_sessions_exceed_cap(self):
        from app.agent.memory import MemoryStore

        store = MemoryStore()
        cap = MemoryStore.MAX_SESSIONS
        for i in range(cap):
            store.get(f"s{i}").record_command(f"c{i}")
        # one more session evicts the oldest (s0)
        store.get("s_new").record_command("c_new")
        self.assertEqual(len(store.get("s0")), 0)
        self.assertEqual(store.get("s_new").recent()[0].command, "c_new")

    def test_drop_removes_session_memory(self):
        from app.agent.memory import MemoryStore

        store = MemoryStore()
        store.get("a").record_command("x")
        store.drop("a")
        self.assertEqual(len(store.get("a")), 0)  # recreated fresh

    def test_global_store_is_singleton_with_reset(self):
        from app.agent.memory import get_memory_store, reset_memory_store

        reset_memory_store()
        s1 = get_memory_store()
        s2 = get_memory_store()
        self.assertIs(s1, s2)
        reset_memory_store()
        self.assertIsNot(get_memory_store(), s1)

    def test_engine_records_command_and_output(self):
        from app.agent.engine import AgentEngine
        from app.agent.memory import MemoryStore
        from app.agent.providers import MockProvider
        import asyncio

        store = MemoryStore()
        engine = AgentEngine(
            memory_store=store,
            provider=MockProvider(model="m", responses=[
                {"action": "RESPOND", "response": "simulated"}
            ]),
            emit_events=False,
        )
        asyncio.run(engine.decide("mem-session", "ps aux"))
        entries = store.get("mem-session").recent()
        kinds = [e.kind.value for e in entries]
        self.assertIn("COMMAND", kinds)
        self.assertIn("OUTPUT", kinds)


if __name__ == "__main__":
    unittest.main()
