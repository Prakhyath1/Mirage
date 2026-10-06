"""Storage layer tests: deterministic init, session/command/event
persistence round-trips, bounded blob sizes, indexes, health check."""
import sqlite3
import time

import pytest

from app.models import (
    CommandRequest,
    CommandResult,
    EventType,
    ResultType,
    SecurityEvent,
    Session,
    SessionStatus,
    Severity,
)
from app.storage.schema import SCHEMA_VERSION
from app.storage.database import _MAX_JSON_FIELD_BYTES, Database, Storage


@pytest.fixture()
async def storage(tmp_foundation_settings):
    s = Storage(tmp_foundation_settings)
    await s.initialize()
    yield s
    await s.close()


class TestInitialization:
    async def test_initialize_creates_all_tables(self, tmp_foundation_settings):
        s = Storage(tmp_foundation_settings)
        await s.initialize()
        rows = await s.database.execute_readall(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = {r["name"] for r in rows}
        assert {"sessions", "commands", "command_results", "events"} <= tables
        await s.close()

    async def test_reinit_is_deterministic_and_idempotent(self, storage):
        # Re-running schema init on an existing DB must not fail or lose data.
        storage.database._init_schema()
        s = Session.new()
        await storage.sessions.create(s)
        storage.database._init_schema()
        fetched = await storage.sessions.get(s.session_id)
        assert fetched is not None

    async def test_schema_version_stamped(self, storage):
        # schema_info is a (key, value) table; the version is stored in
        # the row keyed 'schema_version', not in a dedicated column.
        row = await storage.database.execute_readone(
            "SELECT value FROM schema_info WHERE key = 'schema_version'"
        )
        assert row is not None
        assert row["value"] == str(SCHEMA_VERSION)

    async def test_indexes_present(self, storage):
        rows = await storage.database.execute_readall(
            "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'"
        )
        names = {r["name"] for r in rows}
        assert len(names) >= 8  # every FK/lookup column is indexed


class TestSessionPersistence:
    async def test_create_get_roundtrip(self, storage):
        s = Session.new(username="root", source_address="10.0.0.9")
        await storage.sessions.create(s)
        fetched = await storage.sessions.get(s.session_id)
        assert fetched is not None
        assert fetched.username == "root"
        assert fetched.source_address == "10.0.0.9"
        assert fetched.status is SessionStatus.CREATED

    async def test_update_persists_transition(self, storage):
        s = Session.new()
        await storage.sessions.create(s)
        await storage.sessions.update(
            s.with_changes(status=SessionStatus.ACTIVE)
        )
        fetched = await storage.sessions.get(s.session_id)
        assert fetched.status is SessionStatus.ACTIVE

    async def test_count_by_status(self, storage):
        for _ in range(3):
            await storage.sessions.create(Session.new())
        s = Session.new()
        await storage.sessions.create(s)
        await storage.sessions.update(
            s.with_changes(status=SessionStatus.CLOSED)
        )
        assert await storage.sessions.count_by_status(SessionStatus.CREATED) == 3
        assert await storage.sessions.count_by_status(SessionStatus.CLOSED) == 1

    async def test_list_recent_limited(self, storage):
        for _ in range(7):
            await storage.sessions.create(Session.new())
            time.sleep(0.001)
        recent = await storage.sessions.list_recent(limit=5)
        assert len(recent) == 5

    async def test_summary_includes_command_count(self, storage):
        s = Session.new()
        await storage.sessions.create(s)
        req = CommandRequest.new(
            session_id=s.session_id, raw_command="whoami"
        )
        await storage.commands.create(req)
        summary = await storage.sessions.summary(s.session_id)
        assert summary is not None
        assert summary.command_count == 1
        assert summary.status is SessionStatus.CREATED


class TestCommandPersistence:
    async def test_command_roundtrip(self, storage):
        s = Session.new()
        await storage.sessions.create(s)
        req = CommandRequest.new(
            session_id=s.session_id, raw_command="uname -a"
        )
        await storage.commands.create(req)
        fetched = await storage.commands.get(req.command_id)
        assert fetched is not None
        assert fetched.raw_command == "uname -a"

    async def test_result_roundtrip(self, storage):
        s = Session.new()
        await storage.sessions.create(s)
        req = CommandRequest.new(
            session_id=s.session_id, raw_command="ls"
        )
        await storage.commands.create(req)
        result = CommandResult.new(
            command_id=req.command_id,
            stdout="file_a file_b\n",
            exit_code=0,
            result_type=ResultType.FALLBACK,
        )
        await storage.commands.save_result(result, s.session_id)
        fetched = await storage.commands.get_result(req.command_id)
        assert fetched is not None
        assert fetched.stdout == "file_a file_b\n"
        assert fetched.result_type is ResultType.FALLBACK

    async def test_list_for_session_returns_newest_first(self, storage):
        s = Session.new()
        await storage.sessions.create(s)
        for raw in ("whoami", "id", "pwd"):
            req = CommandRequest.new(
                session_id=s.session_id, raw_command=raw
            )
            await storage.commands.create(req)
            time.sleep(0.001)
        rows = await storage.commands.list_for_session(s.session_id)
        assert [r.raw_command for r in rows] == ["pwd", "id", "whoami"]
        assert await storage.commands.count_for_session(s.session_id) == 3


class TestEventPersistence:
    async def test_event_roundtrip(self, storage):
        s = Session.new()
        await storage.sessions.create(s)
        ev = SecurityEvent.new(
            session_id=s.session_id,
            event_type=EventType.COMMAND_SUBMITTED.value,
            severity=Severity.INFO,
            source="test",
            payload={"key": "value"},
        )
        await storage.events.save(ev)
        fetched = await storage.events.get(ev.event_id)
        assert fetched is not None
        assert fetched.event_type == "command.submitted"
        assert fetched.payload == {"key": "value"}

    async def test_list_for_session(self, storage):
        s = Session.new()
        await storage.sessions.create(s)
        for et in ("session.created", "command.submitted"):
            await storage.events.save(
                SecurityEvent.new(
                    session_id=s.session_id,
                    event_type=et,
                    severity=Severity.INFO,
                    source="test",
                )
            )
        events = await storage.events.list_for_session(s.session_id)
        assert len(events) == 2

    async def test_list_recent_limited(self, storage):
        s = Session.new()
        await storage.sessions.create(s)
        for i in range(5):
            await storage.events.save(
                SecurityEvent.new(
                    session_id=s.session_id,
                    event_type=EventType.COMMAND_SUBMITTED.value,
                    severity=Severity.INFO,
                    source="test",
                    payload={"i": i},
                )
            )
        recent = await storage.events.list_recent(limit=3)
        assert len(recent) == 3


class TestBoundedBlobSizes:
    async def test_oversized_event_payload_replaced_with_sentinel(self, storage):
        # JSON columns are hard-capped at 256 KiB: an oversized payload is
        # replaced by a small truncation sentinel, never an unbounded blob.
        s = Session.new()
        await storage.sessions.create(s)
        ev = SecurityEvent.new(
            session_id=s.session_id,
            event_type=EventType.COMMAND_SUBMITTED.value,
            severity=Severity.INFO,
            source="test",
            payload={"blob": "A" * (2 << 20)},
        )
        await storage.events.save(ev)
        fetched = await storage.events.get(ev.event_id)
        assert fetched is not None
        assert fetched.payload.get("truncated") is True
        assert fetched.payload.get("size", 0) > _MAX_JSON_FIELD_BYTES

    async def test_oversized_command_stdout_roundtrips_by_design(self, storage):
        # stdout is stored verbatim (uncapped by design — the simulated
        # fallback generator is trusted output); it must round-trip intact
        # so T4 dashboards and analysis see exactly what the session saw.
        s = Session.new()
        await storage.sessions.create(s)
        req = CommandRequest.new(
            session_id=s.session_id, raw_command="cat /dev/zero"
        )
        await storage.commands.create(req)
        result = CommandResult.new(
            command_id=req.command_id,
            stdout="A" * (2 << 20),
            exit_code=0,
        )
        await storage.commands.save_result(result, s.session_id)
        fetched = await storage.commands.get_result(req.command_id)
        assert fetched is not None
        assert len(fetched.stdout) == (2 << 20)

    async def test_normal_json_payload_roundtrips_uncapped(self, storage):
        s = Session.new()
        await storage.sessions.create(s)
        payload = {"keys": [f"k{i}" for i in range(100)], "n": 12345}
        ev = SecurityEvent.new(
            session_id=s.session_id,
            event_type=EventType.SECURITY_DECISION.value,
            severity=Severity.INFO,
            source="test",
            payload=payload,
        )
        await storage.events.save(ev)
        fetched = await storage.events.get(ev.event_id)
        assert fetched is not None
        assert fetched.payload == payload


class TestHealth:
    async def test_health_check_true_when_open(self, storage):
        assert await storage.health_check() is True

    async def test_health_check_false_after_close(self, storage):
        await storage.close()
        # A closed storage must not report healthy.
        assert await storage.health_check() is False
