"""Command pipeline tests: registration/claims, LIFO precedence,
fallback behaviour, intake validation, handler error isolation.

The safety invariant under test throughout: no handler, fallback, or
dispatcher path ever executes attacker input on the host.
"""
import pytest

from app.events.bus import EventBus
from app.models import (
    CommandRequest,
    CommandResult,
    ResultType,
    Session,
    SessionStatus,
)
from app.runtime.dispatcher import CommandDispatcher
from app.storage.database import Storage


class StubHandler:
    """Minimal CommandHandler used to exercise dispatcher logic."""

    def __init__(self, name, stdout="handled", claims_all=False, claims=None,
                 raises=False, returns_none=False):
        self.name = name
        self._stdout = stdout
        self._claims_all = claims_all
        self._claims = claims or set()
        self._raises = raises
        self._returns_none = returns_none
        self.seen: list[CommandRequest] = []

    def claims(self, request: CommandRequest) -> bool:
        if self._claims_all:
            return True
        first = request.raw_command.split(" ", 1)[0]
        return first in self._claims

    async def handle(self, request: CommandRequest) -> CommandResult:
        self.seen.append(request)
        if self._raises:
            raise RuntimeError(f"{self.name} exploded")
        if self._returns_none:
            return None  # type: ignore[return-value]
        return CommandResult.new(
            command_id=request.command_id,
            stdout=self._stdout,
            result_type=ResultType.VFS,
            metadata={"handler": self.name},
        )


@pytest.fixture()
def session():
    return Session.new().with_changes(status=SessionStatus.ACTIVE)


@pytest.fixture()
async def pipeline(session, tmp_foundation_settings):
    # The dispatcher persists command intake before running handlers, and
    # the schema enforces commands.session_id -> sessions, so the session
    # row must exist first. Persist it here so every dispatch test is valid.
    storage = Storage(tmp_foundation_settings)
    await storage.initialize()
    await storage.sessions.create(session)
    bus = EventBus()
    yield CommandDispatcher(storage, bus, tmp_foundation_settings), storage, session
    await storage.close()


def _req(session_id, raw):
    return CommandRequest.new(session_id=session_id, raw_command=raw)


class TestRegistration:
    async def test_register_and_unregister(self, pipeline):
        dispatcher, _, _ = pipeline
        h = StubHandler("h1")
        dispatcher.register(h)
        assert dispatcher.registered_handlers() == ["h1"]
        dispatcher.unregister("h1")
        assert dispatcher.registered_handlers() == []

    async def test_lifo_registration_precedence(self, pipeline):
        dispatcher, _, session = pipeline
        first = StubHandler("first", stdout="from-first", claims_all=True)
        second = StubHandler("second", stdout="from-second", claims_all=True)
        dispatcher.register(first)
        dispatcher.register(second)
        result = await dispatcher.dispatch(_req(session.session_id, "ls"), session)
        assert "from-second" in result.stdout
        assert result.metadata["handler"] == "second"
        assert first.seen == []  # later registration wins, earlier never runs

    async def test_claims_gates_handler_invocation(self, pipeline):
        dispatcher, _, session = pipeline
        h = StubHandler("claimer", claims={"whoami"})
        dispatcher.register(h)
        await dispatcher.dispatch(_req(session.session_id, "whoami"), session)
        await dispatcher.dispatch(_req(session.session_id, "uname"), session)
        assert [r.raw_command for r in h.seen] == ["whoami"]


class TestFallback:
    async def test_unclaimed_command_falls_back(self, pipeline):
        dispatcher, _, session = pipeline
        result = await dispatcher.dispatch(
            _req(session.session_id, "whoami"), session
        )
        assert result.result_type is ResultType.FALLBACK
        assert result.metadata["simulated"] is True
        assert "host execution" in result.metadata["note"]

    async def test_fallback_known_hint(self, pipeline):
        dispatcher, _, session = pipeline
        result = await dispatcher.dispatch(
            _req(session.session_id, "whoami"), session
        )
        assert result.stdout == "ubuntu\n"
        assert result.exit_code == 0

    async def test_fallback_prefix_match(self, pipeline):
        dispatcher, _, session = pipeline
        result = await dispatcher.dispatch(
            _req(session.session_id, "uname -a"), session
        )
        assert "Linux mirage-host" in result.stdout

    async def test_fallback_unknown_command(self, pipeline):
        dispatcher, _, session = pipeline
        result = await dispatcher.dispatch(
            _req(session.session_id, "zzz_unknown_cmd"), session
        )
        assert result.exit_code == 127
        assert "command not found" in result.stdout

    async def test_fallback_never_executes(self, pipeline):
        """The whole point: dangerous-looking input is data, not code."""
        dispatcher, _, session = pipeline
        evil = "rm -rf / --no-preserve-root"
        result = await dispatcher.dispatch(_req(session.session_id, evil), session)
        assert result.result_type is ResultType.FALLBACK
        assert "rm" not in result.stdout or "command not found" in result.stdout


class TestErrorIsolation:
    async def test_raising_handler_falls_through_to_next(self, pipeline):
        dispatcher, _, session = pipeline
        bad = StubHandler("bad", claims_all=True, raises=True)
        good = StubHandler("good", stdout="rescued", claims_all=True)
        dispatcher.register(bad)
        dispatcher.register(good)
        result = await dispatcher.dispatch(_req(session.session_id, "id"), session)
        assert result.metadata["handler"] == "good"

    async def test_all_handlers_raising_reaches_fallback(self, pipeline):
        dispatcher, _, session = pipeline
        bad = StubHandler("bad", claims_all=True, raises=True)
        dispatcher.register(bad)
        result = await dispatcher.dispatch(_req(session.session_id, "ls"), session)
        assert result.result_type is ResultType.FALLBACK

    async def test_handler_returning_none_falls_through(self, pipeline):
        dispatcher, _, session = pipeline
        none_h = StubHandler("none", claims_all=True, returns_none=True)
        good = StubHandler("good", stdout="rescued", claims_all=True)
        dispatcher.register(none_h)
        dispatcher.register(good)
        result = await dispatcher.dispatch(_req(session.session_id, "ls"), session)
        assert result.metadata["handler"] == "good"


class TestIntakeValidation:
    def test_empty_command_rejected(self, pipeline):
        dispatcher, _, _ = pipeline
        for raw in ("", "   ", "\t\n"):
            res = dispatcher.validate_command(raw)
            assert not res.ok
            assert res.error_code == "command.empty"

    def test_nul_byte_rejected(self, pipeline):
        dispatcher, _, _ = pipeline
        res = dispatcher.validate_command("ls\x00rm -rf /")
        assert not res.ok
        assert res.error_code == "command.nul_byte"

    def test_too_long_rejected(self, pipeline):
        dispatcher, _, _ = pipeline
        res = dispatcher.validate_command("A" * (dispatcher._settings.max_command_length + 1))
        assert not res.ok
        assert res.error_code == "command.too_long"

    def test_valid_command_passes_and_is_stripped(self, pipeline):
        dispatcher, _, _ = pipeline
        res = dispatcher.validate_command("  whoami \n")
        assert res.ok and res.value == "whoami"

    async def test_session_must_be_active(self, pipeline):
        dispatcher, _, _ = pipeline
        closed = Session.new().with_changes(status=SessionStatus.CLOSED)
        res = await dispatcher.validate_session(closed)
        assert not res.ok
        assert res.error_code == "session.not_active"

    async def test_session_with_invalid_id_rejected(self, pipeline):
        dispatcher, _, _ = pipeline
        forged = Session.new().with_changes(session_id="sess_bogus")
        res = await dispatcher.validate_session(forged)
        assert not res.ok
        assert res.error_code == "session.invalid_id"


class TestPersistenceOnDispatch:
    async def test_dispatch_persists_request_and_result(self, pipeline):
        dispatcher, storage, session = pipeline
        req = _req(session.session_id, "whoami")
        result = await dispatcher.dispatch(req, session)
        fetched_req = await storage.commands.get(req.command_id)
        fetched_res = await storage.commands.get_result(req.command_id)
        assert fetched_req is not None
        assert fetched_res is not None
        assert fetched_res.command_id == result.command_id

    async def test_intake_persisted_before_handler_runs(self, pipeline):
        dispatcher, storage, session = pipeline
        bad = StubHandler("bad", claims_all=True, raises=True)
        dispatcher.register(bad)
        req = _req(session.session_id, "ls")
        await dispatcher.dispatch(req, session)
        # Even though the handler raised, intake is on record.
        assert await storage.commands.get(req.command_id) is not None

    async def test_stats_count_processed_and_fallback(self, pipeline):
        dispatcher, _, session = pipeline
        await dispatcher.dispatch(_req(session.session_id, "ls"), session)
        assert dispatcher.stats["processed"] == 1
        assert dispatcher.stats["fallback"] == 1
