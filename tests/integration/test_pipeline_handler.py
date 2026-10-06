"""The integrated mode: T3's pipeline serving T1's foundation runtime.

The vertical-slice suite (:mod:`tests.integration.test_vertical_slice`)
exercises the T1 stack with the fallback handler. This suite exercises
the mode the deployed merged app actually runs: the lifespan attaches
:class:`app.integration.pipeline_handler.T3PipelineHandler` to the
dispatcher, so every validated foundation command flows through T3's
pipeline (parse → classify → score → sandbox / LLM) while the T1 layers
still record their storage rows and emit their bus events.

Security invariants asserted from outside and inside simultaneously:
- foundation command results are VFS results produced by the pipeline
  (``result_type == "vfs"``, ``metadata["handler"] == "t3-pipeline"``),
  never host execution;
- T3's decoy identity is what the attacker sees, never the host user;
- a canary trip escalates the T3 session and activates containment;
- when the pipeline itself fails, the T1 fallback still answers with a
  simulated result — no path exists that executes on the host.
"""
import pytest

from app.config import Settings
from app.main import create_app
from app.models import ResultType


@pytest.fixture()
async def integrated_stack(tmp_foundation_settings, tmp_path, monkeypatch):
    """Foundation app with the T3 handler attached, as the lifespan does.

    T3's pipeline keeps its own SQLite database (``app.db``); point it
    at a throwaway file so the suite never touches the developer DB.
    """
    monkeypatch.setattr(
        "app.db.DB_PATH", str(tmp_path / "t3.db"), raising=True
    )

    app = create_app(tmp_foundation_settings)
    runtime = app.state.runtime
    await runtime.initialize()

    # Exactly what the lifespan does for the merged build.
    from app.integration import attach_default_handlers

    attach_default_handlers(runtime)

    # And exactly what it does for the legacy pipeline DB.
    import app.db as t3_db

    t3_db.init_db()
    t3_db.migrate_add_threat_summary()
    t3_db.migrate_add_containment_active()

    import httpx

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        yield client, runtime
    await runtime.shutdown()


class TestPipelineHandlerAttached:
    async def test_foundation_command_runs_through_t3_pipeline(
        self, integrated_stack
    ):
        """A /dev command is claimed and simulated by the T3 pipeline."""
        client, runtime = integrated_stack

        session_id = (
            await client.post("/dev/sessions", json={"source_address": "10.9.9.9"})
        ).json()["session_id"]

        resp = await client.post(
            f"/dev/sessions/{session_id}/commands",
            json={"command": "whoami"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["simulated"] is True
        assert body["result_type"] == ResultType.VFS.value
        assert body["metadata"]["handler"] == "t3_pipeline"
        # The decoy identity, not the host user.
        assert body["stdout"].strip() == "admin"

        # The foundation still recorded the exchange.
        req = await runtime.storage.commands.get(body["command_id"])
        assert req is not None
        assert req.raw_command == "whoami"

    async def test_canary_trip_escalates_and_contains(self, integrated_stack):
        """Reading a planted canary escalates the T3 session to High."""
        client, _ = integrated_stack

        session_id = (
            await client.post("/dev/sessions", json={"source_address": "10.9.9.9"})
        ).json()["session_id"]

        for command in ("ls", "cat .env"):
            resp = await client.post(
                f"/dev/sessions/{session_id}/commands",
                json={"command": command},
            )
            assert resp.status_code == 200

        # The T3-side session state the dashboard reads.
        import app.db as t3_db

        session = t3_db.get_session_by_id(session_id)
        assert session is not None
        assert session["threat_score"] > 0
        assert session["threat_level"] == "High"
        assert session["containment_active"] == 1

        # The trip is recorded as an event for the dashboard.
        events = t3_db.get_session_events(session_id, limit=50)
        assert any(e["event_type"] == "HONEYTOKEN_ACCESS" for e in events)

    async def test_path_escape_is_simulated_not_host(
        self, integrated_stack
    ):
        """Traversal outside the VFS yields a simulated reply, never host I/O."""
        client, _ = integrated_stack

        session_id = (
            await client.post("/dev/sessions", json={"source_address": "10.9.9.9"})
        ).json()["session_id"]

        resp = await client.post(
            f"/dev/sessions/{session_id}/commands",
            json={"command": "cat ../../etc/passwd"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["simulated"] is True
        # Resolved inside the VFS: simulated passwd, decoy identity only.
        assert "root:x:0:0" in body["stdout"]
        assert "ubuntu" not in body["stdout"].lower()

    async def test_pipeline_failure_falls_back_to_safe_simulation(
        self, integrated_stack
    ):
        """If the pipeline raises, T1's fallback answers — nothing executes."""
        client, _ = integrated_stack

        session_id = (
            await client.post("/dev/sessions", json={"source_address": "10.9.9.9"})
        ).json()["session_id"]

        # Break the pipeline the way an outage would.
        import app.router as t3_router
        import app.integration.pipeline_handler as ph

        original = t3_router.process_command

        def broken(*args, **kwargs):
            raise RuntimeError("pipeline outage")

        t3_router.process_command = broken
        try:
            resp = await client.post(
                f"/dev/sessions/{session_id}/commands",
                json={"command": "whoami"},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["simulated"] is True
            # SafeFallbackHandler answered with its static hint.
            assert body["result_type"] == ResultType.FALLBACK.value
            assert body["stdout"].strip() == "admin"
        finally:
            t3_router.process_command = original


class TestLegacyRoutesOnMergedApp:
    """T3-era endpoints mounted by the merged main keep their shapes."""

    async def test_command_route_shape(self, integrated_stack):
        client, _ = integrated_stack

        resp = await client.post(
            "/command",
            json={"session_id": "legacy-shape-1", "command": "whoami"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert set(body) == {"output"}
        assert body["output"].strip() == "admin"

    async def test_session_state_route_shape(self, integrated_stack):
        client, _ = integrated_stack

        await client.post(
            "/command",
            json={"session_id": "legacy-shape-2", "command": "ls"},
        )
        resp = await client.get("/session/legacy-shape-2")
        assert resp.status_code == 200
        body = resp.json()
        assert body["cwd"] == "/home/admin"
        assert isinstance(body["threat_score"], int)
        assert isinstance(body["containment_active"], bool)

    async def test_unknown_session_is_404(self, integrated_stack):
        client, _ = integrated_stack
        resp = await client.get("/session/never-existed")
        assert resp.status_code == 404
        resp = await client.get("/session/never-existed/events")
        assert resp.status_code == 404
        resp = await client.get("/session/never-existed/honeytokens")
        assert resp.status_code == 404
