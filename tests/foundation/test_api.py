"""API boundary tests: health/ready probes, the /dev/ surface, input
validation at the HTTP boundary, and the consistent error envelope.

The security invariant under test: identifiers and command text arriving
over HTTP are untrusted data — validated, persisted, and simulated, but
never executed on the host and never interpolated into queries.
"""
import httpx
import pytest

from app.config import Settings
from app.main import create_app
from app.models import EventType, SessionStatus


@pytest.fixture()
async def client(tmp_foundation_settings):
    """Test client wired to a runtime with a throwaway database.

    The lifespan is not exercised here (httpx's ASGITransport does not
    run it); the runtime is initialized explicitly instead, which is the
    same call the lifespan performs.
    """
    app = create_app(tmp_foundation_settings)
    runtime = app.state.runtime
    await runtime.initialize()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as c:
        yield c
    await runtime.shutdown()


class TestHealth:
    async def test_health_ok(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert body["environment"] == "testing"

    async def test_ready_reports_connected(self, client):
        resp = await client.get("/ready")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert body["database_connected"] is True
        assert body["event_bus_running"] is True


class TestSessionEndpoints:
    async def test_create_session(self, client):
        resp = await client.post(
            "/dev/sessions",
            json={"source_address": "10.0.0.9", "username": "root"},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["status"] == "ACTIVE"
        assert body["username"] == "root"
        assert body["session_id"].startswith("sess_")

    async def test_create_rejects_unknown_fields(self, client):
        # extra="forbid": clients cannot smuggle unexpected keys in.
        resp = await client.post(
            "/dev/sessions", json={"source_address": "x", "evil": True}
        )
        assert resp.status_code == 422

    async def test_create_rejects_bad_port(self, client):
        resp = await client.post(
            "/dev/sessions", json={"source_port": 99999}
        )
        assert resp.status_code == 422

    async def test_summary_after_command(self, client):
        created = (
            await client.post("/dev/sessions", json={})
        ).json()
        session_id = created["session_id"]
        await client.post(
            f"/dev/sessions/{session_id}/commands", json={"command": "whoami"}
        )
        resp = await client.get(f"/dev/sessions/{session_id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["command_count"] == 1
        assert body["last_command"] == "whoami"

    async def test_close_session(self, client):
        session_id = (await client.post("/dev/sessions", json={})).json()[
            "session_id"
        ]
        resp = await client.delete(f"/dev/sessions/{session_id}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "CLOSED"

    async def test_close_unknown_returns_envelope(self, client):
        # A well-formed but nonexistent ID: 404, not a stack trace.
        fake = "sess_" + "a" * 32
        resp = await client.delete(f"/dev/sessions/{fake}")
        assert resp.status_code == 404
        body = resp.json()
        assert body["error"] == "http_error"


class TestCommandEndpoint:
    async def test_command_roundtrip(self, client):
        session_id = (await client.post("/dev/sessions", json={})).json()[
            "session_id"
        ]
        resp = await client.post(
            f"/dev/sessions/{session_id}/commands",
            json={"command": "whoami"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["stdout"] == "admin\n"  # decoy identity (T3 discipline: never the host user)
        assert body["exit_code"] == 0
        assert body["simulated"] is True
        assert body["result_type"] == "fallback"
        assert body["session_id"] == session_id

    async def test_malformed_session_id_rejected(self, client):
        # Junk identifiers are rejected at the boundary — before any
        # database lookup.
        for bad in ("bogus", "sess_", "sess_Ünicode"):
            resp = await client.post(
                f"/dev/sessions/{bad}/commands", json={"command": "ls"}
            )
            assert resp.status_code == 400, bad

        # A path-traversal string cannot be exercised through an HTTP
        # client: RFC 3986 path normalization (client- or server-side)
        # collapses "../.." before routing, so no 400 is reachable for
        # it by design. Assert it is still *rejected* (never accepted,
        # never looked up, never executed), and cover the validator's
        # own handling of it directly below.
        resp = await client.post(
            "/dev/sessions/../../etc/passwd/commands", json={"command": "ls"}
        )
        assert resp.status_code in (400, 404)

    def test_traversal_id_rejected_by_validator(self):
        # Direct call into the boundary validator: the traversal string
        # as a session ID raises 400 before any lookup.
        from fastapi import HTTPException

        from app.api.routes import _require_valid_session_id

        with pytest.raises(HTTPException) as exc:
            _require_valid_session_id("../../etc/passwd")
        assert exc.value.status_code == 400

    async def test_empty_command_rejected(self, client):
        session_id = (await client.post("/dev/sessions", json={})).json()[
            "session_id"
        ]
        resp = await client.post(
            f"/dev/sessions/{session_id}/commands", json={"command": "  "}
        )
        assert resp.status_code == 422

    async def test_too_long_command_rejected(self, client):
        session_id = (await client.post("/dev/sessions", json={})).json()[
            "session_id"
        ]
        limit = Settings().max_command_length
        resp = await client.post(
            f"/dev/sessions/{session_id}/commands",
            json={"command": "A" * (limit + 1)},
        )
        assert resp.status_code == 422

    async def test_command_on_closed_session_fails(self, client):
        session_id = (await client.post("/dev/sessions", json={})).json()[
            "session_id"
        ]
        await client.delete(f"/dev/sessions/{session_id}")
        resp = await client.post(
            f"/dev/sessions/{session_id}/commands", json={"command": "ls"}
        )
        assert resp.status_code == 400
        assert resp.json()["message"] == "session.not_active"

    async def test_command_on_unknown_session_is_404(self, client):
        fake = "sess_" + "a" * 32
        resp = await client.post(
            f"/dev/sessions/{fake}/commands", json={"command": "ls"}
        )
        assert resp.status_code == 404
