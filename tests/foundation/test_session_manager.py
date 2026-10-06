"""Session lifecycle tests: explicit state machine, unguessable IDs,
idempotent close, auth recording, rejection of malformed identifiers."""
import pytest

from app.events.bus import EventBus
from app.models import SessionStatus
from app.runtime.session_manager import SessionManager, SessionStateError
from app.storage.database import Storage


@pytest.fixture()
async def runtime(tmp_foundation_settings):
    storage = Storage(tmp_foundation_settings)
    await storage.initialize()
    bus = EventBus()
    manager = SessionManager(storage, bus)
    yield manager
    await storage.close()


async def test_create_persists_created_state(runtime):
    s = await runtime.create(source_address="10.0.0.1")
    assert s.status is SessionStatus.CREATED
    fetched = await runtime.get(s.session_id)
    assert fetched is not None
    assert fetched.session_id == s.session_id


async def test_created_to_active_to_closed(runtime):
    s = await runtime.create()
    res = await runtime.activate(s.session_id)
    assert res.ok and res.value.status is SessionStatus.ACTIVE
    res = await runtime.close(s.session_id)
    assert res.ok and res.value.status is SessionStatus.CLOSED


async def test_created_to_closed_directly(runtime):
    # Connection dropped pre-auth.
    s = await runtime.create()
    res = await runtime.close(s.session_id)
    assert res.ok and res.value.status is SessionStatus.CLOSED


async def test_double_close_is_idempotent(runtime):
    s = await runtime.create()
    first = await runtime.close(s.session_id)
    second = await runtime.close(s.session_id)
    assert first.ok and second.ok
    assert second.value.status is SessionStatus.CLOSED


async def test_close_unknown_session_fails_cleanly(runtime):
    res = await runtime.close("sess_nonexistent")
    assert not res.ok
    assert res.error_code == "session.not_found"


async def test_invalid_transition_raises_state_error(runtime):
    s = await runtime.create()
    await runtime.close(s.session_id)
    with pytest.raises(SessionStateError):
        await runtime.activate(s.session_id)  # CLOSED -> ACTIVE forbidden


async def test_record_auth_success_activates(runtime):
    s = await runtime.create()
    res = await runtime.record_auth(
        s.session_id, username="root", auth_method="password",
        auth_success=True,
    )
    assert res.ok
    assert res.value.status is SessionStatus.ACTIVE
    assert res.value.username == "root"


async def test_record_auth_failure_keeps_created(runtime):
    s = await runtime.create()
    res = await runtime.record_auth(
        s.session_id, username="root", auth_success=False
    )
    assert res.ok
    assert res.value.status is SessionStatus.CREATED
    assert res.value.auth_success is False


async def test_record_auth_on_closed_raises(runtime):
    s = await runtime.create()
    await runtime.close(s.session_id)
    with pytest.raises(SessionStateError):
        await runtime.record_auth(s.session_id, auth_success=True)


async def test_malformed_id_never_reaches_db(runtime):
    # Attacker-supplied junk must be rejected before any repository call.
    assert await runtime.get("'; DROP TABLE sessions;--") is None
    assert await runtime.get("") is None
    assert await runtime.get("sess_Ünicode") is None


async def test_metadata_merges_without_status_change(runtime):
    s = await runtime.create()
    res = await runtime.update_metadata(s.session_id, {"threat": "high"})
    assert res.ok
    assert res.value.metadata["threat"] == "high"
    assert res.value.status is SessionStatus.CREATED


async def test_server_generated_ids_are_unguessable(runtime):
    ids = {(await runtime.create()).session_id for _ in range(50)}
    assert len(ids) == 50
    for session_id in ids:
        assert session_id.startswith("sess_")
        assert len(session_id) >= 27
