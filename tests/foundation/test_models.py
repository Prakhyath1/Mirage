"""Tests for the typed contracts in app.models: identity, immutability,
factory validation, serialization shapes."""
import dataclasses

import pytest

from app.models import (
    CommandRequest,
    CommandResult,
    EventType,
    HealthStatus,
    ResultType,
    SecurityEvent,
    Session,
    SessionStatus,
    SessionSummary,
    Severity,
)


class TestSession:
    def test_new_session_starts_created_with_server_id(self):
        s = Session.new()
        assert s.status is SessionStatus.CREATED
        assert s.session_id.startswith("sess_")
        # Unguessable: two sessions never share an ID.
        assert s.session_id != Session.new().session_id

    def test_session_is_frozen(self):
        s = Session.new()
        with pytest.raises(dataclasses.FrozenInstanceError):
            s.status = SessionStatus.CLOSED

    def test_with_changes_returns_copy(self):
        s = Session.new()
        updated = s.with_changes(status=SessionStatus.ACTIVE)
        assert updated.status is SessionStatus.ACTIVE
        assert s.status is SessionStatus.CREATED  # original untouched

    def test_summary_shape(self):
        s = Session.new(username="root")
        summary = s.to_summary()
        assert isinstance(summary, SessionSummary)
        assert summary.session_id == s.session_id
        assert summary.username == "root"
        assert summary.command_count == 0


class TestCommandContracts:
    def test_command_request_new(self):
        s = Session.new()
        req = CommandRequest.new(
            session_id=s.session_id, raw_command="whoami"
        )
        assert req.raw_command == "whoami"
        assert req.command_id.startswith("cmd_")
        assert req.session_id == s.session_id
        assert isinstance(req.metadata, dict)

    def test_command_result_defaults_fallback(self):
        res = CommandResult.new(command_id="cmd_x")
        assert res.result_type is ResultType.FALLBACK
        assert res.exit_code == 0

    def test_contracts_frozen(self):
        req = CommandRequest.new(session_id="sess_x", raw_command="id")
        with pytest.raises(dataclasses.FrozenInstanceError):
            req.raw_command = "rm -rf /"


class TestSecurityEvent:
    def test_event_new(self):
        ev = SecurityEvent.new(
            session_id="sess_x",
            event_type=EventType.COMMAND_SUBMITTED.value,
            severity=Severity.INFO,
            source="test",
        )
        assert ev.event_id.startswith("evt_")
        assert ev.severity is Severity.INFO
        assert ev.payload == {}

    def test_event_frozen(self):
        ev = SecurityEvent.new(
            session_id="sess_x",
            event_type=EventType.RUNTIME_ERROR.value,
            severity=Severity.WARNING,
            source="test",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            ev.severity = Severity.CRITICAL


class TestHealthStatus:
    def test_is_ready(self):
        assert HealthStatus(status="ok").is_ready
        assert not HealthStatus(status="degraded").is_ready
        assert not HealthStatus(status="error").is_ready

    def test_defaults_are_safe(self):
        h = HealthStatus(status="degraded")
        assert h.database_connected is False
        assert h.details == {}
        assert h.version


class TestEnums:
    def test_session_status_values(self):
        # Stored as UPPERCASE to match wire/DB conventions.
        assert {s.value for s in SessionStatus} == {
            "CREATED", "ACTIVE", "CLOSED"
        }

    def test_result_type_values(self):
        assert {r.value for r in ResultType} == {
            "fallback", "vfs", "security", "agentic", "containment", "error",
        }

    def test_event_type_covers_lifecycle(self):
        # Event types are dotted, namespaced strings.
        values = {e.value for e in EventType}
        assert {
            "session.created",
            "command.submitted",
            "command.completed",
            "runtime.error",
        } <= values

    def test_severity_values(self):
        assert {s.value for s in Severity} == {
            "debug", "info", "warning", "high", "critical",
        }
