"""Tests for app.config.Settings: env-var driven, safe defaults,
secret redaction, malformed value tolerance."""
import pytest

from app.config import Environment, LogLevel, SecurityMode, Settings


class TestDefaults:
    def test_development_defaults_are_safe(self, tmp_foundation_settings):
        s = tmp_foundation_settings
        assert s.environment is Environment.TESTING  # fixture sets testing
        assert s.security_mode is SecurityMode.STRICT
        assert s.database_path.name == "foundation_test.db"
        assert not s.debug

    def test_production_flag(self, tmp_foundation_settings):
        assert not tmp_foundation_settings.is_production

    def test_limits_are_bounded(self, tmp_foundation_settings):
        s = tmp_foundation_settings
        assert 0 < s.max_command_length <= 8192
        assert 0 < s.max_command_output_bytes <= 1 << 20
        assert 0 < s.max_event_payload_bytes <= 1 << 20
        assert 0 < s.max_sessions <= 1_000_000


class TestEnvOverrides:
    def test_env_overrides_respected(self, monkeypatch, tmp_path):
        monkeypatch.setenv("MIRAGE_ENV", "production")
        monkeypatch.setenv("MIRAGE_DB_PATH", str(tmp_path / "x.db"))
        monkeypatch.setenv("MIRAGE_PORT", "9999")
        monkeypatch.setenv("MIRAGE_SECURITY_MODE", "degraded")
        monkeypatch.setenv("MIRAGE_LOG_LEVEL", "DEBUG")
        s = Settings()
        assert s.environment is Environment.PRODUCTION
        assert s.is_production
        assert s.port == 9999
        assert s.security_mode is SecurityMode.DEGRADED
        assert s.log_level is LogLevel.DEBUG

    def test_malformed_values_fall_back(self, monkeypatch):
        monkeypatch.setenv("MIRAGE_PORT", "not-a-number")
        monkeypatch.setenv("MIRAGE_MAX_SESSIONS", "abc")
        s = Settings()
        assert s.port == 8000
        assert s.max_sessions == 10_000

    def test_unknown_enum_falls_back(self, monkeypatch):
        monkeypatch.setenv("MIRAGE_ENV", "bogus-env")
        # Constructor raises on invalid enum; settings must never start
        # half-configured, but also never silently guess production.
        with pytest.raises(ValueError):
            Settings()


class TestSecretRedaction:
    def test_safe_summary_has_no_secrets(self, tmp_foundation_settings):
        summary = tmp_foundation_settings.safe_summary()
        dumped = str(summary).lower()
        for marker in ("password", "secret", "token", "key="):
            assert marker not in dumped, f"secret marker {marker!r} leaked"

    def test_db_url_with_credentials_redacted(self, monkeypatch):
        monkeypatch.setenv(
            "MIRAGE_DATABASE_URL",
            "postgresql://user:password@localhost/mirage",
        )
        s = Settings()
        assert s.safe_summary()["database_url"] == "[redacted]"

    def test_plain_sqlite_url_not_redacted(self, tmp_foundation_settings):
        assert "redacted" not in tmp_foundation_settings.safe_summary()[
            "database_url"
        ]
