"""Pytest configuration for the MIRAGE test suite.

Async tests run via pytest-asyncio in strict mode (every async test
must be explicitly marked). Foundation tests use a temporary SQLite
database per test via the ``tmp_foundation_settings`` fixture.
"""
import os
import sys
from pathlib import Path

import pytest

# Make `app` importable when tests are run from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture()
def tmp_foundation_settings(tmp_path, monkeypatch):
    """Settings pointing at a throwaway database, development-safe mode.

    Also isolates the test from any local .env overrides of the
    variables we care about.
    """
    for var in (
        "MIRAGE_ENV",
        "MIRAGE_DB_PATH",
        "MIRAGE_SECURITY_MODE",
        "MIRAGE_MAX_SESSIONS",
        "MIRAGE_MAX_CONCURRENT_SESSIONS",
        "MIRAGE_MAX_COMMAND_LENGTH",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("MIRAGE_ENV", "testing")
    monkeypatch.setenv("MIRAGE_DB_PATH", str(tmp_path / "foundation_test.db"))
    from app.config import Settings

    return Settings()
