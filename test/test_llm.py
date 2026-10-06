"""LLM fallback tests (STEP 16 sanity).

Hermetic by default: the fallback contract ("command not found" on any
transport failure) is tested with a stubbed transport, and the live Ollama
smoke check is skipped automatically when no Ollama is running.

Run: python3 -m pytest test/ -v
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import llm_engine


def test_fallback_string_on_connection_failure(monkeypatch):
    # Any transport failure must degrade to the generic fallback — never an
    # exception, never host data.
    def refused(*args, **kwargs):
        raise ConnectionError("connection refused")

    monkeypatch.setattr(llm_engine.requests, "post", refused)
    assert llm_engine.generate_response("uname -a", "/home/admin") == "command not found"
    assert llm_engine.generate_analysis("prompt") == ""


def test_fallback_string_on_non_200(monkeypatch):
    class Resp:
        status_code = 500

        def json(self):
            return {}

    monkeypatch.setattr(llm_engine.requests, "post", lambda *a, **k: Resp())
    assert llm_engine.generate_response("ls", "/home/admin") == "command not found"
    assert llm_engine.generate_analysis("prompt") == ""


def test_engine_only_talks_to_localhost():
    # The LLM fallback is a fixed localhost endpoint — it can never become an
    # outbound (data-exfiltration) channel.
    assert llm_engine.OLLAMA_URL.startswith("http://127.0.0.1:")
    assert llm_engine.OLLAMA_URL.startswith("http://127.0.0.1:11434")


def _ollama_up() -> bool:
    try:
        llm_engine.requests.post(
            llm_engine.OLLAMA_URL,
            json={"model": llm_engine.MODEL_NAME, "prompt": "", "stream": False},
            timeout=2,
        )
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _ollama_up(), reason="Ollama not running at 127.0.0.1:11434")
def test_live_fallback_smoke():
    out = llm_engine.generate_response("uname -a", "/home/admin")
    assert isinstance(out, str) and out
