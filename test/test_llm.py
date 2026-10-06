"""LLM fallback tests (STEP 16 sanity, ported to the T2 agent engine).

The engine behind ``llm_engine`` is now T2's agentic deception stack; the
facade keeps the same externally observable contract, so these tests keep
the same invariants:

- any transport failure degrades to the generic fallback ("command not
  found") — never an exception, never host data;
- the provider only ever talks to a fixed localhost endpoint — it can
  never become an outbound (data-exfiltration) channel;
- live smoke checks are skipped automatically when no Ollama is running.

Hermetic by default: the transport is stubbed through the provider module
(``app.agent.providers.ollama.requests``), which is where the HTTP call
lives since the T2 merge.

Run: python3 -m pytest test/test_llm.py -v
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import llm_engine
from app.agent import build_provider, get_agent_config
from app.agent.providers import ollama as ollama_provider


def test_fallback_string_on_connection_failure(monkeypatch):
    # Any transport failure must degrade to the generic fallback — never an
    # exception, never host data. The command is deliberately not one of
    # the deterministic-owned commands (identity/VFS/denials are answered
    # without any provider call — asserted by test_llm: the old engine
    # reached the transport for everything).
    def refused(*args, **kwargs):
        raise ConnectionError("connection refused")

    monkeypatch.setattr(ollama_provider.requests, "post", refused)
    out = llm_engine.generate_response("foobarbaz --flag", "/home/admin")
    assert out == "command not found" or out.endswith("command not found")
    assert llm_engine.generate_analysis("prompt") == ""


def test_fallback_string_on_non_200(monkeypatch):
    class Resp:
        status_code = 500

        def json(self):
            return {}

    monkeypatch.setattr(ollama_provider.requests, "post", lambda *a, **k: Resp())
    out = llm_engine.generate_response("foobarbaz --flag", "/home/admin")
    # The engine's styled fallback ("bash: foobarbaz: command not found")
    # preserves the legacy contract: a command-not-found style error with
    # no host data in it.
    assert out.endswith("command not found")
    assert llm_engine.generate_analysis("prompt") == ""


def test_engine_only_talks_to_localhost(monkeypatch):
    # The LLM fallback is a fixed localhost endpoint — it can never become an
    # outbound (data-exfiltration) channel. Pin the production defaults
    # explicitly: the agent test tree may run earlier in the same pytest
    # process and leave LLM_PROVIDER=mock in os.environ (setdefault there).
    for key, value in (
        ("LLM_PROVIDER", "ollama"),
        ("LLM_BASE_URL", "http://127.0.0.1:11434"),
    ):
        monkeypatch.setenv(key, value)
    from app.agent.config import reset_agent_config

    reset_agent_config()
    try:
        cfg = get_agent_config()
        assert cfg.llm_base_url.startswith("http://127.0.0.1:")
        assert cfg.llm_base_url == "http://127.0.0.1:11434"
        provider = build_provider(cfg)
        assert provider.base_url.startswith("http://127.0.0.1:11434")
    finally:
        reset_agent_config()


def _ollama_up() -> bool:
    try:
        ollama_provider.requests.post(
            "http://127.0.0.1:11434/api/generate",
            json={"model": get_agent_config().llm_model, "prompt": "", "stream": False},
            timeout=2,
        )
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _ollama_up(), reason="Ollama not running at 127.0.0.1:11434")
def test_live_fallback_smoke():
    out = llm_engine.generate_response("uname -a", "/home/admin")
    assert isinstance(out, str) and out
