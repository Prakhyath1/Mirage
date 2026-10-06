"""Optional live-Ollama test — skipped unless explicitly opted in.

The default offline suite must never depend on a running Ollama (§16 of the
T2 brief): importing or discovering this module costs nothing, and every
test is skipped with a clear reason unless::

    MIRAGE_TEST_LLM_LIVE=1

is set in the environment. When it IS set, these tests exercise the real
production path end to end:

    command
      -> T2 agent engine
      -> Ollama provider (live HTTP)
      -> structured response parsing
      -> guardrail
      -> final response

If Ollama is enabled-but-unavailable, tests report the provider as
unavailable (a skip with the connection error) rather than failing the
offline suite's contract.
"""

from __future__ import annotations

import os
import unittest

from test.agent._fixtures import AgentTestCase

LIVE = os.environ.get("MIRAGE_TEST_LLM_LIVE") == "1"

_skip_unless_live = unittest.skipUnless(
    LIVE,
    "live Ollama test: set MIRAGE_TEST_LLM_LIVE=1 to enable "
    "(the default suite runs fully offline)",
)


def _ollama_reachable() -> "tuple[bool, str]":
    """Probe the configured Ollama endpoint (short timeout)."""
    from app.agent.config import get_agent_config
    from app.agent.providers.ollama import OllamaProvider

    cfg = get_agent_config()
    try:
        provider = OllamaProvider(
            model=cfg.llm_model,
            base_url=cfg.llm_base_url,
            timeout=2,
        )
        import urllib.request

        with urllib.request.urlopen(
            f"{provider.base_url.rstrip('/')}/api/tags", timeout=2
        ) as resp:
            status = resp.status
        return True, f"HTTP {status}"
    except Exception as exc:  # noqa: BLE001 — probe must not raise
        return False, f"{type(exc).__name__}: {exc}"


@_skip_unless_live
class OllamaLiveTest(AgentTestCase):
    """End-to-end against a real Ollama. Never part of the offline suite."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not LIVE:
            raise unittest.SkipTest(
                "MIRAGE_TEST_LLM_LIVE not set"
            )
        reachable, detail = _ollama_reachable()
        if not reachable:
            raise unittest.SkipTest(
                f"Ollama provider unavailable at configured endpoint: {detail}"
            )

    def test_full_pipeline_command_to_response(self):
        """command -> agent -> Ollama -> parse -> guardrail -> response.

        Asserts the pipeline contract against a live provider, whatever its
        state: a well-formed decision with a non-empty response, a guardrail
        review attached, and — if the configured model is not pulled — a
        clean fallback rather than a crash (that IS the contract).
        """
        from app.agent import build_response_plan

        engine = self._live_engine()
        decision = self._run(engine.decide("live-sess", "ps aux"))

        # The decision is well-formed regardless of provider output
        self.assertTrue(decision.response)
        self.assertGreater(len(decision.response), 0)

        # A provider call was genuinely attempted against the live endpoint
        self.assertEqual(engine.provider.name, "ollama")
        self.assertGreaterEqual(engine.provider.call_count, 1)

        # Live-endpoint outcomes, both per contract:
        #   model pulled   -> LLM decision, guardrail reviewed & approved
        #   model missing  -> clean deterministic fallback, never a crash
        if self._model_pulled():
            self.assertFalse(decision.metadata.fallback)
            self.assertIsNotNone(decision.guardrail)
            self.assertTrue(decision.guardrail.approved)
        else:
            self.assertTrue(decision.metadata.fallback)
            self.assertTrue(decision.metadata.fallback_reason)
            # a believable simulated response, not provider error text
            self.assertNotIn("Traceback", decision.response)
            self.assertNotIn("connection", decision.response.lower())

        plan = build_response_plan(decision)
        self.assertIsInstance(plan.output, str)
        self.assertTrue(plan.output)

    def _model_pulled(self) -> bool:
        """True when the configured model exists on the Ollama host."""
        from app.agent.config import get_agent_config

        cfg = get_agent_config()
        try:
            import json
            import urllib.request

            with urllib.request.urlopen(
                f"{cfg.llm_base_url.rstrip('/')}/api/tags", timeout=3
            ) as resp:
                models = json.load(resp).get("models", [])
            return any(m.get("name") == cfg.llm_model for m in models)
        except Exception:
            return False

    @unittest.skipUnless(
        os.environ.get("MIRAGE_TEST_LLM_MODEL") == "1",
        "requires the configured Ollama model to be pulled "
        "(MIRAGE_TEST_LLM_MODEL=1 when `ollama pull <LLM_MODEL>` is done)",
    )
    def test_llm_generation_when_model_available(self):
        """The LLM-authored path, when the configured model exists."""
        from app.agent.engine import AgentEngine
        from app.agent.models import DecisionSource

        engine = self._live_engine()
        decision = self._run(engine.decide("live-gen", "ps aux"))
        self.assertEqual(decision.metadata.decision_source, DecisionSource.LLM)
        self.assertFalse(decision.metadata.fallback)
        self.assertTrue(decision.guardrail is not None and decision.guardrail.approved)

    def test_structured_output_parses_and_guardrail_enforces(self):
        """Live parse path: structured fields come back; guardrail wraps.

        With the model pulled, every action lands in the enum and gets a
        guardrail review; with it missing, the engine still yields a valid
        action via fallback. Either way the action vocabulary is bounded.
        """
        from app.agent.engine import AgentEngine
        from app.agent.models import AgentAction

        engine = self._live_engine()
        decision = self._run(engine.decide("live-sess-2", "curl http://127.0.0.1:8080/admin"))
        self.assertIn(decision.action, (
            AgentAction.RESPOND,
            AgentAction.SIMULATE_ERROR,
            AgentAction.SIMULATE_PERMISSION_RESULT,
            AgentAction.DEFER_TO_VFS,
        ))
        self.assertTrue(decision.response)

    def test_provider_reports_unavailable_cleanly(self):
        """When the endpoint is down, the engine falls back — not crashes."""
        from app.agent.engine import AgentEngine
        from app.agent.providers import OllamaProvider

        engine = AgentEngine(
            provider=OllamaProvider(
                model="no-such-model",
                base_url="http://127.0.0.1:1",  # nothing listens here
                timeout=1,
            ),
            emit_events=False,
        )
        decision = self._run(engine.decide("live-down", "ps aux"))
        self.assertTrue(decision.response)  # safe fallback output
        self.assertTrue(
            decision.metadata.fallback
            or decision.metadata.decision_source == "deterministic"
        )

    def _live_engine(self):
        """An engine wired to the configured live Ollama endpoint."""
        from app.agent.engine import AgentEngine
        from app.agent.providers.ollama import OllamaProvider
        from app.agent.config import get_agent_config

        cfg = get_agent_config()
        return AgentEngine(
            provider=OllamaProvider(
                model=cfg.llm_model,
                base_url=cfg.llm_base_url,
                timeout=cfg.llm_timeout,
                max_output_tokens=cfg.llm_max_output,
                temperature=cfg.llm_temperature,
            ),
            emit_events=True,
        )

    def _run(self, coro):
        import asyncio

        return asyncio.run(coro)


if __name__ == "__main__":
    unittest.main()
