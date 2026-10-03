"""Provider tests: error taxonomy, timeout mapping, JSON contract, no blocking."""

from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from test.agent._fixtures import AgentTestCase  # noqa: E402


class ProviderErrorTaxonomyTest(AgentTestCase):
    def test_all_errors_subclass_provider_error(self):
        from app.agent.providers.base import (
            ProviderAuthError,
            ProviderBadResponseError,
            ProviderError,
            ProviderModelUnavailableError,
            ProviderTimeoutError,
            ProviderUnavailableError,
        )

        for exc in (ProviderAuthError, ProviderBadResponseError,
                    ProviderModelUnavailableError, ProviderTimeoutError,
                    ProviderUnavailableError):
            self.assertTrue(issubclass(exc, ProviderError), exc.__name__)

    def test_timeout_maps_to_timeout_error(self):
        import requests

        from app.agent.providers import OllamaProvider
        from app.agent.providers.base import ProviderTimeoutError

        provider = OllamaProvider(model="m", timeout=0.1)
        with unittest.mock.patch.object(
            requests, "post", side_effect=requests.exceptions.Timeout("t")
        ):
            with self.assertRaises(ProviderTimeoutError):
                provider._post("/api/generate", {})

    def test_connection_error_maps_to_unavailable(self):
        import requests

        from app.agent.providers import OllamaProvider
        from app.agent.providers.base import ProviderUnavailableError

        provider = OllamaProvider(model="m")
        with unittest.mock.patch.object(
            requests, "post", side_effect=requests.exceptions.ConnectionError("refused")
        ):
            with self.assertRaises(ProviderUnavailableError):
                provider._post("/api/generate", {})

    def test_404_maps_to_model_unavailable(self):
        import requests

        from app.agent.providers import OllamaProvider
        from app.agent.providers.base import ProviderModelUnavailableError

        provider = OllamaProvider(model="m")
        fake = unittest.mock.Mock(status_code=404)
        with unittest.mock.patch.object(requests, "post", return_value=fake):
            with self.assertRaises(ProviderModelUnavailableError):
                provider._post("/api/generate", {})

    def test_malformed_json_maps_to_bad_response(self):
        import requests

        from app.agent.providers import OllamaProvider
        from app.agent.providers.base import ProviderBadResponseError

        provider = OllamaProvider(model="m")
        fake = unittest.mock.Mock(status_code=200)
        fake.json.side_effect = ValueError("not json")
        with unittest.mock.patch.object(requests, "post", return_value=fake):
            with self.assertRaises(ProviderBadResponseError):
                provider._post("/api/generate", {})

    def test_empty_response_text_maps_to_bad_response(self):
        import asyncio as aio

        import requests

        from app.agent.providers import OllamaProvider
        from app.agent.providers.base import ProviderBadResponseError
        from app.agent.models import LLMRequest

        provider = OllamaProvider(model="m")
        fake = unittest.mock.Mock(status_code=200)
        fake.json.return_value = {"response": "   "}
        with unittest.mock.patch.object(requests, "post", return_value=fake):
            with self.assertRaises(ProviderBadResponseError):
                aio.run(provider.generate(LLMRequest(prompt="p")))

    def test_error_messages_never_include_underlying_exception(self):
        import requests

        from app.agent.providers import OllamaProvider
        from app.agent.providers.base import ProviderUnavailableError

        provider = OllamaProvider(model="m")
        secret = "http://10.0.0.5:11434?token=hunter2"
        with unittest.mock.patch.object(
            requests,
            "post",
            side_effect=requests.exceptions.ConnectionError(f"cannot reach {secret}"),
        ):
            with self.assertRaises(ProviderUnavailableError) as ctx:
                provider._post("/api/generate", {})
            self.assertNotIn(secret, str(ctx.exception))

    def test_generate_returns_text_with_latency(self):
        import requests

        from app.agent.models import LLMRequest
        from app.agent.providers import OllamaProvider

        provider = OllamaProvider(model="qwen2.5:3b")
        fake = unittest.mock.Mock(status_code=200)
        fake.json.return_value = {"response": '{"action": "RESPOND"}', "model": "qwen2.5:3b"}
        with unittest.mock.patch.object(requests, "post", return_value=fake):
            response = asyncio.run(provider.generate(LLMRequest(prompt="p")))
        self.assertEqual(response.text, '{"action": "RESPOND"}')
        self.assertEqual(response.provider, "ollama")
        self.assertGreaterEqual(response.latency_ms, 0.0)


class MockProviderContractTest(AgentTestCase):
    def test_mock_returns_scripted_responses_in_order(self):
        from app.agent.models import LLMRequest
        from app.agent.providers import MockProvider

        provider = MockProvider(
            model="m",
            responses=[
                '{"action": "RESPOND", "response": "one"}',
                '{"action": "RESPOND", "response": "two"}',
            ],
        )
        r1 = asyncio.run(provider.generate(LLMRequest(prompt="p")))
        r2 = asyncio.run(provider.generate(LLMRequest(prompt="p")))
        self.assertIn("one", r1.text)
        self.assertIn("two", r2.text)
        self.assertEqual(provider.call_count, 2)

    def test_mock_raises_scripted_exceptions(self):
        from app.agent.models import LLMRequest
        from app.agent.providers import MockProvider
        from app.agent.providers.base import ProviderTimeoutError

        provider = MockProvider(model="m", responses=[ProviderTimeoutError("t")])
        with self.assertRaises(ProviderTimeoutError):
            asyncio.run(provider.generate(LLMRequest(prompt="p")))

    def test_mock_records_prompts_and_calls_on_prompt(self):
        from app.agent.models import LLMRequest
        from app.agent.providers import MockProvider

        seen = []
        provider = MockProvider(
            model="m",
            responses=["ok"],
            on_prompt=lambda p: seen.append(p),
        )
        asyncio.run(provider.generate(LLMRequest(prompt="hello")))
        self.assertEqual(len(provider.prompts), 1)
        self.assertIn("hello", provider.prompts[0])
        self.assertEqual(seen, provider.prompts)

    def test_mock_requires_scripted_responses(self):
        from app.agent.models import LLMRequest
        from app.agent.providers import MockProvider
        from app.agent.providers.base import ProviderUnavailableError

        provider = MockProvider(model="m", responses=[])
        with self.assertRaises(ProviderUnavailableError):
            asyncio.run(provider.generate(LLMRequest(prompt="p")))


if __name__ == "__main__":
    unittest.main()
