"""Mock provider: deterministic, offline, test-safe.

Used by the standard test suite and as an offline development provider. It
never performs I/O, so tests never require a running Ollama instance.
"""

from __future__ import annotations

import json
from typing import Callable, List, Optional, Union

from ..models import LLMRequest, LLMResponse
from .base import (
    LLMProvider,
    ProviderBadResponseError,
    ProviderError,
    ProviderTimeoutError,
    ProviderUnavailableError,
)


class MockProvider(LLMProvider):
    """Scriptable provider.

    ``responses`` is consumed in order (or repeated when exhausted):

      * ``str``        -> returned as model text
      * ``dict``       -> returned as a JSON dump of the dict
      * ``Exception``  -> raised (e.g. ProviderTimeoutError for tests)

    ``on_prompt`` receives every prompt for assertions.
    """

    name = "mock"

    def __init__(
        self,
        model: str = "mock-model",
        responses: Optional[List[Union[str, dict, Exception]]] = None,
        on_prompt: Optional[Callable[[str], None]] = None,
        base_url: str = "mock://local",
        timeout: float = 5.0,
    ):
        super().__init__(model=model, base_url=base_url, timeout=timeout)
        self.responses: List[Union[str, dict, Exception]] = list(responses or [])
        self.prompts: List[str] = []
        self.call_count = 0
        self.on_prompt = on_prompt

    def supports_json_mode(self) -> bool:
        return True

    async def generate(self, request: LLMRequest) -> LLMResponse:
        self.prompts.append(request.prompt)
        self.call_count += 1
        if self.on_prompt:
            self.on_prompt(request.prompt)

        if not self.responses:
            raise ProviderUnavailableError("mock provider has no scripted responses", self.name)

        item = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]

        if isinstance(item, ProviderError):
            raise item
        if isinstance(item, Exception):
            raise ProviderError(str(item), self.name)

        if isinstance(item, dict):
            text = json.dumps(item)
        else:
            text = str(item)

        if not text.strip():
            raise ProviderBadResponseError("mock provider scripted empty response", self.name)

        return LLMResponse(text=text, provider=self.name, model=self.model, latency_ms=0.1)
