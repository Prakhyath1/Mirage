"""Ollama provider — the provider MIRAGE currently needs.

Async contract: the HTTP call runs in ``asyncio.to_thread`` over the already
installed ``requests`` library, so the FastAPI event loop is never blocked
and no new runtime dependency is introduced. Swapping in httpx later is a
one-method change inside ``_post``.

Error mapping (per ollama_requirements):
  * timeout                       -> ProviderTimeoutError
  * connection refused / DNS      -> ProviderUnavailableError
  * HTTP 404 on /api/tags model    -> ProviderModelUnavailableError
  * malformed JSON / empty body   -> ProviderBadResponseError
  * non-200 status                -> ProviderBadResponseError
  * secrets are never included in error messages
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from typing import Any, Dict, Optional

import requests

from ..models import LLMRequest, LLMResponse
from .base import (
    LLMProvider,
    ProviderBadResponseError,
    ProviderError,
    ProviderModelUnavailableError,
    ProviderTimeoutError,
    ProviderUnavailableError,
)


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(
        self,
        model: str,
        base_url: str = "http://127.0.0.1:11434",
        timeout: float = 30.0,
        max_output_tokens: int = 512,
        temperature: float = 0.2,
        extra_headers: Optional[Dict[str, str]] = None,
    ):
        super().__init__(model=model, base_url=base_url, timeout=timeout)
        self.max_output_tokens = max_output_tokens
        self.temperature = temperature
        self.extra_headers = extra_headers or {}
        self.call_count = 0  # observability / test assertion hook

    def supports_json_mode(self) -> bool:
        return True

    # -- transport ----------------------------------------------------------
    def _post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Synchronous POST executed on a worker thread by ``generate``."""
        url = f"{self.base_url.rstrip('/')}{endpoint}"
        try:
            resp = requests.post(
                url,
                json=payload,
                timeout=self.timeout,
                headers=self.extra_headers,
            )
        except requests.exceptions.Timeout as exc:
            raise ProviderTimeoutError(
                f"ollama request timed out after {self.timeout}s", self.name
            ) from None
        except requests.exceptions.ConnectionError as exc:
            # Never include the low-level exception text: it can embed URLs
            # or proxy environment details.
            raise ProviderUnavailableError(
                "ollama server unreachable", self.name
            ) from None
        except requests.exceptions.RequestException as exc:
            raise ProviderUnavailableError("ollama request failed", self.name) from None

        if resp.status_code == 404:
            raise ProviderModelUnavailableError(
                "model not found on ollama server", self.name
            )
        if resp.status_code in (401, 403):
            # auth is not used with local ollama, but map defensively
            raise ProviderError(
                "ollama rejected the request (auth)", self.name
            )
        if resp.status_code != 200:
            raise ProviderBadResponseError(
                f"ollama returned status {resp.status_code}", self.name
            )

        try:
            data = resp.json()
        except ValueError as exc:
            raise ProviderBadResponseError(
                "ollama returned malformed JSON", self.name
            ) from None
        if not isinstance(data, dict):
            raise ProviderBadResponseError(
                "ollama returned unexpected JSON shape", self.name
            )
        return data

    # -- LLMProvider --------------------------------------------------------
    async def generate(self, request: LLMRequest) -> LLMResponse:
        payload: Dict[str, Any] = {
            "model": self.model,
            "prompt": request.prompt,
            "stream": False,
            "options": {
                "temperature": request.temperature
                if request.temperature is not None
                else self.temperature,
                "num_predict": request.max_output_tokens
                if request.max_output_tokens
                else self.max_output_tokens,
            },
        }
        if request.system:
            payload["system"] = request.system
        if request.json_mode and self.supports_json_mode():
            payload["format"] = "json"

        self.call_count += 1
        started = time.monotonic()
        data = await asyncio.to_thread(self._post, "/api/generate", payload)
        latency_ms = (time.monotonic() - started) * 1000.0

        text = data.get("response")
        if not isinstance(text, str) or not text.strip():
            raise ProviderBadResponseError("ollama returned empty response", self.name)

        return LLMResponse(
            text=text,
            provider=self.name,
            model=str(data.get("model", self.model)),
            latency_ms=round(latency_ms, 2),
            metadata={
                "prompt_eval_count": data.get("prompt_eval_count"),
                "eval_count": data.get("eval_count"),
            },
        )
