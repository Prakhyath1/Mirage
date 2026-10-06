"""LLM provider abstraction.

The agent must not be permanently coupled to Ollama. Providers implement
``generate(request) -> LLMResponse`` (async — never block the FastAPI event
loop). Error taxonomy lives here so the engine can fail safely without
knowing provider internals.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Optional

from ..models import LLMRequest, LLMResponse


class ProviderError(Exception):
    """Base class for all provider failures (never leaks secrets)."""

    kind = "provider_error"

    def __init__(self, message: str = "", provider: str = "unknown"):
        super().__init__(message or self.kind)
        self.provider = provider


class ProviderTimeoutError(ProviderError):
    kind = "timeout"


class ProviderUnavailableError(ProviderError):
    """Connection refused / DNS failure / server down."""

    kind = "unavailable"


class ProviderBadResponseError(ProviderError):
    """Non-200 status, malformed body, or empty response payload."""

    kind = "bad_response"


class ProviderModelUnavailableError(ProviderError):
    """Server reachable but the requested model cannot be served."""

    kind = "model_unavailable"


class ProviderAuthError(ProviderError):
    """Server reachable but rejected credentials (never include the key)."""

    kind = "auth"


class LLMProvider(ABC):
    """Interface every T2 provider must implement.

    Contract:
      * ``generate`` is async and must respect ``request.max_output_tokens``
        and the provider timeout configured at construction.
      * Failures raise subclasses of ``ProviderError`` — never return
        free-form error text as if it were model output.
      * No provider may execute, shell out, or evaluate model output.
    """

    name: str = "base"

    def __init__(self, model: str, base_url: str = "", timeout: float = 30.0):
        self.model = model
        self.base_url = base_url
        self.timeout = timeout

    @abstractmethod
    async def generate(self, request: LLMRequest) -> LLMResponse:
        """Produce raw model text for ``request.prompt``."""

    # -- optional capabilities ---------------------------------------------
    def supports_json_mode(self) -> bool:
        return False

    @property
    def describe(self) -> str:
        return f"{self.name}:{self.model}"
