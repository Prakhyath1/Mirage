"""Provider registry: builds the configured provider without coupling the
agent to any specific vendor. New providers are added by registering a
builder here — the agent code never changes."""

from __future__ import annotations

from typing import Callable, Dict, Optional

from ..config import AgentConfig, get_agent_config
from .base import (
    LLMProvider,
    ProviderAuthError,
    ProviderBadResponseError,
    ProviderError,
    ProviderModelUnavailableError,
    ProviderTimeoutError,
    ProviderUnavailableError,
)
from .mock import MockProvider
from .ollama import OllamaProvider

Builder = Callable[[AgentConfig], LLMProvider]


def _build_ollama(cfg: AgentConfig) -> LLMProvider:
    return OllamaProvider(
        model=cfg.llm_model,
        base_url=cfg.llm_base_url,
        timeout=cfg.llm_timeout,
        max_output_tokens=cfg.llm_max_output,
        temperature=cfg.llm_temperature,
    )


def _build_mock(cfg: AgentConfig) -> LLMProvider:
    return MockProvider(model=cfg.llm_model or "mock-model")


_PROVIDERS: Dict[str, Builder] = {
    "ollama": _build_ollama,
    "mock": _build_mock,
}


def register_provider(name: str, builder: Builder) -> None:
    """Register a provider builder (extension point for future providers)."""
    _PROVIDERS[name.lower()] = builder


def build_provider(config: Optional[AgentConfig] = None) -> LLMProvider:
    """Instantiate the configured provider. Raises for unknown names."""
    cfg = config or get_agent_config()
    builder = _PROVIDERS.get((cfg.llm_provider or "").lower())
    if builder is None:
        raise ProviderError(
            f"unknown LLM provider: {cfg.llm_provider!r}", "registry"
        )
    return builder(cfg)


def available_providers() -> list:
    return sorted(_PROVIDERS)


__all__ = [
    "LLMProvider",
    "ProviderError",
    "ProviderAuthError",
    "ProviderBadResponseError",
    "ProviderModelUnavailableError",
    "ProviderTimeoutError",
    "ProviderUnavailableError",
    "OllamaProvider",
    "MockProvider",
    "build_provider",
    "register_provider",
    "available_providers",
]
