"""T2 agent configuration.

MIRAGE has no central configuration framework yet (``app/config.py`` is
empty, owned by T1). T2 therefore follows the documented extension point:
environment variables, loaded via python-dotenv which is already a runtime
dependency. Every value is overridable so nothing is hardcoded into business
logic — including the model name.
"""

from __future__ import annotations

import os
from typing import Optional

from dotenv import load_dotenv
from pydantic import BaseModel, Field

# Load .env from the repo root once on import (no-op when absent).
load_dotenv(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        ".env",
    )
)


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


class AgentConfig(BaseModel):
    """All knobs of the intelligence engine, sourced from the environment."""

    # --- LLM provider -----------------------------------------------------
    llm_provider: str = Field(default="ollama", alias="LLM_PROVIDER")
    llm_base_url: str = Field(
        default="http://127.0.0.1:11434", alias="LLM_BASE_URL"
    )
    llm_model: str = Field(default="qwen2.5:3b", alias="LLM_MODEL")
    llm_timeout: float = Field(default=30.0, alias="LLM_TIMEOUT")  # seconds
    llm_temperature: float = Field(default=0.2, alias="LLM_TEMPERATURE")
    llm_max_output: int = Field(default=512, alias="LLM_MAX_OUTPUT")

    # --- Agent bounds -----------------------------------------------------
    agent_max_memory: int = Field(default=20, alias="AGENT_MAX_MEMORY")
    agent_max_context: int = Field(default=6000, alias="AGENT_MAX_CONTEXT")  # chars
    agent_max_response: int = Field(default=2000, alias="AGENT_MAX_RESPONSE")  # chars
    agent_max_command_len: int = Field(default=2000, alias="AGENT_MAX_COMMAND_LEN")
    agent_enable_guardrail: bool = Field(default=True, alias="AGENT_ENABLE_GUARDRAIL")
    agent_repair_attempts: int = Field(default=1, alias="AGENT_REPAIR_ATTEMPTS")
    agent_max_llm_calls_per_decision: int = Field(
        default=2, alias="AGENT_MAX_LLM_CALLS_PER_DECISION"
    )

    # --- Deception persona (mirage persona / host identity) ---------------
    mirage_hostname: str = Field(default="web-prod-01", alias="MIRAGE_PERSONA_HOSTNAME")
    mirage_distribution: str = Field(
        default="Ubuntu 22.04.3 LTS", alias="MIRAGE_PERSONA_DISTRIBUTION"
    )
    mirage_kernel: str = Field(
        default="5.15.0-91-generic", alias="MIRAGE_PERSONA_KERNEL"
    )
    mirage_arch: str = Field(default="x86_64", alias="MIRAGE_PERSONA_ARCH")
    # T3's security invariant (test/test_security.py:
    # test_config_identity_is_fixed_decoy / test_no_host_username_in_any_output):
    # the decoy username must never collide with a plausible host username —
    # it is the fixed T3 decoy "admin", not a real distribution default.
    mirage_username: str = Field(default="admin", alias="MIRAGE_PERSONA_USERNAME")
    mirage_uid: int = Field(default=1000, alias="MIRAGE_PERSONA_UID")
    mirage_gid: int = Field(default=1000, alias="MIRAGE_PERSONA_GID")
    mirage_shell: str = Field(default="/bin/bash", alias="MIRAGE_PERSONA_SHELL")
    mirage_role: str = Field(
        default="application server (nginx + python services)",
        alias="MIRAGE_PERSONA_ROLE",
    )
    mirage_org: str = Field(
        default="internal infra team", alias="MIRAGE_PERSONA_ORGANIZATION"
    )

    model_config = {"populate_by_name": True, "protected_namespaces": ()}

    @classmethod
    def from_env(cls) -> "AgentConfig":
        """Build a config from current environment variables."""
        fields = {}
        for name, field_info in cls.model_fields.items():
            env_name = field_info.alias or name
            raw = os.getenv(env_name)
            if raw is not None:
                if field_info.annotation is int:
                    fields[name] = _env_int(env_name, field_info.default)
                elif field_info.annotation is float:
                    fields[name] = _env_float(env_name, field_info.default)
                elif field_info.annotation is bool:
                    fields[name] = _env_bool(env_name, field_info.default)
                else:
                    fields[name] = raw
        return cls(**fields)

    def persona_overrides(self) -> dict:
        """Persona fields exposed for the PersonaEngine (config-driven values)."""
        return {
            "hostname": self.mirage_hostname,
            "distribution": self.mirage_distribution,
            "kernel": self.mirage_kernel,
            "arch": self.mirage_arch,
            "username": self.mirage_username,
            "uid": self.mirage_uid,
            "gid": self.mirage_gid,
            "shell": self.mirage_shell,
            "system_role": self.mirage_role,
            "organization": self.mirage_org,
        }


_config: Optional[AgentConfig] = None


def get_agent_config() -> AgentConfig:
    """Process-wide config singleton (recomputed per import for tests)."""
    global _config
    if _config is None:
        _config = AgentConfig.from_env()
    return _config


def reset_agent_config() -> None:
    """Test helper: force re-reading the environment on next access."""
    global _config
    _config = None
