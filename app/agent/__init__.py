"""T2 — Agentic Deception Intelligence Engine for MIRAGE.

Public API (stable for T1/T3/T4 consumers):

    engine = get_agent_engine()
    decision = await engine.decide(session_id, command)
    plan = build_response_plan(decision)

Everything else is implementation detail. The engine never executes
attacker input on the host; it only produces typed, guardrail-approved
simulated decisions.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .config import AgentConfig, get_agent_config, reset_agent_config
from .engine import AgentEngine, EngineMetrics
from .models import (
    AgentAction,
    AgentContext,
    AgentDecision,
    AgentMemoryEntry,
    BehaviorSignals,
    DecisionMetadata,
    DecisionSource,
    EnvironmentState,
    GuardrailResult,
    GuardrailStatus,
    LatencyProfile,
    MemoryEntryKind,
    PersonaState,
    ResponsePlan,
    SimulatedEffect,
    SimulatedUser,
    STATE_UPDATE_ALLOWLIST,
    VFSResult,
)
from .providers import LLMProvider, MockProvider, OllamaProvider, build_provider
from .trust import detect_injection, wrap_untrusted

__all__ = [
    "AgentEngine",
    "EngineMetrics",
    "AgentConfig",
    "get_agent_config",
    "reset_agent_config",
    "AgentAction",
    "AgentContext",
    "AgentDecision",
    "AgentMemoryEntry",
    "BehaviorSignals",
    "DecisionMetadata",
    "DecisionSource",
    "EnvironmentState",
    "GuardrailResult",
    "GuardrailStatus",
    "LatencyProfile",
    "MemoryEntryKind",
    "PersonaState",
    "ResponsePlan",
    "SimulatedEffect",
    "SimulatedUser",
    "STATE_UPDATE_ALLOWLIST",
    "VFSResult",
    "LLMProvider",
    "MockProvider",
    "OllamaProvider",
    "build_provider",
    "detect_injection",
    "wrap_untrusted",
    "get_agent_engine",
    "reset_agent_engine",
    "build_response_plan",
]


def build_response_plan(decision: AgentDecision) -> ResponsePlan:
    """Translate an approved AgentDecision into the runtime's action plan.

    T1's router consumes this: DEFER_TO_VFS routes to T3's VFS; DEFER_TO_SECURITY
    routes to T3's containment; everything else yields ``output`` directly.
    """
    defer = None
    if decision.action is AgentAction.DEFER_TO_VFS:
        defer = "vfs"
    elif decision.action is AgentAction.DEFER_TO_SECURITY:
        defer = "security"

    new_cwd = None
    if "cwd" in (decision.state_updates or {}):
        new_cwd = decision.state_updates["cwd"]

    events: List[Dict[str, Any]] = []
    if decision.security_flags:
        events.append(
            {
                "event_type": "AGENT_SECURITY_FLAG",
                "session_id": decision.session_id,
                "details": {"flags": decision.security_flags},
            }
        )

    return ResponsePlan(
        session_id=decision.session_id,
        decision_id=decision.decision_id,
        action=decision.action,
        output=decision.response,
        new_cwd=new_cwd,
        defer_to=defer,
        security_flags=decision.security_flags,
        latency_profile=decision.latency_profile,
        simulated_effect=decision.simulated_effect,
        confidence=decision.confidence,
        events=events,
        metadata=decision.metadata,
    )


_engine: Optional[AgentEngine] = None


def get_agent_engine() -> AgentEngine:
    """Process-wide engine singleton. Tests inject their own via the class."""
    global _engine
    if _engine is None:
        _engine = AgentEngine()
    return _engine


def reset_agent_engine() -> None:
    """Test helper: drop the singleton so config changes take effect."""
    global _engine
    _engine = None
