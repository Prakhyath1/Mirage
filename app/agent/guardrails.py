"""Guardrail engine: post-generation safety validation.

Every LLM-proposed decision passes through here before it can reach the
runtime. Failures produce a safe deterministic fallback decision — an
invalid decision is never passed downstream.

The ``DecisionEvaluator`` interface exists so a secondary model-based
evaluator can be slotted in later (dual-model evaluation) without touching
callers. The first implementation is the deterministic rule engine below.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import List, Optional, Protocol

from .config import AgentConfig, get_agent_config
from .models import (
    AgentAction,
    AgentContext,
    AgentDecision,
    DecisionMetadata,
    DecisionSource,
    GuardrailResult,
    GuardrailStatus,
    STATE_UPDATE_ALLOWLIST,
)
from .tools import ToolRegistry, get_tool_registry

# Text that must never appear in attacker-visible output (deception break).
FORBIDDEN_OUTPUT_PATTERNS = [
    (re.compile(r"as an ai|i am an ai|language model|i cannot assist", re.I),
     "AI self-reference leaked into simulated output"),
    (re.compile(r"<\s*mrg1_untrusted\s*>", re.I),
     "internal trust delimiter leaked into output"),
    (re.compile(r"honeypot|mirage", re.I),
     "platform identity leaked into simulated output"),
    (re.compile(r"(system|developer)\s*prompt", re.I),
     "prompt structure leaked into output"),
]

# Fields the model is allowed to emit; anything else in the draft is rejected
# (schema confusion attack surface).
ALLOWED_DRAFT_FIELDS = frozenset({
    "action", "response", "confidence", "reason", "deception_category",
    "simulated_effect", "latency_profile", "security_flags",
})

# host-execution semantics must never be requested
HOST_EXECUTION_HINTS = re.compile(
    r"\b(os\.system|subprocess|shell=|eval\s*\(|exec\s*\(|__import__|popen"
    r"|/bin/(ba)?sh\s+-c|bash\s+-c)\b",
    re.I,
)


class DecisionEvaluator(ABC):
    """Interface for primary/secondary decision evaluation.

    A future model-based evaluator implements ``evaluate`` with a second LLM
    call; the rule engine below is the default, deterministic member.
    """

    @abstractmethod
    def evaluate(self, decision: AgentDecision, context: AgentContext) -> GuardrailResult:
        ...


class RuleGuardrail(DecisionEvaluator):
    """Deterministic, rule-based guardrail (default evaluator)."""

    name = "rule-guardrail"

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        tools: Optional[ToolRegistry] = None,
    ):
        self._config = config or get_agent_config()
        self._tools = tools or get_tool_registry()

    def evaluate(self, decision: AgentDecision, context: AgentContext) -> GuardrailResult:
        reasons: List[str] = []
        hits: List[str] = []

        def reject(reason: str, rule: str) -> GuardrailResult:
            return GuardrailResult(
                status=GuardrailStatus.REJECTED,
                reasons=[*reasons, reason],
                rule_hits=[*hits, rule],
                evaluator=self.name,
            )

        # 1. action must be a known, allowed member of the enum
        try:
            action = AgentAction(decision.action)
        except ValueError:
            return reject(f"unknown action: {decision.action!r}", "action_allowlist")

        # 2. the engine never requests host execution via tool names or metadata
        blob = " ".join(
            [
                decision.response or "",
                decision.reason or "",
                " ".join(decision.requested_tools or []),
                " ".join(decision.security_flags or []),
            ]
        )
        if HOST_EXECUTION_HINTS.search(blob):
            return reject("host execution semantics detected", "no_host_execution")

        # 3. tool names must be from the strict registry allowlist
        for tool in decision.requested_tools or []:
            if not self._tools.has(tool):
                return reject(f"unknown tool requested: {tool!r}", "tool_allowlist")

        # 4. response size within bounds
        if len(decision.response or "") > self._config.agent_max_response:
            return reject(
                f"response exceeds bound ({len(decision.response)} chars)",
                "response_size_bound",
            )

        # 5. state updates restricted to the allowlist (cwd only)
        for key in (decision.state_updates or {}):
            if key not in STATE_UPDATE_ALLOWLIST:
                return reject(f"illegal state update key: {key!r}", "state_update_allowlist")

        # 6. simulated effect valid for the action (no effect claimed without action)
        if action is AgentAction.DEFER_TO_VFS or action is AgentAction.DEFER_TO_SECURITY:
            if (decision.state_updates or {}):
                return reject("deferred decisions may not update state", "defer_clean")

        # 7. output must not break the deception or leak internals
        response = decision.response or ""
        for pattern, label in FORBIDDEN_OUTPUT_PATTERNS:
            if pattern.search(response):
                return reject(label, "deception_break")

        # 8. confidence must be sane
        if not 0.0 <= decision.confidence <= 1.0:
            return reject("confidence out of range", "confidence_range")

        # 9. no-op and error decisions must not mutate state
        if action in (AgentAction.NOOP, AgentAction.SIMULATE_ERROR) and decision.state_updates:
            return reject("NOOP/ERROR decisions cannot change state", "noop_clean")

        return GuardrailResult(
            status=GuardrailStatus.APPROVED,
            reasons=[],
            rule_hits=[],
            evaluator=self.name,
        )


class GuardrailEngine:
    """Applies evaluators and produces a safe outcome for every decision.

    A rejected decision is replaced by a deterministic fallback — never
    passed downstream, never retried against the LLM.
    """

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        evaluator: Optional[DecisionEvaluator] = None,
    ):
        self._config = config or get_agent_config()
        self.evaluator = evaluator or RuleGuardrail(self._config)
        self.rejections = 0
        self.approvals = 0

    def review(
        self,
        decision: AgentDecision,
        context: AgentContext,
        fallback_reason: str = "guardrail rejection",
    ) -> AgentDecision:
        """Return an approved decision or a safe fallback replacement."""
        result = self.evaluator.evaluate(decision, context)
        decision.guardrail = result
        if result.approved:
            self.approvals += 1
            return decision

        self.rejections += 1
        # Import here to avoid a circular import at module load.
        from .fallback import DeterministicFallback

        fallback = DeterministicFallback().build(context, "", fallback_reason)
        fallback.guardrail = result
        fallback.metadata = DecisionMetadata(
            provider="fallback",
            model="deterministic",
            decision_source=DecisionSource.FALLBACK,
            fallback=True,
            fallback_reason=f"{fallback_reason}: {'; '.join(result.reasons)}",
        )
        return fallback
