"""AgentEngine: the T2 intelligence pipeline.

    CommandRequest
        -> input normalization
        -> ContextBuilder            (session memory, env state, behavior)
        -> DecisionEngine pre-pass   (deterministic > VFS > LLM)
        -> prompt construction       (trust-tiered, injection-hardened)
        -> LLMProvider                (async, timeout, error-mapped)
        -> structured parser          (strict JSON -> typed draft)
        -> guardrail                  (rule evaluator; future: 2nd model)
        -> AgentDecision              (approved or safe fallback)

The engine emits structured AGENT_* events for T4 observability and never
exposes chain-of-thought. It never blocks the event loop, never executes
host commands, and degrades to deterministic fallback on any LLM failure.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from .config import AgentConfig, get_agent_config
from .context import ContextBuilder
from .decision import DecisionEngine
from .fallback import DeterministicFallback
from .guardrails import GuardrailEngine, RuleGuardrail
from .memory import MemoryStore, get_memory_store, is_ephemeral_session
from .models import (
    AgentAction,
    AgentContext,
    AgentDecision,
    DecisionMetadata,
    DecisionSource,
    EVENT_AGENT_DECISION,
    EVENT_AGENT_FALLBACK,
    EVENT_AGENT_GUARDRAIL_REJECT,
    EVENT_AGENT_INPUT_FLAG,
    LLMRequest,
    MemoryEntryKind,
    SimulatedEffect,
    new_id,
)
from .parser import DecisionParseError, parse_draft, draft_to_decision
from .persona import PersonaEngine
from .prompts import PROMPT_VERSION, build_agent_prompt, build_system
from .providers import LLMProvider, ProviderError, ProviderTimeoutError, build_provider
from .tools import ToolRegistry, get_tool_registry
from .trust import detect_injection, truncate


class EngineMetrics:
    """Lightweight counters exposed to T4 (no chain-of-thought, no secrets)."""

    def __init__(self) -> None:
        self.llm_requests = 0
        self.llm_successes = 0
        self.llm_failures = 0
        self.fallbacks = 0
        self.guardrail_rejections = 0
        self.deterministic_hits = 0
        self.deferrals = 0
        self.total_latency_ms = 0.0

    def snapshot(self) -> Dict[str, Any]:
        return {
            "llm_requests": self.llm_requests,
            "llm_successes": self.llm_successes,
            "llm_failures": self.llm_failures,
            "fallbacks": self.fallbacks,
            "guardrail_rejections": self.guardrail_rejections,
            "deterministic_hits": self.deterministic_hits,
            "deferrals": self.deferrals,
            "avg_llm_latency_ms": round(
                self.total_latency_ms / max(1, self.llm_successes), 2
            ),
        }


class AgentEngine:
    """The stable, typed interface consumed by the runtime (T1)."""

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        provider: Optional[LLMProvider] = None,
        context_builder: Optional[ContextBuilder] = None,
        decision_engine: Optional[DecisionEngine] = None,
        guardrail: Optional[GuardrailEngine] = None,
        memory_store: Optional[MemoryStore] = None,
        tools: Optional[ToolRegistry] = None,
        persona_engine: Optional[PersonaEngine] = None,
        emit_events: bool = True,
    ):
        self._config = config or get_agent_config()
        self.provider = provider or build_provider(self._config)
        self.context_builder = context_builder or ContextBuilder(
            config=self._config
        )
        self.decision_engine = decision_engine or DecisionEngine(self._config)
        self.guardrail = guardrail or GuardrailEngine(self._config)
        self.memory_store = memory_store or get_memory_store()
        self.tools = tools or get_tool_registry()
        self.persona_engine = persona_engine or PersonaEngine(self._config)
        self.fallback = DeterministicFallback()
        self.emit_events = emit_events
        self.metrics = EngineMetrics()

    # -- public API -------------------------------------------------------------
    async def decide(
        self, session_id: str, command: str, command_id: Optional[str] = None
    ) -> AgentDecision:
        """Produce an approved (or safe-fallback) decision for a command."""
        command_id = command_id or new_id("cmd")

        # Stage 1: input normalization + bounding, then deterministic
        # pre-generation security flags (priv-esc/destructive/execution
        # shapes) from the decision engine's preflight — trusted input
        # boundary, never the LLM's self-report.
        normalized, input_flags = self._normalize(command)
        for flag in self.decision_engine.preflight_flags(normalized):
            if flag not in input_flags:
                input_flags.append(flag)
        if input_flags:
            self._emit(
                EVENT_AGENT_INPUT_FLAG,
                session_id,
                {"command_id": command_id, "flags": input_flags},
            )

        # Stage 2: context construction (bounded)
        context = self.context_builder.build(session_id, command_id, command=normalized)

        # Stage 3: deterministic pre-pass (no LLM for owned/identity/denials)
        deterministic = self.decision_engine.decide_deterministic(context, normalized)
        if deterministic is not None:
            self._finalize(deterministic, context, normalized, input_flags)
            self.metrics.deterministic_hits += 1
            if deterministic.action in (AgentAction.DEFER_TO_VFS, AgentAction.DEFER_TO_SECURITY):
                self.metrics.deferrals += 1
            return deterministic

        # Stage 4: LLM path — gap-filling deception only
        decision = await self._generate_decision(context, normalized, command_id)
        self._finalize(decision, context, normalized, input_flags)
        return decision

    # -- pipeline stages ---------------------------------------------------------
    def _normalize(self, command: str) -> tuple:
        """Bound and flag the raw command before anything else.

        Only input-boundary flags (size, injection) live here; behavioral
        shape flags come from ``decision_engine.preflight_flags`` in Stage 1
        so there is one flag vocabulary, not two parsing systems.
        """
        raw = (command or "").strip()
        flags: List[str] = []
        if len(raw) > self._config.agent_max_command_len:
            flags.append("INPUT_TOO_LARGE")
        bounded = truncate(raw, self._config.agent_max_command_len)
        if detect_injection(bounded):
            flags.append("PROMPT_INJECTION_SUSPECTED")
        return bounded, flags

    async def _generate_decision(
        self, context: AgentContext, command: str, command_id: str
    ) -> AgentDecision:
        """LLM path: prompt -> provider -> parse -> guardrail, with bounded repair."""
        prompt = build_agent_prompt(context, command, self._config.agent_max_command_len)
        system = build_system(context)

        # Global call budget and the repair-attempt cap together bound the
        # loop: retries are repair attempts, never an independent mechanism.
        attempts_allowed = max(0, int(self._config.agent_max_llm_calls_per_decision))
        max_repairs = max(0, int(self._config.agent_repair_attempts))
        repairs_used = 0
        last_error = ""
        response_meta: Dict[str, Any] = {}

        for attempt in range(1, attempts_allowed + 1):
            request = LLMRequest(
                prompt=prompt,
                system=system,
                temperature=self._config.llm_temperature,
                max_output_tokens=self._config.llm_max_output,
                json_mode=True,
            )
            self.metrics.llm_requests += 1
            started = time.monotonic()
            try:
                response = await self.provider.generate(request)
            except ProviderError as exc:
                self.metrics.llm_failures += 1
                last_error = f"{exc.kind}"
                # timeout/bad output may justify a bounded repair retry;
                # unavailable servers get no retry (fail fast to fallback)
                if exc.kind in ("timeout", "bad_response") and attempt < attempts_allowed:
                    if repairs_used < max_repairs:
                        repairs_used += 1
                        continue
                break

            latency_ms = (time.monotonic() - started) * 1000.0
            self.metrics.llm_successes += 1
            self.metrics.total_latency_ms += latency_ms
            response_meta = {
                "provider": response.provider,
                "model": response.model,
                "latency_ms": round(latency_ms, 2),
            }

            try:
                draft = parse_draft(response.text)
                decision = draft_to_decision(draft)
            except DecisionParseError as exc:
                last_error = f"parse: {exc}"
                self.metrics.llm_failures += 1
                if exc.retryable and attempt < attempts_allowed and repairs_used < max_repairs:
                    repairs_used += 1
                    continue  # bounded repair attempt
                break

            decision.metadata = DecisionMetadata(
                provider=response.provider,
                model=response.model,
                decision_source=DecisionSource.LLM,
                llm_latency_ms=round(latency_ms, 2),
                prompt_version=PROMPT_VERSION,
                attempts=attempt,
            )
            decision.command_id = command_id
            decision.session_id = context.session_id

            # Guardrail: rule evaluator now; secondary model slot later.
            if self._config.agent_enable_guardrail:
                reviewed = self.guardrail.review(decision, context)
                if reviewed is not decision:
                    self.metrics.guardrail_rejections += 1
                    self.metrics.fallbacks += 1
                    reviewed.metadata = reviewed.metadata.model_copy(
                        update={
                            "provider": response.provider,
                            "model": response.model,
                        }
                    )
                    reviewed.command_id = command_id
                    reviewed.session_id = context.session_id
                    self._emit(
                        EVENT_AGENT_GUARDRAIL_REJECT,
                        context.session_id,
                        {
                            "command_id": command_id,
                            "reasons": decision.guardrail.reasons if decision.guardrail else [],
                        },
                    )
                    return reviewed
            decision.guardrail = self.guardrail.evaluator.evaluate(decision, context) if not decision.guardrail else decision.guardrail
            return decision

        # All attempts exhausted or unretryable failure -> safe fallback
        self.metrics.fallbacks += 1
        fallback = self.fallback.build(context, command, last_error or "llm unavailable")
        fallback.command_id = command_id
        fallback.session_id = context.session_id
        self._emit(
            EVENT_AGENT_FALLBACK,
            context.session_id,
            {"command_id": command_id, "reason": last_error or "llm unavailable"},
        )
        return fallback

    # -- finalization -------------------------------------------------------------
    def _finalize(
        self, decision: AgentDecision, context: AgentContext, command: str,
        input_flags: Optional[List[str]] = None,
    ) -> None:
        """Attach context ids, merge flags, record memory, emit the decision event."""
        decision.session_id = context.session_id
        if input_flags:
            merged = list(decision.security_flags)
            for flag in input_flags:
                if flag not in merged:
                    merged.append(flag)
            decision.security_flags = merged
        decision.metadata.memory_entries_used = len(context.recent_commands)
        decision.metadata.context_chars = sum(
            len(e.summary()) for e in context.recent_commands
        )
        decision.metadata = decision.metadata.model_copy(
            update={"prompt_version": decision.metadata.prompt_version or PROMPT_VERSION}
        )

        memory = (
            self.memory_store.get_ephemeral(context.session_id)
            if is_ephemeral_session(context.session_id)
            else self.memory_store.get(context.session_id)
        )
        memory.record_command(command)
        memory.record_output(decision.response)

        event = {
            "decision_id": decision.decision_id,
            "command_id": decision.command_id,
            "action": decision.action.value,
            "confidence": decision.confidence,
            "deception_category": decision.deception_category,
            "source": decision.metadata.decision_source.value,
            "provider": decision.metadata.provider,
            "model": decision.metadata.model,
            "latency_profile": decision.latency_profile.value,
            "security_flags": decision.security_flags,
        }
        if decision.metadata.fallback:
            event["fallback_reason"] = decision.metadata.fallback_reason
        self._emit(EVENT_AGENT_DECISION, context.session_id, event)

    def _emit(self, event_type: str, session_id: str, details: Dict[str, Any]) -> None:
        """Structured event emission for T4 (JSON; never chain-of-thought).

        Ephemeral (session-less) callers get no persistent event rows: they
        have no durable identity, and a keyed row would let one caller's
        activity appear in another's observability view.
        """
        if not self.emit_events:
            return
        if is_ephemeral_session(session_id):
            return
        try:
            import json

            from app import db

            db.log_event(session_id, event_type, json.dumps(details))
        except Exception:
            # Observability must never break the request path.
            pass

    # -- introspection ----------------------------------------------------------
    def metrics_snapshot(self) -> Dict[str, Any]:
        snap = self.metrics.snapshot()
        snap["guardrail"] = {
            "approvals": self.guardrail.approvals,
            "rejections": self.guardrail.rejections,
        }
        return snap
