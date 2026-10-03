"""Deterministic fallback responses for when the LLM is unavailable.

This module must NEVER inspect the real host. It answers only from
MIRAGE's simulated state (persona + environment + session memory). The
explicit test patches ``os.gethostname``/``os.uname``/``os.getcwd`` to raise
to prove no host introspection is even attempted.

If a command category is not handled here, the fallback returns a generic
realistic "command not found" — the same behavior the old engine had, but now
persona-consistent and explicitly sourced as FALLBACK.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from .models import (
    AgentAction,
    AgentContext,
    AgentDecision,
    DecisionMetadata,
    DecisionSource,
    LatencyProfile,
    SimulatedEffect,
)
from .persona import simulated_date_string, simulated_uptime_string
from .decision import VFS_OWNED_COMMANDS
from .trust import (
    looks_destructive,
    looks_like_privilege_escalation,
)


class DeterministicFallback:
    """Safe, persona-driven responses with no LLM and no host access."""

    def build(self, context: AgentContext, command: str, fallback_reason: str) -> AgentDecision:
        response, action, effect, flags = self._respond(context, command)
        return AgentDecision(
            action=action,
            response=response,
            confidence=0.9,
            reason="deterministic fallback",
            deception_category="none",
            simulated_effect=effect,
            latency_profile=LatencyProfile.FAST,
            security_flags=flags,
            metadata=DecisionMetadata(
                provider="fallback",
                model="deterministic",
                decision_source=DecisionSource.FALLBACK,
                fallback=True,
                fallback_reason=fallback_reason,
            ),
        )

    # -- category handlers ---------------------------------------------------
    def _respond(
        self, context: AgentContext, command: str
    ) -> Tuple[str, AgentAction, SimulatedEffect, List[str]]:
        env = context.environment_state
        user = context.user_information

        parts = (command or "").strip().split()
        base = parts[0].lower() if parts else ""
        args = [a for a in parts[1:] if not a.startswith("-")]

        flags: List[str] = []
        if looks_like_privilege_escalation(command):
            flags.append("PRIVILEGE_ESCALATION_ATTEMPT")
        if looks_destructive(command):
            flags.append("DESTRUCTIVE_COMMAND")

        # containment / sensitive handling (mirrors T3 containment semantics)
        if flags and context.behavior_signals.containment_active:
            return self._permission_denied(command, flags)

        if base in ("whoami",):
            return user.username, AgentAction.RESPOND, SimulatedEffect.NONE, flags
        if base in ("id",):
            return (
                f"uid={user.uid}({user.username}) gid={user.gid}({user.username}) "
                f"groups={user.gid}({user.username}),27(sudo)",
                AgentAction.RESPOND,
                SimulatedEffect.NONE,
                flags,
            )
        if base in ("hostname",):
            return env.hostname, AgentAction.RESPOND, SimulatedEffect.NONE, flags
        if base in ("uname",):
            all_flags = "-a" in parts or any(a.startswith("a") for a in parts[1:])
            return (
                env.uname(all_flags=all_flags),
                AgentAction.RESPOND,
                SimulatedEffect.NONE,
                flags,
            )
        if base in ("pwd",):
            return context.current_working_directory, AgentAction.RESPOND, SimulatedEffect.NONE, flags
        if base in ("uptime",):
            return (
                simulated_uptime_string(env.hostname),
                AgentAction.RESPOND,
                SimulatedEffect.NONE,
                flags,
            )
        if base in ("arch",):
            return env.arch, AgentAction.RESPOND, SimulatedEffect.NONE, flags
        if base in ("date",):
            return simulated_date_string(), AgentAction.RESPOND, SimulatedEffect.NONE, flags
        if base in ("which",):
            if args:
                return (
                    f"which: no {args[0]} in (/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin)",
                    AgentAction.SIMULATE_ERROR,
                    SimulatedEffect.ERROR,
                    flags,
                )
            return "", AgentAction.RESPOND, SimulatedEffect.NONE, flags
        if base in VFS_OWNED_COMMANDS:
            # VFS-owned commands: defer when possible, otherwise generic
            return self._generic_not_found(command, flags)
        if base in ("sudo", "su", "doas", "pkexec"):
            return self._permission_denied(command, flags)
        if looks_like_privilege_escalation(command):
            return self._permission_denied(command, flags)
        if looks_destructive(command):
            return (
                f"{base}: Operation not permitted",
                AgentAction.SIMULATE_PERMISSION_RESULT,
                SimulatedEffect.PERMISSION_DENIED,
                flags,
            )
        # unknown command — generic realistic error, no LLM needed
        return self._generic_not_found(command, flags)

    def _permission_denied(self, command: str, flags: List[str]) -> Tuple[str, AgentAction, SimulatedEffect, List[str]]:
        base = (command or "").split()[0] if command else "command"
        return (
            "Permission denied",
            AgentAction.SIMULATE_PERMISSION_RESULT,
            SimulatedEffect.PERMISSION_DENIED,
            flags,
        )

    def _generic_not_found(self, command: str, flags: List[str]) -> Tuple[str, AgentAction, SimulatedEffect, List[str]]:
        base = (command or "").strip().split()
        name = base[0] if base else "command"
        return (
            f"bash: {name}: command not found",
            AgentAction.SIMULATE_ERROR,
            SimulatedEffect.ERROR,
            flags,
        )
