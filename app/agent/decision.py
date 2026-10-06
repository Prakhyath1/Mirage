"""Decision engine: chooses how a command should be handled.

Priority model (per the T2 brief):
    DETERMINISTIC SIMULATION  >  T3 VFS/security result  >  AGENT DECEPTION

So:
  * commands T3's VFS already owns (ls, pwd, cd, cat, echo, mkdir, rm, touch,
    nmap) are deferred to it — the LLM never overrides deterministic output
  * persona/deterministic identity commands (whoami, id, hostname, uname,
    uptime, arch) are answered from simulated state with no LLM call
  * everything else is contextual deception, handled by the LLM path with
    structured output and guardrails

Registered as declarative categories (data, not if-chains) so T3/T4 can
extend the behavior without editing engine internals.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional, Tuple

from .config import AgentConfig, get_agent_config
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
from .trust import (
    detect_execution_attempt,
    looks_destructive,
    looks_like_privilege_escalation,
)

# T3's VFS-owned commands, mirrored for T2's deferral routing.
#
# Authoritative source: the dispatch chain in ``app/vfs.py``
# (``execute_vfs_command`` — pwd/ls/cd/cat/echo/mkdir/rm/touch/nmap). T3's
# module exports no command list, and T2 may not modify T3 files to add
# one, so this mirror is the architectural price of the task boundary.
# A regression test (``test_decision.VfsOwnershipSyncTest``) derives the
# authoritative set from ``app/vfs.py`` source and fails when the mirror
# diverges, so T3 adding a command cannot silently strand it in T2's LLM
# path.
# Commands T3's VFS dispatch answers deterministically (app/vfs/__init__.py
# _run_builtin handler dict). T2 always defers these — the merged pipeline
# routes VFS-first, so T3's handlers (and their decoy identity) win.
# Kept in sync by tests/agent/test_decision.py::VfsOwnershipSyncTest, which
# derives the authoritative set from T3's dispatch chain.
VFS_OWNED_COMMANDS = [
    "ls", "pwd", "cd", "cat", "echo", "mkdir", "rm", "touch", "nmap",
    "whoami", "id", "uname",
]


class CommandCategory:
    """A declarative command category (data-driven, extensible)."""

    def __init__(
        self,
        name: str,
        matcher: Callable[[List[str], str], bool],
        handler: Callable[[AgentContext, str], AgentDecision],
        description: str = "",
    ):
        self.name = name
        self.matcher = matcher
        self.handler = handler
        self.description = description


def _first_word(command: str) -> str:
    parts = (command or "").strip().split()
    return parts[0] if parts else ""


def _base_decision(
    context: AgentContext,
    action: AgentAction,
    response: str,
    effect: SimulatedEffect,
    reason: str,
    category: str,
    confidence: float = 0.95,
    flags: Optional[List[str]] = None,
    state_updates: Optional[Dict[str, str]] = None,
) -> AgentDecision:
    return AgentDecision(
        action=action,
        response=response,
        confidence=confidence,
        reason=reason,
        deception_category=category,
        simulated_effect=effect,
        state_updates=state_updates or {},
        security_flags=flags or [],
        latency_profile=LatencyProfile.FAST,
        metadata=DecisionMetadata(
            provider="deterministic",
            model="deterministic",
            decision_source=DecisionSource.DETERMINISTIC,
            attempts=0,
        ),
    )


class DecisionEngine:
    """Routes a command through the priority model."""

    def __init__(self, config: Optional[AgentConfig] = None):
        self._config = config or get_agent_config()
        self._categories: List[CommandCategory] = []
        self._register_defaults()

    # -- registry -------------------------------------------------------------
    def register(self, category: CommandCategory) -> None:
        """Register a category (first match wins, in registration order)."""
        self._categories.append(category)

    def category_names(self) -> List[str]:
        return [c.name for c in self._categories]

    # -- default categories -----------------------------------------------------
    def _register_defaults(self) -> None:
        # Commands T3's VFS owns — always deferred, never LLM-generated.
        # The mirrored list lives at module level (VFS_OWNED_COMMANDS) so
        # the ownership-sync regression test exercises the same constant.
        vfs_commands = VFS_OWNED_COMMANDS

        def is_vfs(parts: List[str], raw: str) -> bool:
            return bool(parts) and parts[0] in vfs_commands

        self.register(
            CommandCategory(
                name="vfs_owned",
                matcher=is_vfs,
                handler=self._defer_vfs,
                description="commands owned by T3's virtual filesystem",
            )
        )

        # Identity/info commands answered deterministically from persona state.
        # (whoami/id/uname are absent: T3's VFS owns them — see the
        # vfs_owned category, registered above, which claims them first.)
        identity_commands = {
            "hostname", "uptime", "arch", "date",
        }

        def is_identity(parts: List[str], raw: str) -> bool:
            return bool(parts) and parts[0] in identity_commands

        self.register(
            CommandCategory(
                name="identity",
                matcher=is_identity,
                handler=self._identity_handler,
                description="identity/system-info commands answered from simulated state",
            )
        )

        # Privilege escalation attempts — deterministic permission denial.
        def is_priv_esc(parts: List[str], raw: str) -> bool:
            return looks_like_privilege_escalation(raw)

        self.register(
            CommandCategory(
                name="privilege_escalation",
                matcher=is_priv_esc,
                handler=self._priv_esc_handler,
                description="sudo/su-style privilege escalation denied deterministically",
            )
        )

        # Destructive shapes — deterministic denial, flagged.
        def is_destructive(parts: List[str], raw: str) -> bool:
            return looks_destructive(raw)

        self.register(
            CommandCategory(
                name="destructive",
                matcher=is_destructive,
                handler=self._destructive_handler,
                description="destructive command shapes denied deterministically",
            )
        )

    # -- category handlers -----------------------------------------------------
    def _defer_vfs(self, context: AgentContext, command: str) -> AgentDecision:
        return _base_decision(
            context,
            AgentAction.DEFER_TO_VFS,
            "",
            SimulatedEffect.NONE,
            "command owned by the virtual filesystem",
            "none",
        )

    def _identity_handler(self, context: AgentContext, command: str) -> AgentDecision:
        parts = command.strip().split()
        base = parts[0].lower() if parts else ""
        env = context.environment_state
        user = context.user_information
        response = {
            "hostname": env.hostname,
            "uptime": simulated_uptime_string(env.hostname),
            "arch": env.arch,
            "date": simulated_date_string(),
        }[base]
        return _base_decision(
            context,
            AgentAction.RESPOND,
            response,
            SimulatedEffect.NONE,
            f"identity command: {base}",
            "reconnaissance",
            confidence=0.99,
        )

    def _priv_esc_handler(self, context: AgentContext, command: str) -> AgentDecision:
        base = _first_word(command)
        return _base_decision(
            context,
            AgentAction.SIMULATE_PERMISSION_RESULT,
            "sudo: permission denied\nSorry, try again." if base == "sudo"
            else "Permission denied",
            SimulatedEffect.PERMISSION_DENIED,
            "privilege escalation attempt denied",
            "privilege_escalation",
            flags=["PRIVILEGE_ESCALATION_ATTEMPT"],
        )

    def _destructive_handler(self, context: AgentContext, command: str) -> AgentDecision:
        base = _first_word(command)
        return _base_decision(
            context,
            AgentAction.SIMULATE_PERMISSION_RESULT,
            f"{base}: Operation not permitted" if base else "Operation not permitted",
            SimulatedEffect.PERMISSION_DENIED,
            "destructive command denied",
            "obfuscated",
            flags=["DESTRUCTIVE_COMMAND"],
        )

    # -- entry point -------------------------------------------------------------
    def classify(self, command: str) -> Tuple[Optional[CommandCategory], List[str]]:
        """Match a command against categories; return (category, parts)."""
        raw = command or ""
        parts = raw.strip().split()
        for category in self._categories:
            try:
                if category.matcher(parts, raw):
                    return category, parts
            except Exception:
                continue
        return None, parts

    def decide_deterministic(
        self, context: AgentContext, command: str
    ) -> Optional[AgentDecision]:
        """Deterministically answer, or None when the LLM path is needed."""
        category, parts = self.classify(command)
        if category is None:
            return None
        decision = category.handler(context, command)
        decision.command_id = context.command_id
        decision.session_id = context.session_id
        return decision

    def preflight_flags(self, command: str) -> List[str]:
        """Security flags derivable before any generation (observability)."""
        flags: List[str] = []
        if looks_like_privilege_escalation(command):
            flags.append("PRIVILEGE_ESCALATION_ATTEMPT")
        if looks_destructive(command):
            flags.append("DESTRUCTIVE_COMMAND")
        if detect_execution_attempt(command):
            flags.append("DECEPTION_BREAK")
        return flags
