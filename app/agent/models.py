"""Typed contracts for the T2 Agentic Deception Intelligence Engine.

These models are the stable, serializable boundary between T2 and the rest of
MIRAGE (T1 runtime, T3 simulation/security layer, T4 dashboard).

Security invariant: nothing in this module can express a real host operation.
``AgentAction`` only describes simulated outcomes or a handoff to another
MIRAGE subsystem, and state updates are restricted to an allowlist owned here.
"""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

# Keys the agent is allowed to propose changing in the session state.
# T1 owns the authoritative session row; "cwd" mirrors db.update_session(cwd=).
STATE_UPDATE_ALLOWLIST = frozenset({"cwd"})

# Event types emitted to T1's events table (db.log_event) for T4 visibility.
EVENT_AGENT_DECISION = "AGENT_DECISION"
EVENT_AGENT_FALLBACK = "AGENT_FALLBACK"
EVENT_AGENT_GUARDRAIL_REJECT = "AGENT_GUARDRAIL_REJECT"
EVENT_AGENT_INPUT_FLAG = "AGENT_INPUT_FLAG"

# Security flags the agent may attach to a decision (observability only;
# scoring/threat levels stay owned by T3's behavior engine).
FLAG_INPUT_TOO_LARGE = "INPUT_TOO_LARGE"
FLAG_PROMPT_INJECTION_SUSPECTED = "PROMPT_INJECTION_SUSPECTED"
FLAG_PRIVILEGE_ESCALATION_ATTEMPT = "PRIVILEGE_ESCALATION_ATTEMPT"
FLAG_DESTRUCTIVE_COMMAND = "DESTRUCTIVE_COMMAND"
FLAG_DECEPTION_BREAK = "DECEPTION_BREAK"


def new_id(prefix: str) -> str:
    """Short unique id for commands/decisions (used in event metadata)."""
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def utc_now() -> float:
    return time.time()


class AgentAction(StrEnum):
    """Constrained action vocabulary.

    No member maps to a host operation. ``SIMULATE_*`` members describe output
    the *simulated* environment should show; ``DEFER_*`` members hand control
    to another MIRAGE subsystem.
    """

    RESPOND = "RESPOND"
    SIMULATE_FILE_OPERATION = "SIMULATE_FILE_OPERATION"
    SIMULATE_DIRECTORY_OPERATION = "SIMULATE_DIRECTORY_OPERATION"
    SIMULATE_PROCESS_QUERY = "SIMULATE_PROCESS_QUERY"
    SIMULATE_NETWORK_QUERY = "SIMULATE_NETWORK_QUERY"
    SIMULATE_PERMISSION_RESULT = "SIMULATE_PERMISSION_RESULT"
    SIMULATE_ERROR = "SIMULATE_ERROR"
    DEFER_TO_VFS = "DEFER_TO_VFS"
    DEFER_TO_SECURITY = "DEFER_TO_SECURITY"
    NOOP = "NOOP"


class LatencyProfile(StrEnum):
    """Intended response-timing class. Metadata only: T2 never sleeps."""

    FAST = "FAST"
    NORMAL = "NORMAL"
    SLOW = "SLOW"


class SimulatedEffect(StrEnum):
    """What the decision pretends happened inside the simulated host."""

    NONE = "NONE"
    FILE_READ = "FILE_READ"
    FILE_WRITE = "FILE_WRITE"
    FILE_DELETE = "FILE_DELETE"
    DIRECTORY_CHANGE = "DIRECTORY_CHANGE"
    DIRECTORY_LISTING = "DIRECTORY_LISTING"
    PROCESS_REVEAL = "PROCESS_REVEAL"
    NETWORK_REVEAL = "NETWORK_REVEAL"
    SERVICE_REVEAL = "SERVICE_REVEAL"
    CREDENTIAL_REVEAL = "CREDENTIAL_REVEAL"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    ERROR = "ERROR"


class MemoryEntryKind(StrEnum):
    COMMAND = "COMMAND"
    OUTPUT = "OUTPUT"
    FACT = "FACT"
    OBSERVATION = "OBSERVATION"
    SECURITY_EVENT = "SECURITY_EVENT"


class GuardrailStatus(StrEnum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class DecisionSource(StrEnum):
    """Where the final decision came from (observability for T4)."""

    DETERMINISTIC = "DETERMINISTIC"  # rule/persona handler, no LLM call
    LLM = "LLM"  # model-generated, guardrail-approved
    FALLBACK = "FALLBACK"  # safe deterministic fallback (LLM failed/rejected)
    DEFERRED = "DEFERRED"  # handed off to VFS/security


class AgentMemoryEntry(BaseModel):
    """One bounded-memory record about the session."""

    timestamp: float = Field(default_factory=utc_now)
    kind: MemoryEntryKind = MemoryEntryKind.COMMAND
    command: Optional[str] = None
    output_summary: Optional[str] = None
    fact: Optional[str] = None

    def summary(self) -> str:
        if self.kind is MemoryEntryKind.COMMAND:
            return self.command or ""
        if self.kind is MemoryEntryKind.OUTPUT:
            return self.output_summary or ""
        return self.fact or ""


class SimulatedUser(BaseModel):
    """Apparent identity the attacker is interacting as."""

    username: str = "ubuntu"
    uid: int = 1000
    gid: int = 1000
    home: str = "/home/ubuntu"
    shell: str = "/bin/bash"
    apparent_privilege: str = "unprivileged user"

    @property
    def is_root(self) -> bool:
        return self.uid == 0


class EnvironmentState(BaseModel):
    """Abstract simulated host state.

    T3 owns the authoritative environment/VFS. T2 consumes this schema;
    when T3 cannot populate it, T2 uses persona-derived values and marks
    ``source="fallback_persona"`` so nothing is presented as authoritative
    when it is not (anti-hallucination contract).
    """

    model_config = ConfigDict(validate_assignment=True)

    hostname: str = "web-prod-01"
    os_name: str = "Ubuntu 22.04.3 LTS"
    kernel: str = "5.15.0-91-generic"
    arch: str = "x86_64"
    user: str = "ubuntu"
    cwd: str = "/home/ubuntu"
    home: str = "/home/ubuntu"
    services: List[str] = Field(default_factory=list)
    processes: List[str] = Field(default_factory=list)
    interfaces: List[str] = Field(default_factory=list)
    installed_packages: List[str] = Field(default_factory=list)
    source: str = Field(
        default="fallback_persona",
        pattern=r"^(t3|fallback_persona)$",
    )

    def uname(self, all_flags: bool = False) -> str:
        """Deterministic ``uname`` output derived from simulated state only."""
        base = f"{self.kernel} #1 SMP {self.os_name} {self.arch}"
        if all_flags:
            return (
                f"Linux {self.hostname} {self.kernel} "
                f"#101-Ubuntu SMP PREEMPT_DYNAMIC x86_64 "
                f"GNU/Linux"
            )
        return base


class PersonaState(BaseModel):
    """Deception persona: the coherent identity of the simulated host."""

    hostname: str
    distribution: str
    kernel: str
    arch: str = "x86_64"
    username: str
    uid: int
    gid: int
    home: str
    shell: str
    system_role: str
    organization: str
    services: List[str] = Field(default_factory=list)
    packages: List[str] = Field(default_factory=list)
    filesystem_style: str = "standard Ubuntu Server layout"
    response_style: str = (
        "terse, realistic bash output; no markdown, no commentary, no AI voice"
    )


class BehaviorSignals(BaseModel):
    """T3-owned behavior context, consumed by T2.

    T2 reads these to adapt deception (e.g. raise sensitivity); it never
    recomputes threat scores itself.
    """

    risk_level: str = "Low"
    threat_score: int = 0
    containment_active: bool = False
    detected_categories: List[str] = Field(default_factory=list)


class AgentContext(BaseModel):
    """Bounded context for one decision.

    Deliberately small: built from the session row, persona, bounded memory
    and T3 signals — never the whole database or filesystem.
    """

    session_id: str
    command_id: str
    current_working_directory: str
    user_information: SimulatedUser = Field(default_factory=SimulatedUser)
    recent_commands: List[AgentMemoryEntry] = Field(default_factory=list)
    environment_state: EnvironmentState = Field(default_factory=EnvironmentState)
    behavior_signals: BehaviorSignals = Field(default_factory=BehaviorSignals)
    persona: PersonaState
    available_simulated_tools: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def virtual_host_information(self) -> EnvironmentState:
        """Alias kept for contract readability with the architecture docs."""
        return self.environment_state


class GuardrailResult(BaseModel):
    """Outcome of the post-generation safety validation."""

    status: GuardrailStatus
    reasons: List[str] = Field(default_factory=list)
    rule_hits: List[str] = Field(default_factory=list)
    evaluator: str = "rule-based"
    checked_at: float = Field(default_factory=utc_now)

    @property
    def approved(self) -> bool:
        return self.status is GuardrailStatus.APPROVED


class DecisionMetadata(BaseModel):
    """Operational metadata exposed to T4. Never contains chain-of-thought."""

    provider: str = "unknown"
    model: str = "unknown"
    decision_source: DecisionSource = DecisionSource.LLM
    fallback: bool = False
    fallback_reason: str = ""
    llm_latency_ms: Optional[float] = None
    prompt_version: str = ""
    attempts: int = 0  # LLM calls made for this decision (bounded)
    memory_entries_used: int = 0
    context_chars: int = 0


class AgentDecision(BaseModel):
    """The central structured output of the T2 intelligence engine."""

    model_config = ConfigDict(validate_assignment=True)

    decision_id: str = Field(default_factory=lambda: new_id("dec"))
    command_id: str = ""
    session_id: str = ""
    action: AgentAction
    response: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reason: str = ""
    deception_category: str = "none"
    simulated_effect: SimulatedEffect = SimulatedEffect.NONE
    state_updates: Dict[str, str] = Field(default_factory=dict)
    requested_tools: List[str] = Field(default_factory=list)
    security_flags: List[str] = Field(default_factory=list)
    latency_profile: LatencyProfile = LatencyProfile.NORMAL
    guardrail: Optional[GuardrailResult] = None
    metadata: DecisionMetadata = Field(default_factory=DecisionMetadata)

    def approved_by_guardrail(self) -> bool:
        return self.guardrail is not None and self.guardrail.approved


class ResponsePlan(BaseModel):
    """What downstream systems (T1 runtime / T3 simulation) should do.

    ``defer_to`` is ``"vfs"`` or ``"security"`` when the decision handed off;
    T1's router decides how to act on the handoff.
    """

    session_id: str
    decision_id: str
    action: AgentAction
    output: str
    exit_code: int = 0
    new_cwd: Optional[str] = None
    defer_to: Optional[str] = None
    security_flags: List[str] = Field(default_factory=list)
    latency_profile: LatencyProfile = LatencyProfile.NORMAL
    simulated_effect: SimulatedEffect = SimulatedEffect.NONE
    confidence: float = 0.0
    events: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: DecisionMetadata = Field(default_factory=DecisionMetadata)


class VFSResult(BaseModel):
    """Consumption schema for T3 VFS output (mirrors vfs.execute_vfs_command)."""

    handled: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    new_cwd: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class LLMRequest(BaseModel):
    """A single structured call to a language-model provider."""

    prompt: str
    system: Optional[str] = None
    temperature: float = 0.2
    max_output_tokens: int = 512
    json_mode: bool = True
    request_id: str = Field(default_factory=lambda: new_id("llm"))


class LLMResponse(BaseModel):
    """A provider's raw textual answer, before structured parsing."""

    text: str
    provider: str = "unknown"
    model: str = "unknown"
    latency_ms: float = 0.0
    metadata: Dict[str, Any] = Field(default_factory=dict)
