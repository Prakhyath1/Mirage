"""Typed read-only view models for the MIRAGE dashboard.

These are *projections* of backend data, not a second business-logic
implementation: every field maps 1:1 to a column or event payload produced
by T1 (foundation runtime), T3 (security/VFS pipeline) or T2 (agent
events). Nothing is computed here that a backend hasn't already computed;
fields the backend doesn't provide are ``None`` — never invented.

Security rules baked into the models:
- ``raw_command``/``output``/``details`` are untrusted attacker-derived
  data: displayed escaped, never evaluated or executed.
- No field may carry a secret; adapters strip keys matching the same
  secret-marker set T1's config uses.
- ``confidence`` maps directly from backend threat levels — the dashboard
  never invents severity.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# Data plane tags so the UI can show provenance honestly.
PLANE_FOUNDATION = "foundation"   # T1 runtime store (mirage_foundation.db)
PLANE_PIPELINE = "pipeline"       # T3/T2 deception pipeline (mirage.db)


# Backends' authoritative threat levels -> display confidence. T3 owns the
# thresholds; T4 only renders the mapping it already produces.
THREAT_CONFIDENCE = {"Low": 0.2, "Medium": 0.5, "High": 0.9}
SEVERITY_BY_LEVEL = {"Low": "LOW", "Medium": "MEDIUM", "High": "HIGH"}


@dataclass(frozen=True, slots=True)
class DashboardSession:
    """One session from either plane, normalized for display."""

    session_id: str
    plane: str
    created_at: Optional[float] = None
    last_seen: Optional[float] = None
    status: str = "unknown"
    source_address: str = ""
    username: str = ""
    cwd: str = ""
    command_count: int = 0
    threat_score: int = 0
    threat_level: str = "Low"
    containment_active: bool = False

    @property
    def severity(self) -> str:
        return SEVERITY_BY_LEVEL.get(self.threat_level, "LOW")

    @property
    def confidence(self) -> float:
        return THREAT_CONFIDENCE.get(self.threat_level, 0.2)

    @property
    def is_active(self) -> bool:
        if self.last_seen is None:
            return False
        import time as _time

        return (_time.time() - self.last_seen) < 300.0

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.created_at is None or self.last_seen is None:
            return None
        return max(0.0, self.last_seen - self.created_at)


@dataclass(frozen=True, slots=True)
class DashboardCommand:
    """One attacker command + MIRAGE's simulated response (untrusted data)."""

    session_id: str
    plane: str
    timestamp: Optional[float] = None
    raw_command: str = ""
    output: str = ""
    source: str = ""          # vfs / sandbox / llm / containment / fallback …
    working_directory: str = ""
    command_id: Optional[str] = None
    result_type: Optional[str] = None
    exit_code: Optional[int] = None

    def truncated_output(self, limit: int = 400) -> str:
        return self.output if len(self.output) <= limit else self.output[:limit] + "…"


@dataclass(frozen=True, slots=True)
class DashboardSecurityEvent:
    """One security/audit event from either plane."""

    event_type: str
    session_id: str
    plane: str
    timestamp: Optional[float] = None
    severity: str = "INFO"     # as recorded by the backend
    details: str = ""          # untrusted attacker-derived text
    event_id: Optional[str] = None
    source: str = ""

    @property
    def is_alert_worthy(self) -> bool:
        """Alerts must originate from backend events — this list only names
        backend event types, it does not invent severity."""
        return self.event_type in (
            "HONEYTOKEN_ACCESS",
            "SANDBOX_BLOCK",
            "CONTAINMENT_ACTIVATED",
            "AGENT_GUARDRAIL_REJECT",
            "AGENT_INPUT_FLAG",
            "security.honeytoken_access",
            "security.containment_triggered",
            "security.decision",
            "runtime.error",
        )


@dataclass(frozen=True, slots=True)
class HoneytokenEvent:
    """Canary metadata — never the secret content (T3 contract)."""

    path: str
    tripped: bool = False
    is_honeytoken: bool = True
    last_accessed: Optional[float] = None
    session_id: str = ""
    token_type: str = "file"


@dataclass(frozen=True, slots=True)
class MitreObservation:
    """A MITRE ATT&CK technique observed — derived ONLY by asking T3's
    classifier to categorize commands the backend actually stored. If T3
    later records explicit technique IDs in events, those win."""

    technique_id: str
    technique_name: str
    category: str            # T3 category that produced this observation
    session_ids: tuple = ()
    command_examples: tuple = ()
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    confidence: float = 0.5
    session_count: int = 0

    @property
    def observed_count(self) -> int:
        return len(self.command_examples)


@dataclass(frozen=True, slots=True)
class AgentObservation:
    """A T2 agent decision, as recorded in AGENT_* events (data only)."""

    event_type: str
    session_id: str
    timestamp: Optional[float] = None
    details: str = ""         # bounded, redacted JSON summary from the event
    action: Optional[str] = None
    used_fallback: Optional[bool] = None
    confidence: Optional[float] = None


@dataclass(frozen=True, slots=True)
class SystemHealth:
    """One component's health, as reported by the backend itself."""

    component: str
    status: str               # up / degraded / down / unknown
    detail: str = ""
    latency_ms: Optional[float] = None
    checked_at: Optional[float] = None

    @property
    def is_healthy(self) -> bool:
        return self.status == "up"


@dataclass(frozen=True, slots=True)
class ThreatObservation:
    """Normalized threat-intelligence object (see docs/integration/
    T4_API_CONTRACT.md §3). Every field derives from backend data."""

    observation_id: str
    session_id: Optional[str]
    timestamp: Optional[float]
    category: str
    severity: str
    confidence: float
    technique_id: Optional[str] = None
    evidence: str = ""
    metadata: dict = field(default_factory=dict)
    plane: str = ""

    def to_export_dict(self) -> dict[str, Any]:
        """Whitelisted export shape — only fields defined in the contract."""
        return {
            "observation_id": self.observation_id,
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "technique_id": self.technique_id,
            "evidence": self.evidence,
            "metadata": self.metadata,
        }
