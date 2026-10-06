"""Structured output parser: strict LLM text -> typed draft decision.

Never trusts raw model text:
  * JSON is extracted defensively (handles stray markdown fences) but must
    then validate against a strict field allowlist
  * unknown fields are rejected (schema-confusion defense)
  * all failures raise ``DecisionParseError`` — the engine catches, logs,
    applies at most one bounded repair attempt, then falls back safely
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from .guardrails import ALLOWED_DRAFT_FIELDS
from .models import (
    AgentAction,
    AgentDecision,
    LatencyProfile,
    SimulatedEffect,
)

# Enum member sets used for strict value validation before pydantic sees them.
_ACTIONS = {a.value for a in AgentAction}
_EFFECTS = {e.value for e in SimulatedEffect}
_LATENCY = {p.value for p in LatencyProfile}
_FLAGS = {
    "PROMPT_INJECTION_SUSPECTED",
    "PRIVILEGE_ESCALATION_ATTEMPT",
    "DESTRUCTIVE_COMMAND",
}

# Draft schema: the exact keys the model is allowed to produce.
DRAFT_FIELDS = frozenset(ALLOWED_DRAFT_FIELDS)


class DecisionParseError(Exception):
    """Raised when model output cannot be parsed into a valid draft."""

    def __init__(self, message: str, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


def extract_json(text: str) -> str:
    """Extract the JSON object from raw model output.

    Tolerates markdown fences and stray prose while refusing anything that
    is not a single JSON object.
    """
    if not text or not text.strip():
        raise DecisionParseError("empty model output", retryable=True)

    cleaned = text.strip()
    # strip markdown fences if present
    if cleaned.startswith("```"):
        first_newline = cleaned.find("\n")
        if first_newline == -1:
            raise DecisionParseError("model output is a code fence with no content")
        cleaned = cleaned[first_newline + 1 :]
        if cleaned.rstrip().endswith("```"):
            cleaned = cleaned.rstrip()[:-3]

    # find the outermost JSON object
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise DecisionParseError("no JSON object found in model output", retryable=True)
    return cleaned[start : end + 1]


def parse_draft(raw: str) -> Dict[str, Any]:
    """Parse raw model text into a validated draft dictionary."""
    candidate = extract_json(raw)
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise DecisionParseError(f"invalid JSON: {exc.msg}", retryable=True) from None

    if not isinstance(data, dict):
        raise DecisionParseError("model output is not a JSON object", retryable=True)

    # strict allowlist: unknown fields mean schema confusion — reject
    unknown = set(data.keys()) - DRAFT_FIELDS
    if unknown:
        raise DecisionParseError(
            f"unknown fields in draft: {sorted(unknown)}", retryable=False
        )

    # required fields
    action = data.get("action")
    if not isinstance(action, str) or action not in _ACTIONS:
        raise DecisionParseError(
            f"invalid or missing action: {action!r}", retryable=False
        )
    if "response" not in data:
        raise DecisionParseError("draft missing response field", retryable=False)
    if not isinstance(data.get("response"), str):
        raise DecisionParseError("response must be a string", retryable=False)

    # typed validation with bounded coercion
    confidence = data.get("confidence", 0.5)
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
        raise DecisionParseError("confidence must be numeric", retryable=False)
    data["confidence"] = max(0.0, min(1.0, float(confidence)))

    effect = data.get("simulated_effect", "NONE")
    if effect not in _EFFECTS:
        raise DecisionParseError(f"invalid simulated_effect: {effect!r}", retryable=False)
    data["simulated_effect"] = effect

    latency = data.get("latency_profile", "NORMAL")
    if latency not in _LATENCY:
        raise DecisionParseError(f"invalid latency_profile: {latency!r}", retryable=False)
    data["latency_profile"] = latency

    flags = data.get("security_flags", [])
    if not isinstance(flags, list):
        raise DecisionParseError("security_flags must be a list", retryable=False)
    data["security_flags"] = [str(f) for f in flags]

    for string_field in ("reason", "deception_category"):
        value = data.get(string_field, "")
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise DecisionParseError(f"{string_field} must be a string", retryable=False)
        data[string_field] = value

    return data


def draft_to_decision(draft: Dict[str, Any]) -> AgentDecision:
    """Build an AgentDecision from a validated draft (pydantic enforces types)."""
    return AgentDecision(
        action=AgentAction(draft["action"]),
        response=draft["response"],
        confidence=float(draft.get("confidence", 0.5)),
        reason=draft.get("reason", ""),
        deception_category=draft.get("deception_category", "none"),
        simulated_effect=SimulatedEffect(draft.get("simulated_effect", "NONE")),
        latency_profile=LatencyProfile(draft.get("latency_profile", "NORMAL")),
        security_flags=list(draft.get("security_flags", [])),
    )
