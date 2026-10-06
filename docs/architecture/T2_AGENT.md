# T2 — Agentic Deception Intelligence Engine

**Owner:** T2 (`app/agent/**`, `app/llm_engine.py`)
**Status:** Implementation complete; see `T2_REPORT.md` for the verified state.

T2 turns attacker commands into believable simulated terminal output. It is the
intelligence layer of MIRAGE: T1's router hands it every command the VFS does
not own, and it decides — deterministically where possible, via the LLM where
necessary — what the fake host should say back.

## Architecture

```
T1 router (app/router.py)
    │  command, session_id, cwd
    ▼
llm_engine.generate_response()      ← T2 facade (app/llm_engine.py)
    │  sync contract preserved; session-less → ephemeral id
    ▼
AgentEngine.decide(session_id, command)      (app/agent/engine.py)
    │
    ├─ ContextBuilder        bounded per-decision context
    ├─ DecisionEngine        deterministic priority routing
    ├─ Provider (Ollama/mock) LLM call only when needed
    ├─ parser                 structured draft → typed decision
    ├─ GuardrailEngine       post-generation validation
    ├─ DeterministicFallback  safe output on any failure
    └─ events                 AGENT_* rows via T1's db.log_event
    ▼
build_response_plan(decision) → ResponsePlan
    ▼
T1/T3 consume output; T4 visualizes events
```

## The agent pipeline (per command)

1. **Input.** `AgentEngine.decide(session_id, command)` — the only entry point.
   Command length is capped (`AGENT_MAX_COMMAND_LEN`); oversized input is
   flagged `INPUT_TOO_LARGE` and truncated, never rejected outright.
2. **Context construction** (`context.py`). Builds a bounded `AgentContext`:
   persona, cwd, bounded recent memory, environment state, and T3 behavior
   signals (threat score/level, containment state, detected categories).
   Never the whole DB or filesystem.
3. **Intent / command analysis** (`decision.py::preflight_flags` +
   `classify`). Flags privilege-escalation shapes, destructive shapes,
   deception-break attempts; classifies into registered categories
   (first-match-wins): `vfs_owned`, `identity`, `privilege_escalation`,
   `destructive`, then fallthrough.
4. **Decision + action selection.** Deterministic handlers answer VFS-owned
   (defer), identity (from persona), denial cases — with no LLM call.
   Everything else goes to the LLM path.
5. **VFS delegation OR simulated response.** `DEFER_TO_VFS` hands back to
   T3's VFS; the facade resolves it inline for legacy callers.
6. **LLM generation** (`prompts/`, `providers/`). One structured prompt with
   the untrusted command wrapped as data; the draft JSON is parsed into a
   typed `AgentDecision` draft.
7. **Parsing** (`parser.py`). Malformed output consumes bounded repair
   attempts (`AGENT_REPAIR_ATTEMPTS`) within the global call cap
   (`AGENT_MAX_LLM_CALLS_PER_DECISION`); exhaustion falls back.
8. **Guardrail** (`guardrails.py`). Validates action allowlist, response
   size, deception consistency, tool allowlist. Rejections are replaced with
   fallback output and logged `AGENT_GUARDRAIL_REJECT`.
9. **Fallback if required** (`fallback.py`). Any failure — provider down,
   timeout, malformed, guardrail-rejected, budget exhausted — yields safe
   believable output, never an exception or stack trace.
10. **Agent event.** `AGENT_DECISION` (and conditional
    `AGENT_FALLBACK`/`AGENT_GUARDRAIL_REJECT`/`AGENT_INPUT_FLAG`) rows via
    T1's `db.log_event` for T4 visibility.
11. **Final terminal response.** `build_response_plan` → `ResponsePlan`;
    the facade returns the output string.

## Context (`context.py`)

`AgentContext` is deliberately small: session id, cwd, simulated user,
bounded memory (`AGENT_MAX_MEMORY` entries, each `AGENT_MAX_RESPONSE` chars),
environment state, T3 `BehaviorSignals`, persona. `BehaviorSignals
.detected_categories` reuses T3's `THREAT_KEYWORDS` table verbatim — T2
adds no keywords and computes no scores.

## Memory (`memory.py`)

Per-session `SessionMemory` in a bounded process-wide store
(`MemoryStore`, capped session count, LRU eviction). Ephemeral ids
(`_ephemeral_*`, from session-less facade calls) get a fresh one-call
`SessionMemory` via `get_ephemeral()` — never cached, never shared, so two
containment callers can never see each other's context.

## Persona (`persona.py`)

Simulated identity (`whoami`, `id`, `uname`, `hostname`, `date`, `uptime`, …)
answered from `PersonaState` (env-overridable: `MIRAGE_PERSONA_*`).
`date`/`uptime` use the **live host clock** (`simulated_now()`,
`simulated_uptime_string()`) — internally consistent with the current
simulation, and no more host information is exposed than the configured
persona already implies.

## Provider (`providers/`)

`LLMProvider` abstracts vendors; the registry maps `LLM_PROVIDER`
(`ollama`|`mock`) to a builder. Ollama runs over HTTP
(`LLM_BASE_URL`, default `http://127.0.0.1:11434`), never a hardcoded URL.
Error taxonomy: `ProviderError` with subclasses (Timeout, Unavailable,
BadResponse, ModelUnavailable, Auth) — each maps to a distinct fallback path.
`MockProvider` scripts responses for offline tests.

## Parser (`parser.py`)

Draft JSON → typed `AgentDecision` fields; unknown fields rejected;
malformed → `DecisionParseError` → bounded repair; repeated failure →
fallback. Structured output is what makes the guardrail's checks possible.

## Guardrails (`guardrails.py`)

`RuleGuardrail` + `GuardrailEngine` validate every decision (deterministic
ones included): action allowlist, response size (`AGENT_MAX_RESPONSE`),
tool allowlist, deception consistency (e.g. "honeypot" text is a
deception-break). `AGENT_ENABLE_GUARDRAIL=false` disables **only** this
post-generation review — input bounding, injection flagging, session
isolation, bounded execution and fallback all remain active (covered by
`GuardrailDisableTest`).

## Fallback (`fallback.py`)

`DeterministicFallback` produces believable simulated output for common
shapes: not-found (`bash: X: command not found`), permission denied,
missing-file errors — consistent with the persona and cwd. It is the last
line of defense: every failure path ends here, so no code path can return
an empty string, a stack trace, or a refusal that breaks the deception.

## Event system

`AGENT_DECISION` (every decision), `AGENT_FALLBACK`, `AGENT_GUARDRAIL_REJECT`,
`AGENT_INPUT_FLAG` — written through T1's `db.log_event`, typed in
`models.py` (`EVENT_AGENT_*`), consumed by T4. Ephemeral sessions emit no
events (no durable identity).

## T1 integration

- `app/router.py:29` — non-VFS commands call
  `llm_engine.generate_response(command, cwd, session_id=...)`.
- `app/main.py:35` — `asyncio.to_thread` so the sync facade never blocks the
  event loop.
- Facade contract preserved: `generate_response(command, cwd)` (T3
  containment), `generate_analysis(prompt)` (T3 threat summary).
  Session-less calls get `_ephemeral_*` ids: no DB row, no events, no shared
  memory.

## T3 integration

- **Consume:** threat score/level, containment state, `THREAT_KEYWORDS`
  (for `detected_categories`), VFS ownership, VFS output.
- **Never duplicate:** T3 owns scoring, threat levels, containment decisions.
- **Mirror, verified:** T3's `vfs.py` exports no command list, so T2 mirrors
  it once (`app/agent/decision.py::VFS_OWNED_COMMANDS`).
  `VfsOwnershipSyncTest` derives the authoritative set from T3's source and
  fails on divergence.
- **Never modified:** `app/vfs.py`, `behavior.py`, `containment.py`,
  `threat_summary.py`, `honeytokens.py` are untouched by T2.

## Trust boundaries

| Boundary | Rule |
|---|---|
| Attacker command → engine | Data only. Wrapped as data in the prompt, never concatenated as instructions. `PROMPT_INJECTION_SUSPECTED` flagged, decision proceeds with deterministic-safety intact. |
| LLM output → decision | Untrusted. Structured parse + guardrail; unknown fields/actions/tools rejected. |
| T3 data → context | Read-only signals; T2 adds no keywords/scores. |
| Agent → host | Nothing. `AgentAction` cannot express a real host op; state updates allowlist = `{cwd}`; no subprocess, no eval, no host file reads (AST-verified by tests). |
| Session A → Session B | Isolated memory stores; ephemeral ids never cached. |

## Failure behavior

Every failure ends in safe simulated output — never an exception, stack
trace, empty string, or deception break:

| Failure | Path | Result |
|---|---|---|
| Oversized input | truncate + flag | `INPUT_TOO_LARGE`, continues |
| Provider down | `ProviderUnavailableError` | fallback output, `AGENT_FALLBACK` |
| Timeout | `ProviderTimeoutError` | fallback (no retry on timeouts) |
| Malformed JSON | parse error | ≤ `AGENT_REPAIR_ATTEMPTS` repairs, then fallback |
| Guardrail rejection | replace + log | fallback output, `AGENT_GUARDRAIL_REJECT` |
| Retry exhaustion | budget cap | fallback, never unbounded |
| Any unexpected error | facade catch-all | `"command not found"` (legacy contract) |
