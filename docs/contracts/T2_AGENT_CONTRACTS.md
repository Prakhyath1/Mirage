# T2 Agent Contracts

**Owner:** T2. These are the stable, typed boundaries between T2 and the
rest of MIRAGE. Source of truth: `app/agent/models.py` (pydantic) — this
document mirrors it; where they disagree, the code wins and this file must be
fixed.

## Ownership map

| Contract | T1 | T2 | T3 | T4 |
|---|---|---|---|---|
| `CommandRequest` / HTTP API | **owns** | — | — | — |
| Session row, logs, events table | **owns** | writes via API | writes via API | reads |
| `AgentContext` | — | **owns** | feeds signals | — |
| `AgentDecision` / `AgentAction` | — | **owns** | — | — |
| `ResponsePlan` | consumes | **owns** | — | — |
| VFS command set, `execute_vfs_command` | routes | mirrors (verified) | **owns** | — |
| `BehaviorSignals` fields, threat score/level | — | consumes | **owns** | reads |
| Containment decisions | — | yields to | **owns** | — |
| `LLMRequest` / `LLMResponse` | — | **owns** | — | — |
| `GuardrailResult` | — | **owns** | — | — |
| Fallback output | — | **owns** | — | — |
| `AGENT_*` events | stores | **emits** | — | visualizes |

## `AgentContext` (`app/agent/models.py:221`)

Bounded context for one decision — never the whole DB or filesystem.

```python
session_id: str
command_id: str
current_working_directory: str
user_information: SimulatedUser        # simulated identity
recent_commands: List[AgentMemoryEntry] # bounded (AGENT_MAX_MEMORY)
environment_state: EnvironmentState
behavior_signals: BehaviorSignals       # T3-owned data, read-only
persona: PersonaState
available_simulated_tools: List[str]
metadata: Dict[str, Any]
# property: virtual_host_information -> EnvironmentState (readability alias)
```

**Invariants:** memory entries are bounded in count and length; behavior
signals are copied, never shared by reference; built by T2's
`ContextBuilder` only.

## `AgentDecision` (`app/agent/models.py:274`)

The central structured output of the T2 engine.

```python
decision_id: str            # dec_<hex12>
action: AgentAction         # enum (below)
response: str                # final terminal output
confidence: float            # 0.0–1.0
reason: str
deception_category: str      # e.g. "none", "simulated_output"
simulated_effect: SimulatedEffect
state_updates: Dict[str,str] # keys ⊆ STATE_UPDATE_ALLOWLIST = {"cwd"}
requested_tools: List[str]    # ⊆ tool registry allowlist
security_flags: List[str]     # FLAG_* (observability only)
latency_profile: LatencyProfile
guardrail: Optional[GuardrailResult]
metadata: DecisionMetadata    # provider, model, source, attempts, fallback
```

**Invariants:** `state_updates` restricted to the `cwd` allowlist (T1 owns the
session row); `security_flags` never alter T3's scoring; a decision without a
`guardrail` review cannot reach callers (deterministic ones are reviewed too,
except when the kill-switch is set).

### `AgentAction` (enum)

`RESPOND`, `SIMULATE_ERROR`, `SIMULATE_PERMISSION_RESULT`, `DEFER_TO_VFS`,
`DEFER_TO_SECURITY`. **Security invariant: no value can express a real host
operation** — only simulated outcomes or a handoff to another MIRAGE subsystem.

### `DecisionMetadata`

`provider`, `model`, `decision_source` (`llm`|`deterministic`), `attempts`
(LLM calls used), `fallback` (bool — true when the decision came from the
deterministic fallback path).

## `ResponsePlan` (`app/agent/models.py:299`)

What T1/T3 do with a decision.

```python
session_id, decision_id, action, output: str, exit_code: int
new_cwd: Optional[str]      # T1 applies via db.update_session
defer_to: Optional[str]     # "vfs" | "security" when handing off
security_flags, latency_profile, simulated_effect, confidence
events: List[Dict]           # AGENT_* rows T1 stores via db.log_event
metadata: DecisionMetadata
```

**Invariant:** the facade (`llm_engine.generate_response`) resolves
`DEFER_TO_VFS` inline for legacy callers, so its return is always a plain
output string.

## VFS result (`app/agent/models.py::VFSResult`)

T2's consumption schema for T3 VFS output, mirroring
`vfs.execute_vfs_command(session_id, command, cwd) -> (output, new_cwd)`:

```python
handled: bool      # False → VFS did not own the command (returns None)
stdout, stderr: str
exit_code: int
new_cwd: Optional[str]
```

**T3 owns the VFS command set** (`ls pwd cd cat echo mkdir rm touch nmap`,
`app/vfs.py:46-63`). T3's module exports no list; T2 keeps one mirror,
`app/agent/decision.py::VFS_OWNED_COMMANDS`, verified against T3's dispatch
chain by `VfsOwnershipSyncTest` (AST-derived from T3's source, fails on
divergence). T1's `router.VFS_COMMANDS` routes first, so T2's mirror is
defense-in-depth, not the primary router.

## `LLMRequest` / `LLMResponse` (`app/agent/models.py:332/343`)

```python
# LLMRequest
prompt: str; system: Optional[str]; temperature: float = 0.2
max_output_tokens: int = 512; json_mode: bool = True
request_id: str  # llm_<hex12>

# LLMResponse — raw provider text BEFORE parsing (untrusted)
text: str; provider: str; model: str
latency_ms: float; metadata: Dict[str, Any]
```

**Trust rule:** `LLMResponse.text` is untrusted data. It must pass
`parser.py` → typed `AgentDecision` → `guardrails.py` before anything
downstream sees it.

## Guardrail result (`app/agent/models.py:245`)

```python
approved: bool
violations: List[str]     # machine-readable rule ids
summary: str              # human-readable, logged with the event
```

Emitted with every decision; rejections swap in fallback output and write
`AGENT_GUARDRAIL_REJECT`. `AGENT_ENABLE_GUARDRAIL=false` disables
enforcement only — the review still runs and attaches, for observability.

## Fallback result

Not a pydantic model: the fallback path returns a normal `AgentDecision`
with `metadata.fallback=True`, `decision_source="deterministic"`. The
facade's terminal failure contract is the string `"command not found"`
(legacy behavior preserved). **Invariant:** every failure ends in a
non-empty, believable simulated output — never an exception, a stack trace,
or an empty string.

## `BehaviorSignals` (T3-owned data, T2 consumption schema)

```python
risk_level: str          # from session.threat_level (T3 computes)
threat_score: int        # from session.threat_score (T3 computes)
containment_active: bool # from session.containment_active (T3 decides)
detected_categories: List[str]  # T3 THREAT_KEYWORDS matched for the command
```

**Ownership:** T3 owns scoring, threat levels and containment. T2 reads
these signals for context and reports them in events; it never computes,
overrides, or duplicates them.

## `AGENT_*` events (`app/agent/models.py:25-28`, emitted via T1 `db.log_event`)

| Event | When | Payload |
|---|---|---|
| `AGENT_DECISION` | every decision (named sessions) | action, category, confidence, source, response size |
| `AGENT_FALLBACK` | fallback replaced the LLM path | reason, failure class |
| `AGENT_GUARDRAIL_REJECT` | guardrail rejected a draft | violations, summary |
| `AGENT_INPUT_FLAG` | input-level flags (oversized, injection-suspected) | flags |

Ephemeral (`_ephemeral_*`) sessions emit **no** events — they have no durable
identity.

## Facade contract (`app/llm_engine.py`)

```python
generate_response(command, cwd, session_id=None) -> str   # T1 router, T3 containment
generate_analysis(prompt) -> str                          # T3 threat_summary (provider-level)
```

Never raises, never returns an empty string, never leaks provider errors to
callers. Session-less calls: ephemeral id, no DB rows, no events, one-call
memory.

## Revision history

| Date | Change |
|---|---|
| 2026-10-02 | Initial contracts doc from implemented code (`team/t2-agentic`) |
