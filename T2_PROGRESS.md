# T2 Progress — Agentic Deception Intelligence Engine

**Branch:** `team/t2-agentic` · **Last updated:** 2026-10-02 ·
**Status:** complete per the T2 acceptance criteria — awaiting human review.

## Completed T2 work

| # | Item | Evidence |
|---|---|---|
| 1 | Agentic engine (`AgentEngine.decide`) | `app/agent/engine.py`, `test_engine.py` (23 tests) |
| 2 | Bounded context construction | `app/agent/context.py`, `test_context.py` |
| 3 | Deterministic decision routing (priority model) | `app/agent/decision.py`, `test_decision.py` |
| 4 | Session memory (bounded, isolated) | `app/agent/memory.py`, `test_memory.py` |
| 5 | Session-less isolation (`_ephemeral_*`, no `""` row) | `memory.py::get_ephemeral`, `test_integration_t1.py::FacadeSessionIsolationTest` |
| 6 | VFS delegation | `decision.py::VFS_OWNED_COMMANDS`, `test_decision.py::VfsOwnershipSyncTest` |
| 7 | Provider abstraction (Ollama + mock, registry) | `app/agent/providers/`, `test_providers.py` |
| 8 | Structured parsing + bounded repair | `app/agent/parser.py`, `RepairAttemptCapTest` |
| 9 | Guardrails (action/size/tool/deception rules) | `app/agent/guardrails.py`, `test_guardrails.py`, `GuardrailDisableTest` |
| 10 | Prompt-injection defenses (trust tiers, detection) | `app/agent/prompts/`, `app/agent/trust.py`, `test_security.py` (19) |
| 11 | Deterministic fallback for every failure path | `app/agent/fallback.py`, `test_fallback.py` |
| 12 | Live-clock `date`/`uptime` (no frozen constants) | `persona.py::simulated_now`, `test_persona.py::SimulatedClockTest` |
| 13 | `detected_categories` from T3's keyword table | `context.py`, `test_context.py` |
| 14 | Preflight flags (independent signal, tested) | `decision.py::preflight_flags`, `test_decision.py` |
| 15 | T1 facade integration (router, containment, summary) | `app/llm_engine.py`, `test_integration_t1.py` (12) |
| 16 | `AGENT_*` events for T4 | `engine.py`, verified in `test_engine.py` |
| 17 | Live Ollama test (opt-in) | `test/agent/test_ollama_live.py` — 4 gated tests; verified live (endpoint reachable, 3 pass, 1 model-gated skip) |
| 18 | Docs: architecture, contracts, this file, `T2_REPORT.md` | `docs/architecture/T2_AGENT.md`, `docs/contracts/T2_AGENT_CONTRACTS.md` |

## Tests

- **T2 suite:** `python -m unittest discover -s test/agent -t .`
  → **168 tests, OK (4 skipped = live-Ollama opt-ins)** — fully offline.
- **Repository suite:** `python -m unittest discover -s test -t .`
  → all green, offline, no Ollama required (§16).
- **Live Ollama:** `MIRAGE_TEST_LLM_LIVE=1` → ran against a reachable
  endpoint (HTTP 200, no models pulled): 3 passed, 1 correctly skipped
  (the model-pulled test gates behind `MIRAGE_TEST_LLM_MODEL=1`). The
  model-absent path proved the fallback contract live: safe simulated
  output, `fallback_reason=model_unavailable`, no crash.
- **Compilation:** `python -m compileall app/agent` → clean.
- Coverage spans every §17 category: decision, context, memory, persona, VFS
  delegation, provider, LLM failure, timeout, retry limit, parser,
  guardrail, prompt injection, fallback, session isolation, behavior
  context, preflight flags, T1 integration, events.

## Integration status

| Boundary | State |
|---|---|
| **T1** | Router → facade → engine verified end-to-end on an isolated DB (`test_integration_t1.py`): output, events, logging, sources (`llm`/`vfs`), fallback-on-failure, no production-DB writes. `app/main.py` runs the sync router via `asyncio.to_thread`. |
| **T3** | Consume-only: threat score/level, containment state, `THREAT_KEYWORDS`, VFS ownership/output. T2 adds no keywords, computes no scores, makes no containment decisions. **No T3 file modified.** VFS ownership mirror verified against T3's dispatch chain by `VfsOwnershipSyncTest`. |
| **T4** | No T4 files in the final tree. `AGENT_*` events are the T4 interface. Two T4 defects found during review were reverted and are reported for the T4 owner (see below). |

## Remaining dependencies

- **Ollama** (optional, runtime): `LLM_BASE_URL` endpoint + `LLM_MODEL`
  loaded. Absent → engine falls back deterministically (by design).
- None other. The offline suite and deterministic path have zero external
  dependencies.

## Known limitations

1. **VFS mirror is inherent.** T3's `vfs.py` exports no command list, and T2
   may not edit T3 files; the mirror is verified against T3's dispatch chain
   by a source-derived regression test instead of a shared constant.
2. **Memory is process-local** (in-process store), not multi-worker
   durable. Multiple FastAPI workers each hold their own store — consistent
   with the current single-process deployment, documented deliberately.
3. **LLM quality** is model-dependent; the guardrail constrains shape and
   safety, not persuasiveness.
4. **Live test coverage** requires a running Ollama; offline suites cannot
   exercise the real HTTP path (mock provider covers the contract).

## T4 handoff notes (defects found, not fixed — T4 ownership)

During review I found two real bugs in `dashboard/dashboard.py` but reverted
my fixes per the ownership rules (§1/§19 — no T4 implementation changes in
T2's tree):

1. **Infinite-refresh loop:** the top-of-script `st.rerun()` runs before the
   page renders anything, so with auto-refresh on, the dashboard stays
   blank. Fix for T4: move the refresh loop inside
   `@st.fragment(run_every=...)` around the data section.
2. **Removed pandas API:** `Styler.applymap` was removed in pandas ≥ 2.1
   (repo pins 3.0.6) — raises `AttributeError` at render. Fix for T4:
   replace with `.map` (same arguments).

## Files owned by T2

```
app/agent/**                     (engine, context, decision, memory, persona,
                                  prompts/, providers/, parser, guardrails,
                                  fallback, tools/, trust, config, models)
app/llm_engine.py                 (T1/T3-facing facade)
test/agent/**                     (all T2 tests + fixtures)
test/test_llm.py                  (T1-era live smoke script; main-guard fix
                                  only — needed for repo-wide discovery)
T2_REPORT.md  T2_PROGRESS.md
docs/architecture/T2_AGENT.md  docs/contracts/T2_AGENT_CONTRACTS.md
```

## Files intentionally untouched

- `app/vfs.py`, `app/behavior.py`, `app/containment.py`,
  `app/threat_summary.py`, `app/honeytokens.py` — **T3-owned**.
- `dashboard/**` — **T4-owned** (findings reported above instead).
- `app/db.py`, `app/main.py` (except the documented `asyncio.to_thread`
  integration line), `requirements.txt`, T1-era tests other than the
  `test_llm.py` main-guard.
- `data/mirage.db` — runtime state, kept at the committed baseline
  (`git status --short data/` clean).

## Review-fix history

- **2026-10-01:** initial implementation, 130 tests green.
- **2026-10-02 (review round):** 10 items fixed — repair-attempt cap +
  dead-loop removal, live clock, ephemeral-session isolation,
  `detected_categories`, guardrail kill-switch tests, dashboard fixes (later
  reverted to T4), README, `.env.example`, `test_llm.py` discovery guard,
  report addendum. 150 tests.
- **2026-10-02 (this round, §1–§21):** VFS mirror single-sourced with a
  source-derived divergence test; facade-level session A/B isolation tests;
  `test_integration_t1.py` (12 tests, isolated DB, production path);
  `test_ollama_live.py` (opt-in; verified live against a reachable
  endpoint — model-absent fallback proven, model-pulled test gated);
  all four docs; dashboard revert per ownership rules. 168 tests.
