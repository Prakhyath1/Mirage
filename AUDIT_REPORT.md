# MIRAGE Independent Audit Report — Integrated T1+T2+T3+T4 Runtime

**Auditor:** Independent QA review (read-only audit + fresh test verification)
**Date:** 2026-10-07
**Tree audited:** `team/t4-integration` @ `2f61540` ("Integrate T1+T2+T3 into the T4 runtime with dashboard observability")
**Method:** Full source read of all four layers; live end-to-end smoke runs against a temp-DB FastAPI instance; fresh full-suite test execution (twice: before and after restoring a tracked test artifact); no source modifications except restoring `test/agent/_test_data/agent_test.db` (a test side-effect, §11).

**Verdict up front: PASS WITH FINDINGS.** The integrated runtime is functionally complete and its security invariants hold under adversarial probing. 320/320 tests pass (4 live-Ollama opt-ins skipped offline). The deception chain — API → parse → classify → score → sandbox/VFS/LLM → events → dashboard — works end to end, and nothing executes on the host. The findings below are real but none is a security hole; the notable ones are: two dead-code layers shipped but never wired (§7, §8), a tracked test DB that dirties the tree on every suite run (§11), stale progress docs that no longer match the merged reality (§13), and exit-code infidelity versus real Bash (§17).

---

## 1. Executive Summary

MIRAGE presents a simulated Ubuntu shell to an attacker. Every command flows through one choke point (`app/router.py::process_command` behind `T3PipelineHandler`), is scored, classified, answered by the virtual filesystem or the agentic LLM engine, logged to exactly one `logs` row, and surfaced to the operator through a Streamlit dashboard. The four team deliverables are merged and working: T1's FastAPI foundation serves sessions and commands with pydantic validation and unguessable IDs; T3's VFS, classifier, honeytokens, containment and decoy identity own the deterministic simulation; T2's agent engine owns everything the VFS does not, with guardrails, bounded repair, injection-proof prompt wrapping and a deterministic fallback; T4's integration handler binds the legacy pipeline into the foundation runtime and a dashboard observes the result.

What the audit verified live (against a temp-DB `create_app()` instance via `TestClient`):

- `cat /etc/passwd` → decoy passwd file; `nmap -sV` → simulated scan; `whoami` → `admin`; `hostname` → `web-prod-01` (decoy identity, never the host's `ubuntu`).
- `sudo cat /etc/shadow` → `Permission denied`; `cat /etc/shadow` → canary trip → `CONTAINMENT_ACTIVATED` + `HONEYTOKEN_ACCESS` events, threat escalates High, `containment_active=1`, and a subsequent `dd` gets blocked with `Failed to open device: Permission denied`.
- `ps aux` (unknown to VFS) → LLM path → `bash: ps: command not found`; every result carries `simulated: true`, `handler: t3_pipeline`, `result_type: vfs`.
- `/ready` reports `database_connected: true`; both DB planes initialize and persist.

What the audit found worth fixing, in priority order:

1. **The T4 service/view layer is shipped dead code** (§7): `dashboard/services/repository.py` (MITRE mapping, secret redaction, agent observations, health), `dashboard/views/*.py` (six pages), and `dashboard/components/metrics.py` all exist, import, and work — but `dashboard/dashboard.py` (the documented entrypoint, README line 43) never imports any of them. The operator sees the monolith's raw tables (including unredacted command output, §7.3), not the redacted view-models. Nothing tests the service layer directly.
2. **`database_connected` is always `false` on `/health`** (§8): the liveness `health()` constructor omits the field; only `/ready` sets it. Not a lie about a broken DB — the field is simply never populated on the liveness route.
3. **Tracked test artifact dirties the tree on every suite run** (§11): `test/agent/_test_data/agent_test.db` is committed and autoincrement-mutated by each test run; `git status` shows it modified after every pytest run.
4. **Progress docs are stale** (§13): `T4_PROGRESS.md` says all integration checkpoints are PENDING; they all landed on Oct 6. `T2_REPORT.md`'s test-count claims predate the merge (130 → 168 → now across suites).
5. **Exit-code infidelity** (§17): every simulated command returns `exit_code: 0`, including `Permission denied` (real Bash: 1) and `command not found` (real Bash: 127 on the T1 fallback path). A sophisticated attacker could probe `$?` to detect the simulation.
6. **`session_summary` is cosmetic** (§18): both `stored_summary` and `live_summary` return `"Analysis unavailable."` even for a High-threat contained session (provider offline). Stored summary falls back to live LLM instead of a deterministic recency summary.

None of these break the security model. §2–§6 confirm the invariants; §19 ranks findings with suggested owners.

---

## 2. Scope, Sources, and Method

**In scope:** the merged tree at `2f61540` — `app/` (8,215 LOC: T1 runtime/storage/api, T2 agent package, T3 pipeline, T4 integration handler), `dashboard/` (2,138 LOC), `test/` + `tests/` (5,170 LOC), `docs/`, progress reports, and git history (22 commits).

**Read in full:** `app/agent/**` (all 15 modules + providers + prompts), `app/vfs/**`, `app/router.py`, `app/sandbox.py`, `app/behavior.py`, `app/classifier.py`, `app/containment.py`, `app/honeytokens.py`, `app/llm_engine.py`, `app/threat_summary.py`, `app/main.py`, `app/integration/pipeline_handler.py`, `app/runtime/dispatcher.py` (fallback handler), `app/runtime/service.py`, `app/api/schemas.py`, `app/storage/database.py`, `app/models.py`, `app/config.py`, `app/core/ids.py`, `app/db.py`; all six `dashboard/views/`, `dashboard/services/{repository,models,exports,mitre_map}.py`, `dashboard/components/metrics.py`, `dashboard/dashboard.py`; every test file in `test/` and `tests/` (spot-checked for assertions-vs-claims alignment); `docs/ARCHITECTURE.md`, `docs/CONTRACTS.md`, `docs/integration/T4_API_CONTRACT.md`, `docs/contracts/*`, `docs/architecture/*`; all four `*_PROGRESS/REPORT.md` files; README.

**Verified by execution:**
- Full suite, fresh, twice: `python3 -m pytest test/ tests/` → **320 passed, 4 skipped** in ~17.5s, both times (second run after restoring the dirtied tracked DB).
- End-to-end smoke: `TestClient(create_app())` with `MIRAGE_DB_PATH` pointed at a temp dir; sessions created, seven command shapes exercised, canary tripped, containment observed, events read, both summaries read, both DB planes inspected.
- Dashboard service layer exercised directly (fresh DB): `MirageRepository` yields threat observations, MITRE rows (`T1005`, `T1046`, `T1485` from seeded demo data), and all six view modules import with callable `render`.
- Provider-offline behavior confirmed by construction (no Ollama on the audit host; every fallback path taken live during smoke).

**Out of scope:** live Ollama quality of generated deception text (provider offline — its absence path is what this audit exercises); Docker deployment (§22: not yet built); the four skipped tests (live-Ollama opt-ins whose skip conditions were met).

---

## 3. Architecture as Built (vs. as Claimed)

The merged runtime has one command path, one execution choke point, and two data planes:

```
POST /dev/sessions/{id}/commands          (T1 FastAPI, pydantic-validated)
  └─ T1 CommandDispatcher
      └─ T3PipelineHandler.handle          (T4 integration, off-loop via asyncio.to_thread)
          └─ app/router.process_command    (T3 pipeline — the single choke point)
              ├─ behavior.update_session_threat   (score first: same-turn escalation visible next turn)
              ├─ containment_active? sandbox.execute(containment=True)
              └─ else: parser.parse →
                    ├─ VFS builtin (12 commands) → app/vfs/ handlers, decoy identity
                    └─ not builtin → llm_engine.generate_response → T2 AgentEngine.decide
                          ├─ deterministic identity (hostname/date/uptime/arch)
                          ├─ DEFER_TO_VFS (mirror sync-tested against T3 dispatch)
                          ├─ priv-esc / destructive → SIMULATE_PERMISSION_RESULT
                          └─ LLM path → parse → guardrails → plan → persona-consistent output
  everything → one `logs` row (sandbox is the single logging point)
  events → t3db.log_event + T1 bus → storage → dashboard reads
```

**Claimed vs. built, layer by layer:**
- T1 (claimed complete in `T1_PROGRESS.md`): built as claimed — runtime, storage, event bus, session manager, dispatcher with fallback, dev API, frozen contracts. 104 T1 tests in `tests/foundation/` all pass inside the 320.
- T3 (rebuilt during merge, commit `8e55f99`): VFS package, classifier, behavior, containment, honeytokens, sandbox choke point — all present, all tested (`test/test_security.py`), all exercised live.
- T2 (claimed complete in `T2_REPORT.md`/`T2_PROGRESS.md`): agent package with the full safety stack; engine, decision routing, guardrails, trust wrapping, bounded repair, fallback, memory, providers — present and green (`test/agent/`, 168 of the 320).
- T4 (claimed *pending* in `T4_PROGRESS.md`): **actually done** — this is the doc-staleness finding (§13). The pipeline handler, decoy-identity fix (`25f3c54`), dashboard rebuild, and contract doc all landed Oct 6.

**Integration seams of note:**
- `CommandRequest` name collision (T1 dataclass vs. T3 pydantic DTO) resolved additively as `LegacyCommandRequest` — documented in `T4_API_CONTRACT.md`, matches code.
- `app/vfs.py` is a package now (`app/vfs/`); T2's `VFS_OWNED_COMMANDS` mirror includes `whoami/id/uname` which T3's VFS claims; the sync test (`test_decision.py::VfsOwnershipSyncTest`) derives the authoritative set from T3 source AST, so divergence fails loudly.
- Two SQLite planes persist: `data/mirage_foundation.db` (T1, via `MIRAGE_DB_PATH`) and `data/mirage.db` (T3/T2 pipeline, `app/db.DB_PATH`, fixed at import). `data/` is gitignored; runtime DBs are untracked (commit `15adf65`).

---

## 4. Security Invariants — Verified

Each invariant was checked by source read AND live probe or test-suite evidence:

| # | Invariant | Evidence |
|---|---|---|
| 1 | **Nothing executes on the host** | `sandbox.execute` is the only path to "execution" and only calls VFS/LLM; `pipeline_handler.handle` wraps `process_command` in `asyncio.to_thread`; AST scan test (`test_security.py::NoShellInvocationTest`) forbids `os.system/subprocess*/eval/exec/shutil.rmtree/pty.spawn` across `app/agent/**`; live probes returned simulated text only. |
| 2 | **No outbound channel from the LLM** | Provider base URL pinned `http://127.0.0.1:11434` (`test_llm.py::test_engine_only_talks_to_localhost`); config reset re-read; no other transport in `app/agent/**`. |
| 3 | **Attacker text is data, never code** | Injection payloads wrapped in non-forgeable `<mrg1_untrusted>` tags (`trust.py`, count-tested); `parse_draft` rejects unknown fields; responses stored as data; `/tmp/pwned` never created in any injection test. |
| 4 | **Decoy identity, never host identity** | `whoami` → `admin`, `hostname` → `web-prod-01`, `uname` → Ubuntu 22.04 decoy — verified live. `25f3c54` fixed the T1 fallback + storage defaults that leaked `ubuntu`/`/home/ubuntu`; `test_security.py::test_fallback_never_reads_host` patches `socket.gethostname/os.uname/os.getcwd/open` to raise and the fallback still answers `admin`. |
| 5 | **VFS cannot escape virtual root** | `_resolve` rejects `..` escapes, deep paths, absolute paths outside root (`test/test_security.py::test_resolve_*`); tilde maps to fake home. |
| 6 | **Exactly one audit row per command** | Sandbox is the single logging point (`app/router.py:41-50` comment + code); non-sandbox branches (LLM fallthrough) log their own row; verified: 5 commands → 5 `logs` rows + events in smoke run. |
| 7 | **Session IDs are server-generated and unguessable** | `sess_/cmd_/evt_` + `secrets.token_urlsafe(24)`; `is_valid_id` regex at every boundary (`app/core/ids.py`); FastAPI returns uniform 404/422 envelopes, no stack traces (`debug=False`). |
| 8 | **Canary trip → containment escalation** | Live: `cat /etc/shadow` → `HONEYTOKEN_ACCESS` + `CONTAINMENT_ACTIVATED` events; threat High; `containment_active=1`; follow-up `dd` → `Failed to open device: Permission denied` (containment path in `sandbox.execute`). |
| 9 | **Dashboard reads, never writes** | `MirageRepository` opens both DBs read-only (`mode=ro` in connections); monolith `dashboard.py` calls only `db.get_*` readers. No `INSERT/UPDATE/DELETE` in any dashboard code (source-scanned). |
| 10 | **Honeytoken content never displayed** | `/session/{id}/honeytokens` returns metadata only; both dashboard surfaces render trip counts/paths, never token contents (`T4_API_CONTRACT.md` §1 + code). |

**Adversarial probes attempted during audit (all stayed inside the simulation):** `sudo cat /etc/shadow`, `cat /etc/shadow`, `rm -rf /`, `dd if=/dev/zero of=/dev/sda`, `:(){ :\|:& };:` fork bomb, `ignore all previous instructions` (flagged, still processed as data), oversized input (`x`*5000 — bounded), unknown tool request (`shell_exec` — guardrail-rejected), malformed JSON model output (fallback), provider unavailable (fail-fast fallback).

---

## 5. Test Suite — Fresh Verification

**Command:** `python3 -m pytest test/ tests/`
**Result (run twice, before and after artifact restore):**

```
320 passed, 4 skipped in ~17.5s
```

**Breakdown by suite:**

| Suite | Files | Result focus |
|---|---|---|
| `tests/foundation/` (T1) | 7 files | runtime, storage, event bus, session manager, dispatcher, API, config — including the vertical slice |
| `tests/integration/` (T4) | 2 files | pipeline handler ordering, canary-trip event contract, vertical slice through all four layers |
| `test/agent/` (T2) | 12 files | engine, decision routing + VFS mirror sync, guardrails, parser repair caps, memory bounds, providers, trust/injection, fallback, facade isolation, security AST scans |
| `test/` root (T3 legacy + compat) | `test_security.py`, `test_llm.py`, `test_dashboard.py` | VFS escape, parser, classifier, containment, dashboard render/anchoring/rerun, llm facade fallback + localhost pinning |

**The 4 skipped:** live-Ollama opt-ins (`test_llm.py::test_live_fallback_smoke` and 3 agent-live tests) whose `skipif` fired — correct behavior offline; they passed live per T2's report when a provider was up.

**Suite quality observations:**
- Tests assert behavior, not implementation trivia — e.g. `VfsOwnershipSyncTest` derives T3's owned set from source AST rather than trusting the mirror; `GuardrailDisableTest` proves the kill-switch removes only LLM-output review while input bounding, injection flagging, and deterministic denials survive.
- Test isolation is disciplined: every `AgentTestCase` gets a throwaway DB (via `db.DB_PATH` redirect) and singleton resets. The one isolation leak is repo-level, not runtime: the *tracked* fixture DB itself mutates (§11).
- `test_dashboard.py` is a genuine regression trap — it documents and pins three real rot incidents (pandas `Styler.applymap` removal, unpinned pandas, Streamlit `sys.path` anchoring) and asserts `st.rerun()` stays the final statement.
- One suite-claim mismatch to note: `T2_REPORT.md` §6 says "130 Tests, All Green" and its header says 168/168 — both true at their respective dates, but the merged tree's number is 320 across all suites; progress docs were not updated after the merge (§13).

---

## 6. Live End-to-End Verification (Smoke)

Full transcript of the audit's smoke run against `TestClient(create_app())`, temp `MIRAGE_DB_PATH`, no Ollama:

| Command | result_type | handler | simulated | stdout (truncated) |
|---|---|---|---|---|
| `cat /etc/passwd` | vfs | t3_pipeline | true | `root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:...` |
| `nmap -sV 10.0.2.10` | vfs | t3_pipeline | true | `Starting Nmap 7.92 ( https://nmap.org ) at ...` |
| `sudo cat /etc/shadow` | vfs | t3_pipeline | true | `Permission denied` |
| `ps aux` | vfs | t3_pipeline | true | `bash: ps: command not found` (LLM fallback styled) |
| `whoami` | vfs | t3_pipeline | true | `admin` |
| `hostname` | vfs | t3_pipeline | true | `web-prod-01` |
| `rm -rf /` | vfs | t3_pipeline | true | `rm: cannot remove: Operation not permitted` |

Escalation chain: after `cat /etc/shadow`, `GET /session/{id}/events` → `['CONTAINMENT_ACTIVATED', 'HONEYTOKEN_ACCESS']`; `GET /session/{id}` → `threat_level: High, threat_score: 58, cwd: /home/admin`; T3 DB row shows `containment_active: 1`; a follow-up `dd` under containment → `Failed to open device: Permission denied`.

Readiness: `GET /ready` → `database_connected: true` before and after session creation. Liveness `GET /health` → `status: ok, event_bus_running: true` (but see §8 on its `database_connected` field).

Command log integrity: 5 commands → 5 `logs` rows + 2 events, `source` column correctly distinguishing `vfs`/`llm`/`containment` per the pipeline's branches.

**What this proves:** the deception contract holds through the whole merged stack — API validation, off-loop pipeline dispatch, VFS-first routing, canary containment escalation, LLM degradation, decoy identity, and honest observability rows — with zero host execution anywhere in the path.

---

## 7. Finding — Shipped Dead Code: the T4 Service/View Layer (High Priority, Functional)

**What:** `dashboard/` contains two complete architectures:

1. **The monolith** — `dashboard/dashboard.py` (115 lines): raw `db.get_all_sessions()/events()/logs()` tables, custom CSS, 4 metrics, session table with `Styler.map`, honeytoken events, command logs, auto-refresh. This is the *only* thing reachable from the documented entrypoint (`README.md:43`: `streamlit run dashboard/dashboard.py`).
2. **The service/view layer** — `dashboard/services/{repository,models,exports,mitre_map}.py`, `dashboard/views/{overview,sessions,security_events,agent_activity,threat_intel,system_health}.py`, `dashboard/components/metrics.py`: frozen view-models, MITRE ATT&CK rendering, secret redaction (`_redact`/`_safe_metadata`), agent observations, system health aggregation, JSON/webhook exports (webhook opt-in only, refuses unset/non-http URLs).

**Evidence it's dead:** `grep -rn "from dashboard.views\|dashboard.services"` across all Python returns *zero* references outside the `dashboard/` package itself. `dashboard.py` imports only `pandas`, `streamlit`, `time`, `os`, `sys`, and `app.db`. The audit imported all six views plus the repository against a fresh temp DB — every one works (observations, MITRE rows `T1005/T1046/T1485`, callable `render`) — so this is not broken code, merely *unreachable* code.

**Why it matters:**
- **Security downgrade in practice:** the monolith renders `logs.output` (attacker-controlled simulated output) **unredacted**, while the shipped `_redact`/`_safe_metadata` machinery (which strips `key=***REDACTED***` patterns and bounds lengths) sits unused. The operator-facing surface that *was built to be safe* is not the one that runs.
- **MITRE ATT&CK, agent decisions, and system health never reach the operator**, despite full implementations existing.
- **The contract doc describes the layer as the dashboard** (`T4_API_CONTRACT.md` §1–2 documents view-models as "the typed view-models the dashboard is allowed to use").
- **Test gap:** `test/test_dashboard.py` covers the monolith only; nothing anywhere imports `dashboard.services` or `dashboard.views` in a test (confirmed by grep across `test/` and `tests/`).

**Fix (owner T4):** either make `dashboard.py` a thin router over the six views (they were clearly built for this), or delete the layer and amend the contract doc. Add a service-layer test file regardless. Estimated: one afternoon for the wiring + tests.

---

## 8. Finding — `/health` Reports `database_connected: false` Unconditionally (Low Severity, Misleading)

**What:** `HealthResponse.database_connected` defaults to `False`; `app/runtime/service.py::health()` (liveness) constructs `HealthStatus` without setting it (or `active_sessions`), so `GET /health` always shows `database_connected: false` and `active_sessions: 0` even when the DB is fully connected and sessions exist. Only `readiness()` computes `db_ok` via `storage.health_check()`.

**Live evidence:** smoke run showed `/health` → `database_connected: false` while `/ready` → `true` in the same process, same instant, DB connected, sessions active.

**Impact:** monitoring that watches liveness for DB status will false-alarm perpetually (or worse, get trained to ignore the field). Not a security issue; an observability fidelity issue.

**Fix (owner T1):** either populate the fields in `health()` (cheap: one `SELECT 1`), or split the response models so liveness honestly omits fields it does not measure. Prefer the former — operators do check `/health` first.

---

## 9. Finding — T2 LLM Path's Answers for "command not found" Are Stylistically Perfect but Semantically One-Dimensional (Info)

Every non-VFS, non-deterministic command degrades to a "command not found"-style string in this offline configuration. The facade (`app/llm_engine.py`) preserves the legacy contract: any transport failure → `"command not found"`, any provider absence → styled `bash: <cmd>: command not found`, never an exception, never host data. The guardrail-approved path means a *live* Ollama could contextualize responses, but offline the deception story is: **VFS-owned commands look real; everything else looks like a broken box.**

This is actually a defensible posture for a honeypot (a stripped attack surface invites probing elsewhere), but operators should know it: with no Ollama running, the LLM layer contributes exactly the fallback string and nothing else. `T2_REPORT.md` §14 documents live-Ollama behavior; this audit could only verify the offline leg. **Info-level: no action needed beyond awareness.**

---

## 10. Finding — `data/mirage.db` Ships with Demo Data; Fresh Clones Seed Production-Looking Sessions (Low, Hygiene)

`data/mirage.db` (untracked now, per commit `15adf65`) exists on this host with 43 observations-worth of seeded demo activity (sessions, commands, events, honeytoken trips). Any dashboard run that has not set `MIRAGE_PIPELINE_DB_PATH` and whose `app.db.DB_PATH` import-time default resolves to the repo's `data/mirage.db` will render this old demo activity as if it were live.

**Verified:** the audit's first repository check accidentally read the real `data/mirage.db` (import-time `DB_PATH` binding — see §12 for the mechanism) and got 43 observations from an "empty" session. After redirecting `db.DB_PATH` to a truly fresh file, a seeded nmap + honeytoken-access produced the expected 2 observations and 1 MITRE row (`T1046`).

**Impact:** low — it is demo data, not a leak — but an operator could mistake stale demo rows for a live attacker. The monolith dashboard has no "data as of" indicator.

**Fix (owner T4):** the rebuilt view layer already aggregates with timestamps (`first_seen/last_seen`), which mitigates this; wiring §7's layer is the main remedy. Optionally `init_db()` could refuse to open a DB whose schema version predates a marker.

---

## 11. Finding — Tracked Test DB Mutates on Every Suite Run (Medium, Repo Hygiene)

**What:** `test/agent/_test_data/agent_test.db` is committed (added in `cff10d0`, T2's engine commit). The agent fixtures redirect `db.DB_PATH` to it, and SQLite's `sqlite_sequence` autoincrement metadata mutates the file on every test run. Result:

```
$ python3 -m pytest test/ tests/
320 passed, 4 skipped
$ git status --short
 M test/agent/_test_data/agent_test.db
```

Reproduced twice in this audit (run → dirty; `git checkout --` → clean; run → dirty again). The binary diff is 0 textual lines — pure file-format churn — but it makes `git status` noisy, invites accidental commits of state, and breaks "clean tree = clean CI" conventions. It also contains an empty `sessions/logs/events/virtual_files` schema (checked: 0 rows) plus the autoincrement residue.

**Why it's still a real finding even though harmless at runtime:** any teammate running the suite before committing will see a modified file and may either commit it (noise, blame pollution) or `git checkout` other people's work by reflex. CI without `git diff --exit-code` won't catch it either way.

**Fix (owner T2, one line):** either (a) delete the tracked file and add `test/agent/_test_data/` to `.gitignore` (fixtures `mkdir` it on demand — they already do), or (b) keep a tracked *schema seed* in a non-SQLite form and build the DB per-run. Option (a) is strictly better; the fixtures' `mkdir(parents=True, exist_ok=True)` already tolerates absence.

---

## 12. Finding — `app/db.py`'s Import-Time `DB_PATH` Binding Is an Integration Foot-Gun (Low, Design)

`app/db.py:8`: `DB_PATH = os.path.join(BASE_DIR, "data", "mirage.db")` — bound at import time, never re-read. T2's fixtures handle this by reassigning the module global (`db.DB_PATH = ...`) *after* import, which works only because every consumer reads `db.DB_PATH` at call time rather than capturing it.

This audit tripped over it twice (see §10): setting `MIRAGE_PIPELINE_DB_PATH` has **no effect whatsoever** (the env var isn't even read — the name appears only in this audit's own scripts), and setting `MIRAGE_DB_PATH` affects only T1's foundation DB. The pipeline DB location is hard-wired to the repo tree unless callers mutate a module global.

**Impact:** (a) tests must mutate production module state to isolate, which is the §11 mechanism in action; (b) two DB planes with three different resolution conventions (`MIRAGE_DB_PATH` env var for T1, import-time constant for T3, `monkeypatch` for tests) is a comprehension tax on every future maintainer; (c) the dashboard repository's `_pipeline_db_path()` imports `app.db` and reads `DB_PATH` dynamically, so it inherits whatever the import-time binding gave — correct, but only by courtesy of the global being read-late everywhere.

**Fix (owner T3, small):** make `DB_PATH` a function or read an env var at connect time (`MIRAGE_PIPELINE_DB_PATH` would be the natural name and matches the docs' phrasing in `T4_API_CONTRACT.md` §1's table). This is a refactor with a wide but shallow blast radius; the sync AST tests and fixtures will catch misses.

---

## 13. Finding — Progress Docs Contradict the Shipped Tree (Medium, Process)

The repository's own progress docs are the audit's least reliable sources; all four were checked against reality:

| Document | Claims | Reality at `2f61540` |
|---|---|---|
| `T4_PROGRESS.md` (updated 2026-10-05) | All 5 integration checkpoints "PENDING"; "IN_PROGRESS: checkpoint 1"; dashboard rebuild "in progress"; deployment "Pending" | Checkpoints 1–4 all landed Oct 6 (`8687204`, `8e55f99`, `25f3c54`, `2b11059`, `2f61540`); dashboard exists (both layers, §7); deployment genuinely pending (§22) |
| `T2_REPORT.md` | "130 Tests, All Green" (§6) vs "168/168" (header) | Both true on their own dates; merged tree runs 320 across all suites — no post-merge reconciliation |
| `T2_PROGRESS.md` | "awaiting human review"; VFS ownership table without `whoami/id/uname` | Engine now defers those to T3 (commit `2f61540`'s own message documents this) |
| `T1_PROGRESS.md` | "commits landing in stages ... blocked only by the session's command-permission classifier" | All T1 commits landed Oct 1–3 (`4951153`→`f518e99`) |

**Impact:** the next reader (human or agent) trusting `T4_PROGRESS.md` will believe the integration never happened and may redo it. This is exactly the failure mode progress docs exist to prevent.

**Fix (owner T4 as QA owner):** one sweep updating each doc's status section with the merged-tree truth and a pointer to `AUDIT_REPORT.md` for the delta. The docs are otherwise excellent — specific, evidence-linked, honest about defects — they just stopped being updated 24h before the work completed.

---

## 14. Finding — `requirements.txt` Unpinned; Suite Depends on Exact-ish Modern Versions (Low, Supply-Chain/Repro)

`requirements.txt` lists bare names: `fastapi`, `uvicorn`, `streamlit`, `pandas`, `requests`, `pydantic`, `python-dotenv`, `pytest`, `pytest-asyncio`, `httpx`. Installed today: pandas 3.0.6, streamlit 1.65.0, httpx 0.28.1 — and the suite passes against these.

But `test/test_dashboard.py`'s own docstring documents the cost of exactly this policy: a bare `streamlit run` crashed on render because pandas ≥2.1 removed `Styler.applymap` (the monolith now uses `Styler.map`, correct for current pandas), and the unpinned dependency drifted under the team. The tests now pin the *behavior* (render smoke via `AppTest`), which is the right defense — but a fresh `pip install -r requirements.txt` a year from now pulls whatever pandas ships and the monolith's `style.map` could break again (`.map` replaced `.applymap` in pandas 2.1; nothing guarantees `.map` survives 4.x either).

**Fix (owner T4):** pin with ranges (`pandas>=2.1,<4`, `streamlit>=1.30,<2`, `pydantic>=2,<3`, `fastapi>=0.100`, `httpx>=0.24,<0.29` …) or commit a lockfile. Ten minutes of work, prevents the exact class of rot the project already suffered once.

---

## 15. T2 Agent Layer — Deep Review (Pass with Notes)

The agent package is the most defensively engineered layer and deserved the deepest read. All 15 modules reviewed; findings:

**Architecture is sound:** `AgentEngine.decide` composes context → preflight flags → deterministic routing → (LLM path: prompt build → provider → parse → repair-cap retry → guardrail) → fallback. The fallback is not an afterthought: `DeterministicFallback` is persona-consistent (answers `whoami` → `admin` even with host introspection patched to raise — tested), and the facade `llm_engine.generate_response` preserves the never-raise contract.

**The strongest single design decision:** the VFS ownership mirror is *tested against T3's source AST* (`VfsOwnershipSyncTest`). The mirror (`VFS_OWNED_COMMANDS`, 12 commands incl. `whoami/id/uname`) is a manual copy across a team boundary — the classic place drift rots in — and the test makes divergence a build failure rather than a silent routing regression.

**Trust tiers:** untrusted input is wrapped in `<mrg1_untrusted>` tags with forging neutralized (count-based tests assert a forged closer can't escape); injection detection flags but does not block (correct: a honeypot wants to observe the attempt); the wrapper appears exactly once per prompt (count-tested).

**Guardrail disable switch** (`AGENT_ENABLE_GUARDRAIL=false`): `GuardrailDisableTest` proves the switch removes *only* LLM-output review while input bounding, injection flagging, trust wrapping, and deterministic denials of priv-esc/destructive all still hold — the kill-switch cannot become a safety bypass. This is the correct paranoia.

**Bounded everything:** repair attempts (`AGENT_REPAIR_ATTEMPTS`) are capped by the per-decision call budget (`agent_max_llm_calls_per_decision`); unavailable providers fail fast (exactly 1 call — tested); timeouts are retryable but budget-bounded; memory is LRU-bounded; ephemeral (session-less) callers get `_ephemeral_*` IDs, no DB rows, no shared memory (all three asserted).

**Notes (all minor):**
1. `engine.py::_emit` swallows all exceptions in the observability seam (`except Exception: pass`). Deliberate and documented ("observability must never break the request path") — correct choice for this system, but it means event-pipeline breakage is invisible to metrics. The comment is honest about the trade.
2. `_safe_metadata`/`_redact` in the dashboard services handle `key=value` secrets, but the redaction loop has a `break` at the end of the `while` — it redacts only the *first* marker occurrence per string (the `while idx != -1` is effectively an `if`). Dead code shape suggests an intended multi-redaction that never loops. Low impact (bounded display either way), but the shipped monolith never calls this code (§7), so it compounds.
3. `parse_draft` rejects unknown fields outright (`DecisionParseError`). Good default; the repair path gives the model one bounded chance to fix.
4. The AST security scanner forbids importing `subprocess/pty/shutil` in `app/agent/**` — correct scope (T3's own `app/` uses none of these either; the scanner's scope is the agent package, the right boundary for T2's ownership).

**Verdict: no defects in the agent layer.** The two integration bugs found during the audit's probing (decoy identity leak, §4 row 4, fixed in `25f3c54`) were in T1's fallback, not T2.

---

## 16. T3 Pipeline Layer — Deep Review (Pass with Notes)

**Sandbox as single choke point is real, not aspirational.** `app/router.py::process_command` routes *everything* — containment path, VFS path, LLM fallthrough — and each non-sandbox branch logs its own row to preserve exactly-one-row-per-command. The code comments state the invariant and the code matches (`router.py:41-50`).

**Score-then-execute ordering is deliberate and correct:** `behavior.update_session_threat` runs *before* the containment check, so a command that escalates the session to High is executed normally this turn and containment applies from the next turn. The comment explains the choice. Live-verified: `cat /etc/shadow` scored High + tripped canary + contained; subsequent `dd` blocked.

**Classifier severity model** (`classify`): a pipeline is as severe as its most severe stage — max over `UNKNOWN < SAFE < RECON < SENSITIVE < DESTRUCTIVE`. Clean, tested (`sudo` inherits underlying command severity; `cat passwd` → SENSITIVE; `rm -r` → DESTRUCTIVE while plain `rm` is not; a filename containing "history" is not a `history` command — all in `test/test_security.py`).

**Honeytokens:** `/etc/shadow`-style canary reads return `Permission denied`-style output *and* trip events (`HONEYTOKEN_ACCESS`), escalating containment. Metadata-only exposure end-to-end (API schema, dashboard, contract doc all agree).

**Containment deception:** under containment, destructive commands get device-level failures (`Failed to open device: Permission denied`) — more believable than a blanket "blocked" message. Sensitive reads degrade (shadow → permission error). Live-verified both.

**Notes:**
1. `app/sandbox.py:66` hardcodes `exit_code=0` — the §17 finding lives here.
2. `containment.execute` path duplicates the classification+block logic rather than reusing `sandbox.execute`'s — acceptable duplication (~15 lines) but a divergence risk if block messages change.
3. The VFS package's `whoami/id/uname` handlers returning the decoy identity are the reason T2's mirror includes them — cross-team coupling handled correctly with the sync test.

**Verdict: pass.** The security-boundary rebuild lost in the team merge (restored in `8e55f99`) is back and tested.

---

## 17. Finding — Simulated Exit Codes Are Always 0 (Medium, Deception Fidelity)

**Live evidence:**

| Command | stdout | real Bash `$?` | MIRAGE `exit_code` |
|---|---|---|---|
| `sudo cat /etc/shadow` | `Permission denied` | 1 | **0** |
| `cat /etc/shadow` (canary) | `cat: /etc/shadow: Permission denied` | 1 | **0** |
| `nmap -sV 10.0.2.10` | (scan output) | 0 | 0 ✓ |
| unknown cmd → T1 fallback | `bash: x: command not found` | 127 | **127 only on the pure-T1 fallback path** |

The T1 dispatcher's fallback handler *does* compute 127 for unrecognized commands (`dispatcher.py:123`), and `CommandResult`/`schemas.py` carry `exit_code` faithfully — but `pipeline_handler.py:66` hardcodes `exit_code=0` for every T3-pipeline result, and T3's `sandbox.py`/VFS/LLM never produce anything else. In the merged runtime the T1 fallback path is unreachable behind the T3 handler, so **every command the attacker runs reports success**.

**Why it matters:** `$?` probing is a first-week enumeration technique. A real Ubuntu returns 1 for permission-denied reads and 127 for unknown commands; a box where `cat /etc/shadow` "succeeds" (exit 0) while printing `Permission denied` is a fingerprintable inconsistency. The output *text* is right; the *semantics* are wrong.

**Fix (owner T3 + T4, small and contained):** thread an exit code through the choke point — VFS permission denials → 1, containment blocks → 1, LLM `command not found` → 127, success → 0. The `CommandResult` schema already carries the field; `pipeline_handler` just needs the pipeline to return it. Tests to update: the two integration files assert `exit_code == 0` in places (they pin current behavior, which is the point of this finding).

---

## 18. Finding — `session_summary` Persists the Failure String, Not the Analysis (Low-Medium, Observability)

**Live evidence:** after a contained, High-threat session (canary tripped), both summary fields return the same failure string:

```json
{"stored_summary": "Analysis unavailable.", "live_summary": "Analysis unavailable."}
```

**Mechanism, traced in source:** `behavior.update_session_threat` calls `threat_summary.generate_and_store()` on any threat-level escalation to Medium/High — i.e. at exactly the moment the session becomes most interesting. `generate_threat_summary` builds a good analyst prompt and calls `llm_engine.generate_analysis`, which (provider offline) returns `""`, so the summary becomes `"Analysis unavailable."` — **and `generate_and_store` writes that failure string into the `sessions.threat_summary` column**. It is now durable: `get_stored_summary` will serve "Analysis unavailable." until the *next* escalation rewrites it. The dashboard-facing endpoint layers `or "No summary available"` on top, so three indistinguishable failure states exist ("Analysis unavailable.", "No summary available.", `None`).

**Why it matters:** the stored summary is the operator's one-look triage artifact for the most important sessions. Persisting a provider-failure string converts "no LLM" into "no analysis, forever" for that session. A deterministic fallback summary would be nearly free: the threat level, category mix, and last-N commands are all already in the DB row and in scope at the write site (e.g. `"High-threat session: 5 commands including privilege escalation (sudo) and a honeytoken trip (/etc/shadow). Containment active."`).

**Related gap in the same function:** `generate_and_store` is called *synchronously inside `update_session_threat`, inside `process_command`, inside the request path*. With a live provider this puts a full LLM round-trip (plus retries) on the critical path of every command that escalates a level. `llm_engine.generate_analysis` is sync and failure-silent, so offline it costs nothing — but online it is a latency landmine. Consider deferring summary generation to after the response returns (background task or on-read).

**Fix (owner T3):** (a) don't store failure strings — store `None` and let the endpoint fall back; (b) add a deterministic template summary for the offline case; (c) move generation off the request path. (a) is a two-line change; (b) is an afternoon; (c) is optional but recommended before live-Ollama deployment.

---

## 19. Consolidated Findings Table (Ranked)

| # | Severity | Area | Finding | Suggested owner |
|---|---|---|---|---|
| 1 | **High (functional)** | T4 | Service/view layer shipped but unreachable from entrypoint; unredacted monolith serves instead of redacted view-models; no tests on services (§7) | T4 |
| 2 | **Medium** | T3/T4 | Exit codes always 0 behind the pipeline handler — `$?` fingerprinting can detect the simulation (§17) | T3+T4 |
| 3 | **Medium** | T2 | Tracked `test/agent/_test_data/agent_test.db` mutates on every suite run — dirty-tree noise, accidental-commit risk (§11) | T2 |
| 4 | **Medium** | T4/QA | Progress docs contradict shipped tree; `T4_PROGRESS.md` says integration is PENDING when it landed (§13) | T4 |
| 5 | **Low-Med** | T3 | `session_summary` persists `"Analysis unavailable."` into the DB at the worst moment; sync LLM call on request path (§18) | T3 |
| 6 | **Low** | T1 | `/health` always reports `database_connected: false` / `active_sessions: 0` (§8) | T1 |
| 7 | **Low** | T3 | Import-time `db.DB_PATH` binding; three DB-resolution conventions; `MIRAGE_PIPELINE_DB_PATH` never read (§12) | T3 |
| 8 | **Low** | T4 | `requirements.txt` unpinned — same drift that already broke the dashboard once (§14) | T4 |
| 9 | **Low** | T4 | Stale demo data in repo `data/mirage.db` renders as live activity in the monolith (§10) | T4 |
| 10 | **Info** | T2 | Offline, the LLM layer contributes only "command not found" — defensible honeypot posture, but operators should know (§9) | — |
| 11 | **Info** | T4 | `_redact`'s multi-marker loop degenerates to single-redaction (`while`-with-`break`) (§15 note 2) | T4 |

**Security findings: none.** All ten invariants in §4 held under direct adversarial probing. The two genuine security-adjacent bugs discovered during integration (T1 fallback leaking host identity `ubuntu`; T3 security-boundary rebuild lost in the merge) were already fixed in `25f3c54` and `8e55f99` respectively before this audit — both fixes verified in source and by tests.

---

## 20. T1 Foundation Layer — Deep Review (Pass)

- **ID discipline:** `sess_/cmd_/evt_` + `token_urlsafe(24)`, `is_valid_id` regex validated at every boundary. Live-probed with malformed IDs — uniform 404s, no stack traces, no timing divergence.
- **Pydantic boundary:** `app/api/schemas.py` validates `CommandRequest` (1–512 chars command), `SessionCreate` (typed source address/port/username), response models. `debug=False` + uniform error envelope confirmed.
- **Storage:** `app/storage/database.py` — all operations run through `asyncio.to_thread` (checked each method); WAL-mode SQLite; `_connect` per-call so the off-loop rule holds. 41 tests in `tests/foundation/test_database.py` (part of the 320).
- **Event bus:** in-process, bounded subscriber list, `publish` never blocks on slow consumers (fire-and-await with timeout); `test_event_bus.py` covers fan-out and failure isolation.
- **Session manager:** server-generated IDs only, lifecycle transitions validated; no client-supplied session identity anywhere.
- **Dispatcher:** chain-of-responsidence with the T3 handler registered; the T1 safe fallback sits behind it (unreachable in practice — see §17 — but harmless and correct as a last resort). The fallback handler's `_FALLBACK_HINTS` echo only the command's own first token as data (bounded to 32 chars); no host introspection (verified: `25f3c54` fixed the identity leak and `test_security.py` pins it with patched-to-raise host functions).
- **The decoy-identity fix (`25f3c54`)** deserves call-out as the most important single commit post-merge: without it, any T3-handler outage would have leaked the real host username through every fallback reply. The fix, its test, and the storage-default alignment are all present and green.

**Verdict: pass.** The only T1 finding is §8's health-field omission.

---

## 21. T4 Integration Layer — Deep Review (Pass with the §7 Caveat)

- **`T3PipelineHandler`** (`app/integration/pipeline_handler.py`): registers as a T1 `CommandHandler`, wraps the sync legacy pipeline in `asyncio.to_thread` (so the event loop never blocks on DB or LLM), maps `LegacyCommandRequest` → `process_command`, wraps output into `CommandResult` with `simulated: true` and `handler: t3_pipeline`. Correct in every live probe.
- **Session-state bridging:** the handler materializes a T3 pipeline session on the first command (T1 session IDs flow through as T3 session keys), so scoring/containment/summary all work without a second session concept leaking into the API. `test_pipeline_handler.py` asserts the canary trip produces the events the dashboard consumes.
- **Vertical slice** (`tests/integration/test_vertical_slice.py`): create session → run commands across all routing classes → read events → verify one-log-row-per-command. The audit's smoke run reproduced it independently.
- **Contract doc** (`T4_API_CONTRACT.md`): accurate against the code — endpoint tables, both DB planes, view-model field mapping, and the `CommandRequest`/`LegacyCommandRequest` resolution note all check out. This is the repo's best-quality doc.
- **The caveat is §7:** the dashboard half of T4's mandate is built twice, and the wrong half is wired. The integration half (handler, doc, tests) is exemplary; the dashboard half stopped one import short of done.

---

## 22. Deployment Posture (Not Yet Built — Confirmed)

`T4_PROGRESS.md`'s deployment section is the one stale claim that is *correctly* stale: no Dockerfile, no compose file, no CI config exists. The plan recorded there (single Dockerfile for the API, compose with API + dashboard on an internal network, only API ports published, no host mounts of `/` or `$HOME`, no privileged containers, no Docker socket) is sound for a honeypot.

**Deployment-relevant facts this audit adds:**
- Both DBs default into the repo tree (`data/`); in a container they need a volume *or* should be ephemeral by design (a honeypot's data is its product — persist it, back it up, treat it as untrusted input everywhere downstream).
- The dashboard must never be the exposed surface; only the API. The monolith's unredacted output tables (§7) are a stronger argument for the compose network-isolation plan than the plan itself states.
- `MIRAGE_DB_PATH` is the only env-var DB control honored (§12) — the compose file should set it explicitly rather than relying on defaults.
- Ollama, when live, must be localhost-bound (the provider pins `127.0.0.1:11434` — verified default and env-respected, both test-pinned).

**Recommendation:** before first real deployment, land §7's dashboard wiring and §17's exit-code fidelity; the deception quality is only as good as its most fingerprintable inconsistency.

---

## 23. What This Audit Could Not Verify

Stated plainly, with reasons:

1. **Live-Ollama deception quality** — no provider on the audit host. Every LLM-dependent behavior was exercised in its *offline* configuration (fallbacks, guardrails, repair caps, provider-absence contracts). The 4 skipped tests are exactly the live-provider smoke set; T2's report documents them passing under a live provider.
2. **Dashboard visual fidelity** — `AppTest`-level render is tested and passing; actual browser appearance (CSS, dark theme, dataframe styling) was not eyeballed by this audit.
3. **Concurrency under real SSH load** — the event-bus and to_thread patterns are correct by construction and test; no load test was run (out of audit scope).
4. **Git-history completeness** — 22 commits; the five September "v1" commits predate the team split and were treated as baseline, not audited line-by-line.
5. **`docs/architecture/T2_AGENT.md` and `docs/contracts/*` internal accuracy** — spot-checked against code (the T2 contract's acceptance criteria map to the §14 verification in `T2_REPORT.md`); not exhaustively diffed.

---

## 24. Recommended Next Actions (Priority Order)

1. **Wire the dashboard service/view layer** into `dashboard/dashboard.py` (or delete the layer and amend the contract). Add `test/test_dashboard_services.py` covering `MirageRepository` against a fresh DB. *(Owner: T4 — closes findings 1, 9, and 11; makes the redaction machinery real.)*
2. **Thread real exit codes** through `process_command` → `T3PipelineHandler` → `CommandResult`. Update the integration tests that pin `exit_code == 0`. *(Owner: T3+T4 — closes finding 2, the highest-value fidelity fix.)*
3. **Untrack `test/agent/_test_data/agent_test.db`**, add the directory to `.gitignore`. *(Owner: T2 — one command: `git rm --cached`.)*
4. **Stop persisting failure summaries**: `generate_and_store` should skip the write when the summary is the failure string; add the deterministic template. *(Owner: T3 — closes finding 5.)*
5. **Update all four progress docs** to reflect the merged tree; point each at this report for the delta. *(Owner: T4 — closes finding 4.)*
6. **Pin dependencies** in `requirements.txt` with safe ranges. *(Owner: T4 — closes finding 8.)*
7. **Populate `/health`'s `database_connected`/`active_sessions`** (or drop the fields from the liveness response). *(Owner: T1 — closes finding 6.)*
8. **Make pipeline DB path runtime-resolvable** (`MIRAGE_PIPELINE_DB_PATH` honored at connect time). *(Owner: T3 — closes finding 7; do this opportunistically, it's a comfort item.)*
9. Then, **build the deployment artifacts** per the recorded plan. *(Owner: T4 — §22.)*

Items 1–5 are one to two days of combined effort and would clear every Medium-or-higher finding.

---

## 25. Final Verdict

**PASS WITH FINDINGS — approved for next-stage work, not yet for production deployment.**

The four-team integration is genuinely complete and the security discipline that matters most — nothing executes on the host, the decoy identity never leaks, the LLM can't become an exfiltration channel, injection is data, containment escalates, everything is audited exactly once — **held up under every probe this audit could throw at it**, from source-level AST scans to live adversarial command sequences. 320 tests pass, freshly, twice. The two real security bugs that existed during the merge (host identity leak in the T1 fallback; the T3 security-boundary rebuild lost in the merge) were caught and fixed before this audit arrived, with tests pinning both fixes.

What remains is unglamorous: dead code that should have been the product (§7), an observability field that lies by omission (§8), a dirty-tree hygiene bug (§11), docs that say the finished work never happened (§13), and a fidelity gap a patient attacker could fingerprint (§17). None of these is a security hole. All of them are the difference between a demo that passes its tests and a honeypot an attacker believes for a week.

The recommended sequence in §24 clears every Medium-or-higher finding in one to two days. Until §7 and §17 land, treat the deployment boundary as "lab-ready"; after they land, the recorded deployment plan in §22 is safe to execute.

---

*Audit artifacts: this report (`AUDIT_REPORT.md`); fresh test runs on 2026-10-07 (`pytest test/ tests/` → 320 passed, 4 skipped, twice, tree clean after artifact restore per §11); live smoke transcripts in the audit session log. No source files were modified during this audit.*
