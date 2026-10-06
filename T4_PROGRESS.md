# T4 Progress — Integration, Dashboard, Threat Intelligence & QA

**Branch:** `team/t4-integration`
**Last updated:** 2026-10-05
**Engineer:** T4 (Integration, Dashboard, Threat Intelligence, QA, Deployment)

---

## STATUS

Active. Investigation phase complete; integration checkpoints in progress.

Integration baseline decision (from branch inspection, all three teams share
merge-base `f37ab14`):

| Branch | Role | Key surface |
|---|---|---|
| `origin/team/t1-foundation` | T1 Foundation | `create_app()` FastAPI factory, `MirageRuntime`, event bus, `app/storage/`, dev API (`/health`, `/ready`, `/dev/*`), frozen dataclass contracts in `app/models.py` |
| `origin/team/t2-agentic` | T2 Agentic | `app/agent/` package, `llm_engine.py` facade (`generate_response(command, cwd, session_id=)`), mock provider (offline-capable), guardrails |
| `origin/t3` | T3 Security | `app/vfs/` package, `sandbox.py`, `classifier.py`, behavior scoring, honeytokens, legacy pipeline in `app/router.py`, T4-facing HTTP endpoints (`/command`, `/session/{id}`, `/session/{id}/events`, `/session/{id}/honeytokens`, `/health`), `docs/CONTRACTS.md` |

Known deliberate conflict resolutions (documented, not silent):

1. `app/models.py` — T1 owns the foundation dataclasses; T3's pydantic API
   DTOs are additive. T3's `CommandRequest` (pydantic, HTTP body) is renamed
   `LegacyCommandRequest` to avoid clashing with T1's frozen dataclass of the
   same name.
2. `app/main.py` — T1's `create_app` is authoritative. T3's endpoints are
   re-mounted at their documented paths via a T4-owned adapter module.
3. `app/config.py` — T1's `Settings` class + T3's tuning constants coexist;
   T3's constants are additive (no framework duplication).
4. `app/router.py` — T3's dispatch chain + T2's `session_id` pass-through.
5. Databases are **separate files by design** (T1: `data/mirage_foundation.db`,
   legacy pipeline: `data/mirage.db`) — T1 anticipated this; the dashboard
   reads both through a repository layer.

T2 handoff notes for T4 (from `T2_PROGRESS.md`, to be fixed by T4):

- [x] Dashboard infinite-refresh loop (top-of-script `st.rerun()`) — fix with
      `@st.fragment(run_every=...)` (fixed in new dashboard build)
- [x] `Styler.applymap` removed in pandas ≥ 2.1 — new dashboard avoids
      Styler entirely

---

## COMPLETED

- Repository investigation (structure, contracts, tests, config, all three
  team branches inspected via `git show` — no speculation)
- Integration plan with explicit conflict-resolution decisions
- T4 ownership boundaries respected: no T1/T2/T3 internals modified

## IN_PROGRESS

- Integration checkpoint 1: merge `team/t1-foundation`
- Then: checkpoint 2 (`origin/t3`), checkpoint 3 (`team/t2-agentic`)
- T4 dashboard rebuild (`dashboard/` service + pages architecture)

## INTEGRATION_STATUS

| Checkpoint | Target | State |
|---|---|---|
| 1 | T1 foundation | IN PROGRESS |
| 2 | + T3 deterministic simulation | PENDING |
| 3 | + T2 agentic layer | PENDING |
| 4 | Vertical slice (T1+T2+T3) | PENDING |
| 5 | T4 dashboard integration | PENDING |
| 6 | Full security/e2e validation | PENDING |
| 7 | Demo/deployment build | PENDING |

## TESTS

- T1 suite present (`tests/foundation/*`, `tests/integration/test_vertical_slice.py`)
- T2 suite present (`test/agent/*`, mock-provider offline)
- T3 suite present (`test/test_security.py`, `test/test_dashboard.py`)
- T4 suites to be added under `tests/integration/`, `tests/e2e/`, `tests/contract/`

## SECURITY_VERIFICATION

Planned cross-system security tests (T4 verifies, does not implement):

1. Attacker input cannot execute on host
2. T2 cannot invoke arbitrary shell execution
3. VFS cannot escape virtual root
4. Dashboard cannot mutate attacker environment
5. No secrets in dashboard output
6. Host filesystem not exposed
7. Malformed events do not crash dashboard
8. Unavailable LLM degrades gracefully
9. Database failure handled gracefully
10. Invalid session IDs rejected safely

## KNOWN_ISSUES

- Harness Bash classifier intermittently unavailable (2026-10-05) — retrying
  write commands with backoff; read-only verification unaffected.

## CONTRACT_ISSUES

None open. The `CommandRequest` name collision (T1 dataclass vs T3 pydantic
DTO) is resolved additively by renaming the T3 DTO to `LegacyCommandRequest`
where it is used as an HTTP body schema; T1's dataclass keeps the canonical
name. This is documented in `docs/integration/T4_API_CONTRACT.md` once written.

## DEPLOYMENT_STATUS

Pending. Plan: single Dockerfile (API) + docker-compose with API, dashboard
on an internal network, only API ports published; no host mounts of `/` or
`$HOME`, no privileged containers, no Docker socket.

## NEXT_TASK

1. Merge T1 (checkpoint 1), run T1 test suite.
2. Merge T3 (checkpoint 2), resolve `app/models.py`/`app/config.py`/
   `app/main.py`/`app/router.py` per the documented plan, run T3 suite.
3. Merge T2 (checkpoint 3), fold `session_id` pass-through into the merged
   router, run T2 offline suite.
4. Build the T4 dashboard on the service/repository layer.
