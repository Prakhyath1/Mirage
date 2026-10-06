# T1 Foundation & Runtime — Architecture

Scope: the runtime foundation that every other MIRAGE team builds on.
T1 owns configuration, typed contracts, logging, the event bus, the
command pipeline, session management, storage, and the development API.

## Non-negotiable design rule

**ATTACKER INPUT MUST NEVER BECOME HOST OPERATING SYSTEM EXECUTION.**
Every byte an attacker sends is treated as *data*: validated at the
boundary, stored verbatim as forensic evidence, and answered with
**simulated** output. The terminal handler in the pipeline
(`SafeFallbackHandler`) is a static simulator — there is no code path
from attacker text to `subprocess`, `os.system`, `shell=True`, `eval` or
`exec`. The host filesystem is never exposed to attacker input.

## Component map

```
app/
├── config.py             Settings — env-driven (MIRAGE_*), safe defaults
├── models.py             frozen typed contracts (Session, CommandRequest,
│                         CommandResult, SecurityEvent, SessionSummary,
│                         HealthStatus) + enums
├── logger.py             structured logging (no secrets, no payloads)
├── main.py               FastAPI app factory + lifespan
├── core/
│   ├── ids.py            server-generated unguessable IDs + validation
│   └── result.py         RuntimeResult — failures as values
├── events/
│   └── bus.py            async in-process pub/sub, wildcard delivery
├── storage/
│   ├── schema.py         isolated DDL + SCHEMA_VERSION
│   └── database.py       sqlite3 via asyncio.to_thread; repositories
├── runtime/
│   ├── session_manager.py state machine + persistence + lifecycle events
│   ├── dispatcher.py      CommandDispatcher, CommandHandler protocol,
│   │                      SafeFallbackHandler
│   ├── ssh.py             SSH adapter contract (interface only)
│   └── service.py         MirageRuntime — composition root
└── api/
    ├── schemas.py         pydantic request/response models
    └── routes.py          thin routes → runtime calls
```

## Runtime flow (vertical slice)

```
HTTP / SSH adapter
        │  (validate everything at the boundary)
        ▼
MirageRuntime.submit_command(session_id, raw_command)
        │  ready check → session lookup → session/command validation
        ▼
CommandRequest.new(...)  ──bus──▶  command.submitted
        ▼
CommandDispatcher.dispatch
        │  1. persist intake (before any handler — evidence survives crashes)
        │  2. bus: command.dispatched
        │  3. run registered handlers (LIFO, claims-gated, exception-isolated)
        │  4. fall through to SafeFallbackHandler (simulation only)
        │  5. persist CommandResult
        ▼  6. bus: command.completed
CommandResult ──▶ HTTP response / channel
        │
        └─ every bus event is mirrored into storage by a subscriber
```

## Key decisions

**Failures are values.** `RuntimeResult` (`app/core/result.py`) carries
`ok/value/error_code/error_message` across module boundaries instead of
exceptions, so bad input degrades into a clean 400/404/422 response, and
the safe error codes (`command.too_long`, `session.not_active`, …) are
assertable in tests and greppable in logs.

**One funnel.** Every input source (dev REST today, AsyncSSH tomorrow)
enters through `MirageRuntime.submit_command`, so validation, event
emission, and evidence persistence cannot be bypassed by a new
transport. The SSH contract (`app/runtime/ssh.py`) exists precisely so
the transport task plugs in without touching validated runtime code.

**Event bus is wildcard and replaceable.** `subscribe(handler)` takes no
topic — all subscribers see all events and filter on `event_type`.
This keeps the interface trivially portable to Redis/ZeroMQ later (the
protocol is the same; only delivery changes). Handler errors are
isolated per-subscriber; publishing after close is a silent no-op.

**Storage is PostgreSQL-shaped.** sqlite3 runs through
`asyncio.to_thread`; all repository method signatures are written as
the async interface a PostgreSQL (asyncpg) driver would implement, with
the DDL quarantined in `app/storage/schema.py` behind `SCHEMA_VERSION`.
JSON columns are hard-capped at 256 KiB with a truncation sentinel so a
hostile payload cannot balloon the database; `stdout`/`stderr` round-trip
verbatim because they are simulated, trusted output. `events` carries
no FK so forensic records survive session pruning.

**Sessions are a strict state machine.** `CREATED → ACTIVE → CLOSED`
only; illegal transitions raise `SessionStateError`; double-close is
idempotent. IDs are server-generated `secrets.token_urlsafe`-derived and
validated by regex everywhere they re-enter the system.

**API routes are thin.** Routes validate (pydantic, `extra="forbid"`,
ID regex, length caps) and delegate to the runtime; all errors go
through one envelope `{"error", "message"}` — never a stack trace.

## Configuration

All settings come from `MIRAGE_*` environment variables (optionally
seeded from `.env`), with safe local defaults (`MIRAGE_ENV=development`
binds `127.0.0.1`, SQLite under `data/`). No secret has a default; no
secret is ever logged (`Settings.safe_summary()` exposes only safe
fields). Key knobs: `MIRAGE_ENV`, `MIRAGE_HOST/PORT`, `MIRAGE_DB_PATH`,
`MIRAGE_LOG_LEVEL`, `MIRAGE_MAX_COMMAND_LENGTH` (2048),
`MIRAGE_MAX_SESSIONS`, `MIRAGE_MAX_EVENT_PAYLOAD_BYTES`,
`MIRAGE_SECURITY_MODE` (default `strict`).

## Logging

Structured JSON via `app/logger.py`: timestamp, level, component,
message, plus optional `session_id` / `command_id` for correlation.
Commands are logged as metadata, never executed; payloads are not
dumped wholesale into logs; no credentials at any level.

## Testing

`pytest` with `asyncio_mode=auto` (`pytest.ini`). Foundation tests in
`tests/foundation/` (models, database, session manager, dispatcher,
event bus, API); the required vertical slice in
`tests/integration/test_vertical_slice.py` drives the whole stack over
HTTP and asserts both the retrievable record trail and the
malicious-input-never-executed invariant. Tests run locally against a
throwaway SQLite file; no network and no host execution are required.

## What is deliberately NOT here

T2 (LLM agent), T3 (VFS, honeytoken detection, MITRE tagging, sandbox),
and T4 (dashboard) features. Their integration points are the
`CommandHandler` protocol (T2/T3), `EventType` dotted-string extension
and bus subscription (T2/T3), the repository/`SessionSummary.metrics`
surface (T4), and `SSHTransportObserver` (future SSH task).
