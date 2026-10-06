# T4 API & Data Contract

**Owner:** T4 · **Consumers:** dashboard, integration tests, future SIEM/STIX
exporters · **Rule:** T4 consumes T1/T2/T3 public contracts; it never
re-implements backend logic.

This document defines the two data planes T4 reads, and the typed view-models
the dashboard is allowed to use. Where a backend type already exists, T4
adapts it; T4 does not duplicate domain logic.

---

## 1. Data planes

MIRAGE has two persisted data planes, deliberately separate files:

| Plane | Owner | File | Written by |
|---|---|---|---|
| Foundation runtime | T1 | `data/mirage_foundation.db` (config: `MIRAGE_DB_PATH`) | `app/runtime/*`, `app/storage/*` |
| Deception pipeline (legacy T3/T2 pipeline) | T3/T2 via legacy `app/db.py` | `data/mirage.db` | `app/router.process_command`, honeytokens, behavior scoring |

T4 reads **both** through `dashboard/services/` adapters. The dashboard
never writes to either database.

### Foundation endpoints (T1, mounted at root by `create_app`)

| Endpoint | Method | Purpose |
|---|---|---|
| `/health` | GET | Liveness + component status (`HealthStatus`) |
| `/ready` | GET | Readiness (DB reachable, event bus up) |
| `/dev/sessions` | POST | Create development session (trusted/dev entry) |
| `/dev/sessions/{session_id}` | GET | Session summary |
| `/dev/sessions/{session_id}` | DELETE | Close session |
| `/dev/sessions/{session_id}/commands` | POST | Submit one attacker command (simulated) |

All requests are pydantic-validated (`app/api/schemas.py`); session IDs are
validated by `app/core/ids.is_valid_id` (server-generated, unguessable).
Stack traces never leave the process (`debug=False`, uniform error envelope).

### Deception-pipeline endpoints (T3, re-mounted by the T4 integration adapter)

| Endpoint | Method | Response model |
|---|---|---|
| `/command` | POST | `{"output": str}` — simulated output only |
| `/session_summary/{session_id}` | GET | `SessionSummaryResponse` (stored + live summary) |
| `/session/{session_id}` | GET | `SessionInfo` (threat score/level, containment, cwd) |
| `/session/{session_id}/events?limit=N` | GET | `list[EventInfo]` newest first |
| `/session/{session_id}/honeytokens` | GET | `list[HoneytokenInfo]` (metadata only, never content) |
| `/health` | GET | component status |

Notes:
- `/command` accepts `session_id` (1–128 chars) + `command` (1–512 chars).
  Commands are classified (SAFE/SENSITIVE/DESTRUCTIVE/RECON/UNKNOWN),
  optionally containment-blocked, then simulated by the VFS (T3) or the T2
  agent engine. **Nothing executes on the host.**
- Legacy T1 path `/legacy/command` and `/legacy/session_summary/{id}` also
  exist (T1's compatibility mount over the same pipeline).

### T2 agent events (consumed as data)

T2 emits `AGENT_*` security events through the same persistence seam; T4
visualizes them as **agent decisions**, never re-computing them.

---

## 2. T4 view-models (`dashboard/services/models.py`)

T4 adapts backend rows into frozen view-models. These are *read-only
projections* — if a field is absent in the backend, it is `None`, never
invented:

| Model | Key fields | Source |
|---|---|---|
| `DashboardSession` | session_id, created_at, last_seen, status, source, username, cwd, command_count, threat_score, threat_level, containment_active, plane (`foundation`/`pipeline`) | both planes |
| `DashboardCommand` | command_id, session_id, raw_command, timestamp, working_directory, result_output (truncated), result_type, source | both planes |
| `DashboardSecurityEvent` | event_id, timestamp, session_id, event_type, severity, command_id, details, plane | both planes |
| `HoneytokenEvent` | path, token_type, tripped, last_accessed, session_id, evidence | T3 pipeline |
| `MitreObservation` | technique_id, name, confidence, sessions, first_seen, last_seen, evidence | derived from T3 classification + event evidence |
| `AgentObservation` | decision_id, session_id, action, reasoning (bounded), confidence, used_fallback | T2 `AGENT_*` events |
| `SystemHealth` | component, status, detail, latency_ms, checked_at | `/health`, `/ready`, DB probes |
| `ThreatObservation` | observation_id, session_id, timestamp, category, severity, confidence, technique_id, evidence, metadata | normalized union (see §3) |

Rules:
- `raw_command` and `output` are displayed but always treated as **untrusted
  data** (escaped, never evaluated, never executed).
- No field may carry secrets: the adapters strip/deny keys matching
  `password|secret|token|api_key|credential` (same marker set as T1 config).
- Every metric must trace to a backend row/event. Empty backend → "No data
  available", never a fake number.

---

## 3. ThreatObservation (normalized TI object)

The single normalized structure T4 derives from actual MIRAGE data:

```text
ThreatObservation:
    observation_id   str          # "obs_<hash12>"
    session_id       str | None
    timestamp        float        # epoch UTC
    category         str          # e.g. RECON, SENSITIVE, DESTRUCTIVE,
                                 #      HONEYTOKEN, AGENT_DECISION, SESSION
    severity         str          # LOW | MEDIUM | HIGH (from backend only)
    confidence       float        # 0.0-1.0, from backend score mapping
    technique_id     str | None   # MITRE ATT&CK id from T3 mapping
    evidence         str          # bounded, redacted summary
    metadata         dict         # bounded key/value, secret-stripped
```

Severity is **never invented by T4**: it is mapped 1:1 from backend fields
(`threat_level`, event type weights defined by T3). MITRE technique IDs come
from T3's classification mapping (see §4).

## 4. MITRE ATT&CK mapping (T3-owned, T4-visualized)

T3's classifier maps command categories to ATT&CK techniques. T4 only
renders what T3 recorded. Techniques actually reachable in the live pipeline:

| T3 category | Technique | Name |
|---|---|---|
| RECON (`nmap`, port scans, `who`, network probes) | T1046 | Network Service Discovery |
| RECON (`ls`, `find`, directory walking) | T1083 | File and Directory Discovery |
| SENSITIVE (`cat` on canary paths, `/etc/*` reads) | T1005 | Data from Local System |
| DESTRUCTIVE (`rm -rf` et al.) | T1485 | Data Destruction |
| DESTRUCTIVE (blocked under containment) | T1499 | Endpoint Denial of Service (flag only when T3 emits it) |
| HONEYTOKEN_ACCESS | T1552.001 | Unsecured Credentials: Credentials In Files |

(If T3's classifier records a different id, T3 wins — T4 renders the id in
the events, it does not re-map.)

## 5. Export abstractions (future STIX 2.1 / SIEM)

`dashboard/services/exports.py` provides:

- `to_json_events(...)` — structured JSON security-event export (always
  available, no extra dependency).
- `STIXExportAdapter` / `SIEMExportAdapter` — interfaces with a JSON
  implementation; a real STIX/TAXII library can plug in later without
  touching call sites. A webhook sender, if configured, requires explicit
  `MIRAGE_WEBHOOK_URL`, validates the URL scheme, enforces a timeout, and
  sends only redacted `ThreatObservation` payloads.

Exports contain **only** fields listed in §2/§3. No host paths outside the
VFS, no environment variables, no secrets.
