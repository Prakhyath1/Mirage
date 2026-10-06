# Mirage T3 Contracts

Interfaces between layers. These are the seams T4 (reporting/dashboard) and
external consumers code against; changes here are additive-only.

## T1 → T3 (HTTP API)

### `POST /command`
Request:
```json
{ "session_id": "string (1-128 chars)", "command": "string (1-512 chars)" }
```
Response:
```json
{ "output": "string" }
```
Validation via `app/models.py:CommandRequest` (Pydantic). Errors: 400-level
validation from Pydantic; 500 with a generic message (internal details are
logged, never returned to the client — the honeypot API faces untrusted input).

### `GET /session_summary/{session_id}`
Response:
```json
{ "session_id": "...", "stored_summary": "...", "live_summary": "..." }
```
404 when the session does not exist.

### `GET /session/{session_id}` — session state for the T4 dashboard
```json
{
  "session_id": "...",
  "threat_score": 0,
  "threat_level": "Low|Medium|High",
  "containment_active": false,
  "cwd": "/home/admin",
  "created_at": 1234567890.0,
  "last_seen": 1234567890.0
}
```

### `GET /session/{session_id}/events?limit=50`
Security events, newest first:
```json
[ { "event_type": "SANDBOX_BLOCK|CONTAINMENT_ACTIVATED|HONEYTOKEN_ACCESS", "session_id": "...", "details": "...", "timestamp": 1234567890.0 } ]
```
These three are what the live pipeline emits: `SANDBOX_BLOCK` is what a
DESTRUCTIVE command under containment produces (sandbox.py, the single choke
point), `CONTAINMENT_ACTIVATED` fires when behavior scoring escalates a
session to High, and `HONEYTOKEN_ACCESS` when a canary is read.
`CONTAINMENT_BLOCK`/`CONTAINMENT_SENSITIVE`/`HONEYTOKEN_PLANTED` are defined
but unreachable in the live dispatch (legacy `containment.handle_containment`
facade and the never-called `honeytokens.register`).

### `GET /session/{session_id}/honeytokens`
Planted canaries and their trip status:
```json
[ { "path": "/home/admin/.env", "is_honeytoken": true, "tripped": false, "last_accessed": null } ]
```

### `GET /health`
```json
{ "status": "online" }
```

## T3 internal contracts (module seams)

| Seam | Contract |
|---|---|
| `router.process_command(session_id, command)` | Returns the output string. Scores first, then executes via the sandbox (the single choke point). Logs exactly once: the sandbox logs the commands it runs; the router logs its own row only on the LLM-direct branch (empty/unparsable input). |
| `sandbox.execute(session_id, command, cwd, containment=False)` | Returns the output string. Enforces the containment policy itself — DESTRUCTIVE blocked, SENSITIVE degraded — so no dispatch path bypasses it. Falls back to the LLM engine for non-VFS commands. Never touches the host. **Single logging point:** every executed command lands in `logs` exactly once, here. Callers that bypass the sandbox (router's and containment's LLM-direct branches) log their own row. |
| `vfs.execute_vfs_command(session_id, command, cwd)` | Returns `(output\|None, new_cwd)`. `None` = not a VFS builtin. |
| `vfs.parser.parse(command)` | Returns a `Pipeline` (stages, redirect, raw) or raises `ParseError`. Pure text — no shell. |
| `classifier.classify(pipeline)` / `classify_stage(argv)` | Returns one of `config.CATEGORY_SAFE/RECON/SENSITIVE/DESTRUCTIVE/UNKNOWN`. Argv-based, not substring-based. |
| `path_resolver.resolve(cwd, target)` | Pure-string resolution anchored at the virtual root; raises `PathEscapedError` on escape attempts. `safe_resolve()` returns `None` instead. |
| `behavior.calculate_score(command)` / `get_threat_level(score)` | Risk scoring from parsed categories; thresholds in `config.THREAT_LEVELS`. |
| `honeytokens.trip(session_id, path)` | Records `HONEYTOKEN_ACCESS` and escalates the session threat score. |
| `simulated.nmap_scan/ps_output/netstat_output/ssh_probe` | Pure string generation for fake hosts/services/processes. No sockets, no subprocess. |
| `db.*` | SQLite, additive-only schema (`migrate_*` functions add columns; nothing is altered or dropped). |
| `llm_engine.generate_response(command, cwd)` | Ollama fallback for unknown commands. Timeout-bounded. |

## Security invariants (all layers)

1. **No host filesystem access** — every path is a virtual string resolved by
   `path_resolver` anchored at `/`. No `os.path.realpath` on attacker input,
   no file I/O outside `data/mirage.db`.
2. **No real execution** — no `subprocess`, no sockets. Unknown commands go to
   the LLM engine, which is also sandboxed to string generation.
3. **Bounded resources** — command length, arg count, output size
   (`MAX_OUTPUT_LENGTH`, enforced in the sandbox), file size, list entries,
   session file count (`MAX_SESSION_FILES`, new creations refused past the
   cap; overwrites allowed), path depth all capped in `app/config.py`.
4. **Honeytokens as tripwires** — canary reads raise `HONEYTOKEN_ACCESS`
   events and escalate the threat score; the escalation recomputes the
   threat level immediately and activates containment on the spot when it
   lands in High.
5. **Credential containment** — `/etc/shadow` content never reaches an
   attacker, containment or not (the VFS refuses the read by resolved path
   and the sandbox degrades on top); output returns `Permission denied`.
6. **Fake identity** — the honeypot presents `admin`/`mirage` (fixed decoys in
   `config.py`), never the host's real username or hostname. No module in
   `app/` calls identity/process/network APIs (`os.getlogin`, `os.environ`
   lookups, `socket`, `subprocess`, `shutil`) — enforced by
   `test_no_identity_or_net_or_process_apis_in_source`.
7. **Audit trail** — every command produces exactly one `logs` row,
   whichever dispatch path handled it (single logging point in
   `sandbox.execute`; LLM-direct branches log their own row).
