# Mirage

An SSH-style honeypot that simulates a believable Linux host — virtual
filesystem, fake network, simulated processes — while recording attacker
behavior and containing anything dangerous. Everything runs inside the
honeypot's own sandbox; the host machine is never touched.

## Architecture

Four layers (see `docs/ARCHITECTURE.md` for the full picture and
`docs/CONTRACTS.md` for every interface):

| Layer | Role | Code |
|---|---|---|
| T1 | FastAPI command API | `app/main.py` |
| T2 | Intelligence — LLM fallback, threat summaries | `app/llm_engine.py`, `app/threat_summary.py` |
| T3 | Simulation core — VFS, parser, classifier, sandbox, containment, behavior, honeytokens | `app/vfs/`, `app/classifier.py`, `app/sandbox.py` (enforces containment), `app/containment.py` (legacy facade, unwired), `app/behavior.py`, `app/honeytokens.py` |
| T4 | Reporting — operator dashboard | Streamlit (`dashboard/dashboard.py`) |

Command pipeline: **session → risk score → parse → sandbox.execute (classify + contain + log) → LLM fallback**

The sandbox is both the single execution choke point and the single logging
point: every command lands in the `logs` table exactly once, whichever path
dispatched it.

## How it works

1. Every command is parsed into a pipeline (`app/vfs/parser.py`) — argv
   lists, redirection, pipes. No shell is ever spawned.
2. The classifier (`app/classifier.py`) maps each stage to SAFE / RECON /
   SENSITIVE / DESTRUCTIVE / UNKNOWN, from the parsed argv rather than
   substring matching.
3. Behavior scoring (`app/behavior.py`) accumulates a per-session threat
   score; reaching **High** auto-activates containment.
4. The sandbox (`app/sandbox.py`) is the single execution choke point.
   Under containment: DESTRUCTIVE commands are blocked with realistic
   errors, SENSITIVE output is degraded so credentials never leak.
5. Honeytokens (`app/honeytokens.py`) — fake credential files planted in
   the session (`/etc/shadow`, `.env`, `aws_credentials.txt`,
   `db_backup.sql`) — trip a `HONEYTOKEN_ACCESS` event the moment they are
   read, and escalate the session's threat score.
6. Unknown commands fall back to the LLM engine (`app/llm_engine.py`,
   Ollama), which generates simulated output — never real execution.

## Security invariants

- **No host filesystem access** — all paths are virtual strings resolved by
  `app/vfs/path_resolver.py`, anchored at `/`.
- **No real execution** — no subprocess, no sockets, anywhere.
- **Bounded resources** — command length, args, output, files, path depth
  capped in `app/config.py`.
- **Fake identity** — the honeypot presents a fixed decoy user (`admin`) and
  hostname (`mirage`), never the host's real ones.
- **Credential containment** — protected file content never reaches an
  attacker.

## Running

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Operator dashboard (separate terminal):

```bash
streamlit run dashboard/dashboard.py
```

Endpoints: `POST /command`, `GET /session_summary/{id}`, `GET /session/{id}`,
`GET /session/{id}/events`, `GET /session/{id}/honeytokens`, `GET /health`.

Optional LLM fallback: Ollama at `127.0.0.1:11434` (model `qwen2.5:3b`).
Without it, unknown commands get a generic simulated response.

## Testing

```bash
python3 -m pytest test/ -v
```

Requires `pytest` (`pip install pytest`). The Ollama smoke check is skipped
automatically when Ollama is not running; everything else is hermetic — no
network, no host access.

Security tests cover path-escape attempts, containment blocks, honeytoken
trips, and host-leakage checks (fake identity everywhere, no host paths in
any output, and no identity/process/network APIs anywhere in `app/`).
Dashboard tests (`test/test_dashboard.py`) render the operator view headlessly
via Streamlit's AppTest, including the sys.path anchoring a bare `streamlit
run` depends on.

## Data

SQLite at `data/mirage.db` — sessions, command logs, virtual files, and
security events. Schema changes are additive-only (`migrate_*` functions).
