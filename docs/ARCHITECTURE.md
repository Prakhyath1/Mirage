# Mirage Architecture

Mirage is an SSH-style honeypot. Attackers land in a fully simulated Linux
environment (the **sandbox**); every command is parsed, classified, scored,
and logged — nothing ever touches the host filesystem, network, or processes.

## Layers

```
T1  API surface        app/main.py        FastAPI (POST /command, /session_summary, /health)
T2  Intelligence       app/llm_engine.py  Ollama fallback responses + threat summaries
                       app/threat_summary.py
T3  Simulation core    app/router.py      pipeline orchestrator (see below)
                       app/sandbox.py     execution boundary — the ONLY execution path
                       app/vfs/           virtual filesystem, parser, path resolver
                       app/classifier.py  command classification
                       app/simulated/     fake processes, network, services
                       app/behavior.py    pattern detection + risk scoring
                       app/containment.py legacy facade (unwired) — policy
                                           is enforced inside app/sandbox.py
                       app/honeytokens.py canaries
T4  Reporting          dashboard/         Streamlit operator view (dashboard/dashboard.py)
                       docs/CONTRACTS.md  downstream (T4) API contracts
```

## Command pipeline

```
POST /command
  └─ router.process_command(session_id, command)
       1. db.get_or_create_session()       session state (cwd, threat score)
       2. behavior.update_session_threat() risk scoring FIRST (T2 summaries on
                                           escalation), so a command that pushes
                                           the session to High is contained on
                                           the next turn
       3. parser.parse()                   tokens, pipes, redirects — and the
                                           dispatch decision: parsable →
                                           sandbox, anything else → LLM engine
       4. sandbox.execute()                the single execution AND logging
                                           choke point: classifies each stage
                                           (SAFE | RECON | SENSITIVE |
                                           DESTRUCTIVE | UNKNOWN), enforces the
                                           containment policy, and writes the
                                           command row itself
       5. llm_engine.generate_response()   fallback for unparsable commands;
                                           the router writes that row itself
```

Containment policy (STEP 8): SAFE commands run normally; SENSITIVE run but are
flagged and get degraded output; DESTRUCTIVE are blocked with realistic errors
once containment is active; UNKNOWN goes to the LLM engine (T2), never to the host.

## Security invariants

1. **No host access.** The sandbox resolves every path through
   `path_resolver`, anchored at the VFS root. `..`, absolute host paths,
   and symlink-style tricks resolve inside the virtual tree or fail — never
   to the real filesystem.
2. **No real execution.** Every command is simulated (VFS builtin, simulated
   service, or LLM text). No `subprocess`, no shell, no sockets to real hosts.
3. **Bounded resources.** Output size, argument count, and command length are
   capped (`config.py`) so the sandbox can't be used to exhaust memory.
4. **Honeytokens are tripwires.** Any read of a canary file raises a
   HONEYTOKEN_ACCESS event; tokens are seeded per-session and can't be
   distinguished from real bait by path alone.

## Database

SQLite at `data/mirage.db`. Tables: `sessions`, `logs`, `virtual_files`,
`events`. Schema is additive-only: new columns go through `migrate_*`
functions so existing deployments upgrade in place.
