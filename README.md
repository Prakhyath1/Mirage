# MIRAGE — Deceptive-Response Honeypot

MIRAGE is an SSH-tarpit-style honeypot that never executes an attacker's
commands on the host. Instead, every command is analyzed, classified, and
answered with a **simulated response** that maintains a consistent fake
machine identity — an agentic deception engine makes unknown commands feel
real, while VFS-owned and identity commands are answered deterministically.

```
attacker command
      │
      ▼
T1 runtime (FastAPI)  ──containment──▶ T3 containment (deception about containment)
      │
      ▼
T1 router  ──VFS-owned?──▶ T3 virtual filesystem (deterministic simulation)
      │
      ▼
T2 agent engine (this repo's intelligence layer)
      │
      ├── deterministic answers (whoami/id/date/…, priv-esc denials)
      ├── contextual LLM deception (structured output + guardrails)
      └── safe fallback on any LLM failure ("command not found"-style)
      │
      ▼
T4 observability (Streamlit dashboard over the events/logs tables)
```

## Quick start

```bash
# 1. deps
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. (optional) configure — defaults work out of the box; see below
cp .env.example .env 2>/dev/null || true

# 3. run the honeypot API
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000

# 4. run the dashboard (T4)
.venv/bin/streamlit run dashboard/dashboard.py
```

The prototype ships with `LLM_PROVIDER=ollama` pointing at a local
`qwen2.5:3b` — install [Ollama](https://ollama.com) and `ollama pull
qwen2.5:3b` for live LLM deception. With no Ollama running, the engine
degrades to deterministic fallback responses and stays fully functional.

## Configuration

All knobs are environment variables (optionally `.env` at repo root, loaded
by `python-dotenv`); malformed values fall back to defaults. Full table in
`T2_REPORT.md` §12; the essentials:

| Variable | Default | Meaning |
|---|---|---|
| `LLM_PROVIDER` | `ollama` | provider registry key (`mock` for offline tests) |
| `LLM_BASE_URL` | `http://127.0.0.1:11434` | provider endpoint |
| `LLM_MODEL` | `qwen2.5:3b` | deception model |
| `LLM_TIMEOUT` | `30` | seconds per provider call |
| `AGENT_ENABLE_GUARDRAIL` | on | kill-switch for the output guardrail layer |
| `AGENT_MAX_LLM_CALLS_PER_DECISION` | `2` | hard cap on provider calls per decision |
| `AGENT_REPAIR_ATTEMPTS` | `1` | bounded structured-output repair retries |
| `MIRAGE_PERSONA_HOSTNAME` | `web-prod-01` | simulated hostname (and siblings for the rest of the identity) |

## Security invariants

- **Nothing an attacker types ever reaches a host shell** — `AgentAction`
  has no host-execution member; every response is simulated data.
- **LLM output is never trusted** — structured JSON → typed model → rule
  guardrail → size/content bounds; violations fall back deterministically.
- **Prompt-injection hardened** — trust-tiered prompt with non-forgeable
  delimiters, injection detection, zero-width character stripping; suspect
  input is analyzed as data and flagged, never obeyed.
- **Fail-closed to deception** — any LLM/provider/parse failure produces a
  persona-consistent deterministic fallback, never an error leak.
- **Ephemeral callers stay isolated** — session-less calls share no DB
  rows, no events, and no memory with any other caller.

## Testing

```bash
# full agent suite (offline; no Ollama, no network)
.venv/bin/python -m unittest discover -s test -p "test_*.py" -v

# the T2 suite alone
.venv/bin/python -m unittest discover -s test/agent -p "test_*.py" -v
```

## Repository layout

```
app/            T1 (runtime: main.py, router.py, db.py, logger.py, config.py, models.py)
app/agent/       T2 — agentic deception engine (models, config, context, memory,
                decision, engine, guardrails, fallback, parser, persona, prompts,
                providers, trust, tools)
app/vfs.py       T3 — virtual filesystem
app/behavior.py  T3 — threat scoring (THREAT_KEYWORDS, score, level)
app/containment.py  T3 — containment once thresholds trip
dashboard/      T4 — Streamlit observability over the shared SQLite DB
test/agent/     offline unittest suite for the engine (stdlib unittest)
data/mirage.db  runtime SQLite (sessions, logs, events, virtual_files)
```

## Task boundaries

MIRAGE is built by four collaborating tasks. T2 (this engine) owns
`app/agent/`, `app/llm_engine.py` (compat facade), `test/agent/`, and the
integration lines inside `app/main.py` + `app/router.py`. T3 owns
`vfs.py`/`behavior.py`/`containment.py`; T4 owns `dashboard/`. Shared-file
changes are kept minimal and documented in `T2_REPORT.md` §5.
