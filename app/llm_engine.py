"""T2 compatibility facade over the agentic deception engine.

Historical contract (preserved exactly):
    generate_response(command, cwd)              -> str   # router, containment
    generate_analysis(prompt)                    -> str   # threat_summary

New (optional, backward-compatible):
    generate_response(command, cwd, session_id=...)

Both delegate to ``app.agent`` (T2) via ``run_sync()``, which works from a
plain worker thread (``asyncio.run``) and from inside a running event loop
(fresh executor thread), because T1 may call this sync facade from either.

The legacy direct-HTTP-to-Ollama path is gone: every response now flows
through the typed, guardrail-approved AgentDecision pipeline with persona
consistency, session memory, prompt-injection defenses and a deterministic
fallback. Failure contract is unchanged ("command not found" style errors),
never a stack trace.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
from uuid import uuid4


def run_sync(coro):
    """Drive a coroutine to completion from synchronous code.

    - No running loop in this thread  -> ``asyncio.run`` (worker threads,
      ``asyncio.to_thread`` bodies, plain scripts).
    - Running loop in this thread     -> run the coroutine on a fresh thread
      and block until it finishes. Never blocks the loop's thread.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    # We are on the event loop's own thread (sync code called back from the
    # loop). Execute the coroutine on a private thread and wait for it.
    with ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, coro).result()


def _engine():
    from app.agent import get_agent_engine

    return get_agent_engine()


def generate_response(command: str, cwd: str, session_id: Optional[str] = None) -> str:
    """Simulated terminal output for an attacker command (T2 agent pipeline).

    Called by T1's router for non-VFS commands and by T3's containment for
    commands the VFS does not handle. Output is always guardrail-approved.

    Session-less calls (T3 containment's legacy signature) get an ephemeral
    per-call identity: no persistent "" session row is created, and nothing
    is shared between unrelated callers.
    """
    effective_session = session_id if session_id else f"_ephemeral_{uuid4().hex[:12]}"
    try:
        engine = _engine()
        decision = run_sync(engine.decide(effective_session, command))
    except Exception:
        # Contract preserved from the legacy engine: never raise, never leak.
        return "command not found"

    from app.agent import build_response_plan
    from app.agent.models import AgentAction

    plan = build_response_plan(decision)

    # Deferred actions: the facade's callers expect output, not a handoff,
    # so resolve the handoff inline (only reachable when a caller bypassed
    # T1's VFS routing, e.g. containment's fallthrough path).
    if decision.action is AgentAction.DEFER_TO_VFS:
        try:
            from . import vfs

            output, _ = vfs.execute_vfs_command(effective_session, command, cwd)
            return output if output is not None else ""
        except Exception:
            return ""
    if decision.action is AgentAction.DEFER_TO_SECURITY:
        return "Permission denied"

    # Apply state updates the decision proposed (allowlisted: cwd only).
    # Ephemeral sessions never persist state: there is no durable row to
    # update, and persisting one would recreate the ""-session leak.
    if plan.new_cwd and session_id:
        try:
            from . import db

            db.update_session(session_id, cwd=plan.new_cwd)
        except Exception:
            pass

    return plan.output if plan.output is not None else ""


def generate_analysis(prompt: str) -> str:
    """Free-form analyst text for T3's threat summary (provider-level call).

    Kept synchronous and failure-silent (returns "" on any provider error),
    matching the legacy contract used by ``threat_summary.get_live_summary``.
    """
    try:
        from app.agent import build_provider, get_agent_config
        from app.agent.models import LLMRequest

        cfg = get_agent_config()
        provider = build_provider(cfg)
        request = LLMRequest(
            prompt=prompt,
            temperature=0.1,
            max_output_tokens=1024,
            json_mode=False,
        )
        response = run_sync(provider.generate(request))
        return response.text.strip()
    except Exception:
        return ""
