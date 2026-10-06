"""Adapter: T3's deception pipeline as a T1 ``CommandHandler``.

T1's dispatcher asks registered handlers, in order, to produce a
:class:`CommandResult` for a validated :class:`CommandRequest`. This
module makes T3's command pipeline (parse → classify → score → sandbox)
available under that protocol without touching either team's internals:

    T1 dispatcher ──▶ T3PipelineHandler.handle(request)
                          └─ app.router.process_command(session_id, command)
                               ├─ T3 behavior scoring + containment
                               ├─ T3 sandbox / VFS simulation
                               └─ T2 llm_engine (UNKNOWN commands),
                                  all inside T3's single choke point

Why ``process_command`` and not direct VFS calls: it is the documented
pipeline entry (T3 STEP 15) that the standalone T3 FastAPI app already
uses, so the merged app exercises the exact same code path, logging, and
containment semantics as the T3 service. No logic is duplicated.

Session ids: T3's pipeline keys all state on ``session_id``; T1's runtime
generates and validates its own session ids — passing T1's id through to
the pipeline keeps per-session threat scoring, VFS state, and honeytoken
seeding intact. T2's ``llm_engine.generate_response(command, cwd,
session_id=...)`` accepts an optional session id (T2's handoff note), so
agent events land in the same session record automatically.
"""
from __future__ import annotations

import asyncio
import time

from app.models import CommandRequest, CommandResult, ResultType
from app.runtime.service import MirageRuntime


class T3PipelineHandler:
    """Runs commands through T3's pipeline (sync pipeline, async wrapper).

    SECURITY: the only code path invoked is T3's ``process_command``
    (parse → classify → score → sandbox.execute / llm_engine) — the same
    no-host-execution guarantee the standalone T3 app provides. Nothing
    in this class runs a subprocess, touches the real filesystem, or
    makes network calls (the LLM endpoint call is T2's, bound by T2's
    own guardrails and timeout config).
    """

    name = "t3_pipeline"

    def __init__(self, call_timeout: float = 30.0):
        # Not enforced with asyncio.wait_for: T3's LLM path already has
        # T2-configured timeouts; an extra hard kill could cut a graceful
        # fallback short. Kept as a bound for metadata only.
        self._timeout = call_timeout

    async def handle(self, request: CommandRequest) -> CommandResult:
        started = time.monotonic()
        try:
            from app import router as t3_router  # deferred: post-merge module

            output = await asyncio.to_thread(
                t3_router.process_command, request.session_id, request.raw_command
            )
            return CommandResult.new(
                command_id=request.command_id,
                stdout=str(output),
                exit_code=0,
                duration=time.monotonic() - started,
                result_type=ResultType.VFS,
                metadata={
                    "handler": self.name,
                    "pipeline": "t3",
                    # Same simulation flag the T1 fallback sets: the API
                    # layer reports ``simulated`` from this metadata key.
                    "simulated": True,
                },
            )
        except Exception:
            # Propagate: the T1 dispatcher's isolation policy logs the
            # failure, emits a runtime-error event, and falls through to
            # the next handler — T1's SafeFallbackHandler answers the
            # attacker with a simulated result, so the outage never
            # surfaces as an error (and never executes anything).
            raise

    def claims(self, request: CommandRequest) -> bool:
        """Claims every command: the T3 pipeline is the primary handler."""
        return True


def attach_default_handlers(service, *, include_t3: bool = True) -> None:
    """Register the T4 adapters on a T1 application/service object.

    Called from the merged ``app/main.py`` after ``create_app`` so the
    vertical slice (T1 intake + T3 simulation + T2 agent) runs in one
    process. Accepts the FastAPI app or the runtime service — it finds
    the dispatcher either way, and registration failures never break
    startup (T1's own SafeFallbackHandler still serves commands).
    """
    handlers = [T3PipelineHandler()] if include_t3 else []
    for handler in handlers:
        dispatcher = _find_dispatcher(service)
        if dispatcher is None:
            return
        try:
            dispatcher.register(handler)
        except Exception:
            # Registration must never break startup; the dispatcher's own
            # SafeFallbackHandler still serves commands if we fail here.
            pass


def _find_dispatcher(service):
    """FastAPI app or runtime service -> dispatcher, or None.

    The runtime service exposes ``dispatcher`` directly; a FastAPI app
    carries it on ``app.state.runtime``. Handle both, plus the
    underscored attribute a defensive caller might have used.
    """
    if isinstance(service, MirageRuntime) or hasattr(service, "dispatcher"):
        return getattr(service, "dispatcher", None)
    target = getattr(service, "state", service)
    runtime = getattr(target, "runtime", None) or getattr(service, "runtime", None)
    dispatcher = getattr(runtime, "dispatcher", None)
    if dispatcher is None and runtime is not None:
        dispatcher = getattr(runtime, "_dispatcher", None)
    return dispatcher
