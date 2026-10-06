"""Command router (T1/T2 contract, integrated with the T3 pipeline in STEP 15).

Pipeline: session → parse → classify → threat score → sandbox.execute → log.
The sandbox is the single execution choke point (STEP 14) and the single
logging point: it writes the command row itself, so every command lands in
the logs exactly once no matter which path dispatched it.

Preserved contract:
    process_command(session_id, command) -> str
"""

from . import behavior
from . import db
from . import logger
from . import sandbox
from .vfs import parser

log = logger.get_logger("router")


def process_command(session_id, command):
    session = db.get_or_create_session(session_id)
    cwd = session["cwd"]
    containment_active = session.get("containment_active", 0)

    # Score first so a command that itself escalates the session to High is
    # still handled by normal execution this turn, then contained next turn.
    behavior.update_session_threat(session_id, command)

    if containment_active == 1:
        output = sandbox.execute(session_id, command, cwd, containment=True)
    else:
        try:
            pipeline = parser.parse(command)
        except parser.ParseError:
            pipeline = None
        if pipeline and pipeline.stages:
            # sandbox.execute is the single execution choke point AND the
            # single logging point — it writes the command row itself.
            output = sandbox.execute(session_id, command, cwd)
        else:
            # Unknown/not-parsable: LLM engine answers, never the host.
            # The sandbox is bypassed here, so this branch logs its own row.
            from . import llm_engine
            output = llm_engine.generate_response(command, cwd)
            db.log_command(session_id, command, output, "llm")

    return output
