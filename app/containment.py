"""Containment policy (STEP 8).

Intercepts commands when containment mode is active for a session.
The policy itself is enforced inside the sandbox (sandbox.execute with
containment=True), so no dispatch path can bypass it:

  DESTRUCTIVE  → blocked with a realistic error, event logged
  SENSITIVE    → allowed but the output is degraded (never leaks credentials)
  RECON / SAFE → allowed normally through the sandbox
  UNKNOWN      → LLM engine (never the host)

Containment activates automatically when behavior.py escalates a session to
High threat.
"""

from . import classifier
from . import config
from . import db
from . import llm_engine
from . import logger
from . import sandbox
from .vfs import parser

log = logger.get_logger("containment")


def handle_containment(session_id: str, command: str, cwd: str) -> str:
    """Intercepts commands in containment mode."""
    try:
        pipeline = parser.parse(command)
    except parser.ParseError:
        pipeline = None

    category = classifier.classify(pipeline) if pipeline else config.CATEGORY_UNKNOWN

    if category == config.CATEGORY_DESTRUCTIVE:
        db.log_event(session_id, "CONTAINMENT_BLOCK", f"Command: {command}")
        logger.security_event("CONTAINMENT_BLOCK", session_id, command)
    elif category == config.CATEGORY_SENSITIVE:
        db.log_event(session_id, "CONTAINMENT_SENSITIVE", f"Command: {command}")

    if category == config.CATEGORY_UNKNOWN:
        # The sandbox is bypassed on the LLM path, so log the command row
        # here — every command must land in the logs exactly once.
        output = llm_engine.generate_response(command, cwd, session_id=session_id)
        db.log_command(session_id, command, output, "llm")
        return output

    return sandbox.execute(session_id, command, cwd, containment=True)
