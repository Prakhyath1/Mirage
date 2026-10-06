"""Sandbox abstraction (STEP 14).

The single execution choke point for every command the honeypot runs.
Nothing in T3 ever touches the host: execution means resolving virtual
paths, calling simulated generators, or falling back to the LLM engine.

Contract:
    execute(session_id, command, cwd, containment=False) -> str

Containment enforcement lives here (not in the caller) so no dispatch
path — router, containment, behavior — can bypass the policy.
"""

from . import classifier
from . import config
from . import db
from . import llm_engine
from . import logger
from . import vfs
from .vfs import parser

log = logger.get_logger("sandbox")


def execute(session_id: str, command: str, cwd: str, containment: bool = False) -> str:
    """Execute a command inside the simulated environment.

    containment=True applies the containment policy on top of normal
    execution: DESTRUCTIVE commands are blocked, SENSITIVE output is
    degraded, everything else runs as usual.
    """
    session = db.get_or_create_session(session_id)

    # Re-classify per call: a session that escalated mid-flight cannot
    # dodge the policy with a cached category.
    try:
        pipeline = parser.parse(command)
    except parser.ParseError as e:
        # Rejected before execution — still exactly one command row.
        db.log_command(session_id, command, str(e), "sandbox")
        return str(e)

    category = classifier.classify(pipeline) if pipeline else config.CATEGORY_UNKNOWN

    if containment and category == config.CATEGORY_DESTRUCTIVE:
        db.log_event(session_id, "SANDBOX_BLOCK", f"Command: {command}")
        logger.security_event("SANDBOX_BLOCK", session_id, command)
        blocked = _block_message(command)
        # The sandbox is the single logging point: even a blocked command
        # gets exactly one command row.
        db.log_command(session_id, command, blocked, "containment")
        return blocked

    output, new_cwd = vfs.execute_vfs_command(session_id, command, session["cwd"])
    if output is None:
        # Not a VFS builtin — the LLM engine answers instead. Never the host.
        # session_id flows through so T2's per-session deception memory applies.
        output = llm_engine.generate_response(
            command, session["cwd"], session_id=session_id
        )
        source = "llm"
    else:
        source = "vfs"

    if new_cwd != session["cwd"]:
        db.update_session(session_id, cwd=new_cwd)

    if containment:
        output = _degrade(session_id, command, output)

    # Bounded output (STEP 9): no command ever returns more than
    # MAX_OUTPUT_LENGTH characters, whichever backend produced it.
    if len(output) > config.MAX_OUTPUT_LENGTH:
        output = output[:config.MAX_OUTPUT_LENGTH]

    # Single logging point: every executed command lands in the logs
    # exactly once, here — callers never add a second row.
    db.log_command(session_id, command, output, source)
    return output


def _block_message(command: str) -> str:
    """A realistic bash-style error for blocked commands."""
    lowered = command.lower()
    if "rm" in lowered:
        return "rm: cannot remove: Operation not permitted"
    if "mkfs" in lowered or "dd " in lowered or "fdisk" in lowered:
        return "Failed to open device: Permission denied"
    if "shutdown" in lowered or "reboot" in lowered or "halt" in lowered:
        return "Failed to initiate reboot: Operation not permitted"
    if "mount" in lowered:
        return "mount: only root can do that"
    return "Permission denied"


def _degrade(session_id: str, command: str, output: str) -> str:
    """Strip credential material from SENSITIVE command output."""
    if not output:
        return output
    if "/etc/shadow" in command.lower():
        return "Permission denied"
    return output
