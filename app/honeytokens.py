"""Honeytokens / canaries (STEP 13).

Tripwires planted in the virtual filesystem. The VFS flags certain files as
honeytokens (is_honeytoken=1); whenever an attacker reads one, this module
records a HONEYTOKEN_ACCESS event — the strongest single signal that a
session is hostile, since no legitimate user touches these files.

Public contract:
    trip(session_id, path)            — record an access to a honeytoken
    is_honeytoken(session_id, path)   — check whether a path is a canary
    register(session_id, path)        — plant an additional canary
"""

from . import config
from . import db
from . import logger

log = logger.get_logger("honeytokens")

# Paths the session seeder plants as canaries. Any access to these is
# immediate evidence of credential theft intent.
CANARY_PATHS = ("/etc/shadow",)


def trip(session_id: str, path: str) -> None:
    """Record that a honeytoken was accessed."""
    db.log_event(session_id, "HONEYTOKEN_ACCESS", f"Path: {path}")
    logger.security_event("HONEYTOKEN_ACCESS", session_id, path)
    # A canary trip is itself strong hostile-intent evidence: escalate the
    # session's threat score so behavior/containment react immediately.
    _escalate(session_id, path)


def is_honeytoken(session_id: str, path: str) -> bool:
    """Check whether a virtual path is a planted canary."""
    if path in CANARY_PATHS:
        return True
    file_obj = db.get_virtual_file(session_id, path)
    return bool(file_obj and file_obj.get("is_honeytoken"))


def register(session_id: str, path: str, content: str = "") -> None:
    """Plant an additional canary at a virtual path."""
    db.save_virtual_file(session_id, path, content, is_honeytoken=1)
    db.log_event(session_id, "HONEYTOKEN_PLANTED", f"Path: {path}")


def _escalate(session_id: str, path: str) -> None:
    """Escalate threat score on a canary trip.

    The score alone is not enough: the level must be recomputed immediately
    so a trip that lands the session in High activates containment right
    away, without waiting for the next scored command.
    """
    try:
        session = db.get_session_by_id(session_id)
        if session is None:
            return
        # Lazy import: keeps this module free of a hard dependency on the
        # scoring layer (behavior.py does not import honeytokens, so there
        # is no cycle — lazy just keeps the seam one-directional).
        from . import behavior

        current_score = session.get("threat_score", 0) or 0
        current_level = session.get("threat_level", "Low")
        containment_active = session.get("containment_active", 0)

        new_score = current_score + config.THREAT_LEVELS["Medium"]
        new_level = behavior.get_threat_level(new_score)

        db.update_session(session_id, threat_score=new_score, threat_level=new_level)
        log.info("honeytoken tripped, session escalated", session_id=session_id,
                 score=new_score, threat_level=new_level)

        if new_level == "High" and current_level != "High" and containment_active == 0:
            db.update_session(session_id, containment_active=1)
            db.log_event(session_id, "CONTAINMENT_ACTIVATED", f"Threat Score: {new_score}")
            logger.security_event("CONTAINMENT_ACTIVATED", session_id, str(new_score))
    except Exception as e:  # never let scoring break command handling
        log.error("honeytoken escalation failed", error=str(e)[:200])
