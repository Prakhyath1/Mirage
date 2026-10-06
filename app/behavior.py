"""Behavior detection and risk scoring (STEPS 11-12).

Rebuild of the original keyword scorer: risk is now computed from the
parsed pipeline via classifier.py categories, with per-category point
weights — "history" in a filename no longer scores like the history
command, and "cat /etc/shadow" scores exactly.

Contract preserved from T1/T2:
    update_session_threat(session_id, command)  — score + auto-containment
    calculate_score(command) -> int
    get_threat_level(score) -> "Low"|"Medium"|"High"
"""

from . import classifier
from . import config
from . import db
from . import logger
from . import threat_summary
from .vfs import parser

log = logger.get_logger("behavior")

# Points per category per command.
CATEGORY_WEIGHTS = {
    config.CATEGORY_SAFE: 1,
    config.CATEGORY_RECON: 4,
    config.CATEGORY_SENSITIVE: 6,
    config.CATEGORY_DESTRUCTIVE: 12,
    config.CATEGORY_UNKNOWN: 2,
}

# Multipliers for escalation signals on top of the category weight.
# Canary trips are not scored here: honeytokens.py escalates the session
# directly on a trip, and a static command score cannot know session state.
RECURSIVE_BONUS = 4        # rm -rf style flags
CREDENTIAL_PATH_BONUS = 8  # cat /etc/shadow, /etc/passwd

# Behavioral keyword vocabulary (v1 table, kept as a consumed contract).
# Scoring authority is the classifier above (category weights + bonuses);
# this table no longer contributes to scores. It is the data source for
# T2's behavior-signals heuristic: app/agent/context.py reads it to report
# which T3 keywords a command matches (docs/contracts/T2_AGENT_CONTRACTS.md
# — "BehaviorSignals fields: T2 consumes, T3 owns"). Removing it breaks the
# frozen cross-team contract, so it stays.
THREAT_KEYWORDS = {
    "nmap": 5,
    "sudo": 3,
    "passwd": 7,
    "curl": 5,
    "wget": 5,
    "chmod": 2,
    "777": 8,
    "nc": 8,
    "netcat": 8,
    "python": 3,
    "bash": 2,
    "sh": 2,
    "eval": 5,
    "exec": 5,
    "rm -rf": 10,
    "dd": 4,
    "history": 2,
    "whoami": 1,
    "id": 1,
    "uname": 1,
    "cat /etc": 5,
    "shadow": 10,
}


def calculate_score(command: str) -> int:
    """Risk score for one command, from its parsed pipeline."""
    try:
        pipeline = parser.parse(command)
    except parser.ParseError:
        return CATEGORY_WEIGHTS[config.CATEGORY_UNKNOWN]

    if not pipeline or not pipeline.stages:
        return 0

    total = 0
    for argv in pipeline.stages:
        category = classifier.classify_stage(argv)
        points = CATEGORY_WEIGHTS.get(category, CATEGORY_WEIGHTS[config.CATEGORY_UNKNOWN])
        joined = " ".join(argv).lower()

        if category == config.CATEGORY_SENSITIVE:
            if any(p in joined for p in classifier.SENSITIVE_PATHS):
                points += CREDENTIAL_PATH_BONUS
        if category == config.CATEGORY_DESTRUCTIVE and classifier.RM_RECURSIVE & set(argv):
            points += RECURSIVE_BONUS

        total += points
    return min(total, config.MAX_COMMAND_LENGTH // 2)


def get_threat_level(score: int) -> str:
    if score <= config.THREAT_LEVELS["Low"]:
        return "Low"
    elif score <= config.THREAT_LEVELS["Medium"]:
        return "Medium"
    return "High"


def update_session_threat(session_id: str, command: str) -> None:
    """Score a command and auto-contain a session that reaches High."""
    score_increment = calculate_score(command)

    if score_increment == 0:
        return

    session = db.get_or_create_session(session_id)
    current_score = session.get("threat_score", 0) or 0
    current_level = session.get("threat_level", "Low")
    containment_active = session.get("containment_active", 0)

    new_score = current_score + score_increment
    new_level = get_threat_level(new_score)

    db.update_session(session_id, threat_score=new_score, threat_level=new_level)
    log.info("session threat updated", session_id=session_id,
             from_level=current_level, to_level=new_level,
             score=new_score, increment=score_increment)

    if new_level == "High" and current_level != "High" and containment_active == 0:
        db.update_session(session_id, containment_active=1)
        db.log_event(session_id, "CONTAINMENT_ACTIVATED", f"Threat Score: {new_score}")
        logger.security_event("CONTAINMENT_ACTIVATED", session_id, str(new_score))

    if new_level in ("Medium", "High") and current_level != new_level:
        threat_summary.generate_and_store(session_id)
