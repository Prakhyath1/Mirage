"""Mirage Honeypot API (T1, integrated with the T3 pipeline in STEP 15)."""

from fastapi import FastAPI, HTTPException

from . import db
from . import logger
from . import models
from . import router
from . import threat_summary

app = FastAPI(title="Mirage Honeypot API")
log = logger.get_logger("api")


@app.on_event("startup")
def startup():
    db.init_db()
    db.migrate_add_threat_summary()
    db.migrate_add_containment_active()
    log.info("mirage api startup: db ready")


@app.post("/command", response_model=models.CommandResponse)
async def handle_command(req: models.CommandRequest):
    try:
        output = router.process_command(req.session_id, req.command)
        return {"output": output}
    except Exception as e:
        log.error("command failed for session %s: %s", req.session_id, e)
        raise HTTPException(status_code=500, detail="internal error")


@app.get("/session_summary/{session_id}", response_model=models.SessionSummaryResponse)
async def get_session_summary(session_id: str):
    session = db.get_session_by_id(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    stored_summary = threat_summary.get_stored_summary(session_id)
    live_summary = threat_summary.get_live_summary(session_id)

    return {
        "session_id": session_id,
        "stored_summary": stored_summary or "No summary available",
        "live_summary": live_summary
    }


@app.get("/session/{session_id}", response_model=models.SessionInfo)
async def get_session(session_id: str):
    """Session state for the T4 dashboard: threat score, containment, cwd."""
    session = db.get_session_by_id(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "session_id": session_id,
        "threat_score": session.get("threat_score", 0),
        "threat_level": session.get("threat_level", "Low"),
        "containment_active": bool(session.get("containment_active", 0)),
        "cwd": session.get("cwd", "/"),
        "created_at": session.get("created_at"),
        "last_seen": session.get("last_seen"),
    }


@app.get("/session/{session_id}/events", response_model=list[models.EventInfo])
async def get_session_events(session_id: str, limit: int = 50):
    """Security events (containment blocks, honeytoken trips) for T4."""
    if not db.get_session_by_id(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    events = db.get_session_events(session_id, limit=limit) or []
    return [
        {
            "event_type": e.get("event_type", ""),
            "session_id": session_id,
            "details": e.get("details", ""),
            "timestamp": e.get("timestamp"),
        }
        for e in events
    ]


@app.get("/session/{session_id}/honeytokens", response_model=list[models.HoneytokenInfo])
async def get_session_honeytokens(session_id: str):
    """Honeytoken status for T4: which canaries exist and whether they tripped."""
    if not db.get_session_by_id(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    # Trip status comes from HONEYTOKEN_ACCESS events (details: "Path: <p>"),
    # newest first — a canary merely existing is not a trip, and there is no
    # last_accessed column to read.
    accesses = {}
    for e in db.get_session_events(session_id, limit=500):
        details = e.get("details") or ""
        if e.get("event_type") == "HONEYTOKEN_ACCESS" and details.startswith("Path: "):
            accesses.setdefault(details[len("Path: "):], e.get("timestamp"))

    honeytokens = db.list_virtual_files(session_id) or []
    return [
        {
            "path": f["path"],
            "tripped": f["path"] in accesses,
            "last_accessed": accesses.get(f["path"]),
        }
        for f in honeytokens
        if f.get("is_honeytoken")
    ]


@app.get("/health")
async def health():
    return {"status": "online"}
