from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from . import db
from . import router
from . import threat_summary

app = FastAPI(title="Mirage Honeypot API")

@app.on_event("startup")
def startup():
    db.init_db()
    db.migrate_add_threat_summary()
    db.migrate_add_containment_active()

class CommandRequest(BaseModel):
    session_id: str
    command: str

class CommandResponse(BaseModel):
    output: str

class SessionSummaryResponse(BaseModel):
    session_id: str
    stored_summary: str
    live_summary: str

@app.post("/command", response_model=CommandResponse)
async def handle_command(req: CommandRequest):
    if not req.session_id:
        raise HTTPException(status_code=400, detail="session_id required")
    try:
        output = router.process_command(req.session_id, req.command)
        return {"output": output}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/session_summary/{session_id}", response_model=SessionSummaryResponse)
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

@app.get("/health")
async def health():
    return {"status": "online"}