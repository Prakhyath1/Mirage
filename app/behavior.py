from . import db
from . import threat_summary

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
    "shadow": 10
}

def calculate_score(command):
    score = 0
    cmd_lower = command.lower()
    for keyword, points in THREAT_KEYWORDS.items():
        if keyword in cmd_lower:
            score += points
    return score

def get_threat_level(score):
    if score <= 5:
        return "Low"
    elif score <= 15:
        return "Medium"
    else:
        return "High"

def update_session_threat(session_id, command):
    session = db.get_or_create_session(session_id)
    score_increment = calculate_score(command)
    
    if score_increment == 0:
        return
    
    current_score = session.get("threat_score", 0)
    current_level = session.get("threat_level", "Low")
    containment_active = session.get("containment_active", 0)
    
    new_score = current_score + score_increment
    new_level = get_threat_level(new_score)
    
    db.update_session(session_id, threat_score=new_score, threat_level=new_level)
    
    if new_level == "High" and current_level != "High" and containment_active == 0:
        db.update_session(session_id, containment_active=1)
        db.log_event(session_id, "CONTAINMENT_ACTIVATED", f"Threat Score: {new_score}")
    
    if new_level in ["Medium", "High"] and current_level != new_level:
        threat_summary.generate_and_store(session_id)