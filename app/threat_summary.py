from . import db
from . import llm_engine

SUMMARY_PROMPT = """
You are a cybersecurity threat analyst reviewing honeypot session data.
Analyze the following command history and generate a concise threat summary.

Focus on:
- Attack patterns (reconnaissance, exploitation, persistence)
- Intent (credential theft, lateral movement, data exfiltration)
- Sophistication level

Requirements:
- 2-3 sentences only
- Professional tone
- Plain text only
- No markdown
- No bash prefix

Command History:
{command_history}

Threat Summary:
"""

def generate_threat_summary(session_id: str) -> str:
    commands = db.get_session_commands(session_id, limit=10)

    if not commands:
        return "No significant activity detected."

    history_text = "\n".join([
        f"$ {cmd['command']}"
        for cmd in reversed(commands)
    ])

    prompt = SUMMARY_PROMPT.format(command_history=history_text)

    try:
        summary = llm_engine.generate_analysis(prompt)
        return summary.strip() if summary else "Analysis unavailable."
    except Exception:
        return "Analysis unavailable."


def generate_and_store(session_id: str) -> None:
    summary = generate_threat_summary(session_id)
    db.update_session(session_id, threat_summary=summary)


def get_stored_summary(session_id: str):
    session = db.get_session_by_id(session_id)
    if session:
        return session.get("threat_summary")
    return None


def get_live_summary(session_id: str):
    return generate_threat_summary(session_id)