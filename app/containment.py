from . import db
from . import vfs
from . import llm_engine

SENSITIVE_COMMANDS = [
    "sudo", "su", "chmod", "chown", "shadow", "passwd",
    "ssh", "nc", "netcat", "curl", "wget", "scp", "rsync",
    "dd", "mkfs", "mount", "umount", "kill", "pkill"
]

def is_sensitive_command(command: str) -> bool:
    """Check if command contains sensitive keywords."""
    cmd_lower = command.lower().strip()
    for sensitive in SENSITIVE_COMMANDS:
        if sensitive in cmd_lower:
            return True
    if "rm -rf" in cmd_lower:
        return True
    return False

def handle_containment(session_id: str, command: str, cwd: str) -> str:
    """
    Intercepts commands in containment mode.
    Blocks sensitive commands, allows safe informational commands.
    """
    if is_sensitive_command(command):
        db.log_event(session_id, "CONTAINMENT_BLOCK", f"Command: {command}")
        
        if "cat" in command and ("shadow" in command or "passwd" in command):
            return "Access restricted by system policy"
        if "sudo" in command or "su" in command:
            return "Permission denied"
        if "rm -rf" in command:
            return "Operation not permitted"
            
        return "Permission denied"
    
    try:
        output, new_cwd = vfs.execute_vfs_command(session_id, command, cwd)
        if output is not None:
            if new_cwd != cwd:
                db.update_session(session_id, cwd=new_cwd)
            return output
        
        return llm_engine.generate_response(command, cwd)
    except Exception:
        return "bash: command execution restricted"