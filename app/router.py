from . import db
from . import vfs
from . import behavior
from . import llm_engine
from . import containment

VFS_COMMANDS = ["ls", "pwd", "cd", "cat", "echo", "mkdir", "rm", "touch", "nmap"]

def process_command(session_id, command):
    session = db.get_or_create_session(session_id)
    cwd = session['cwd']
    containment_active = session.get('containment_active', 0)
    
    output = ""
    source = ""
    new_cwd = cwd
    
    if containment_active == 1:
        output = containment.handle_containment(session_id, command, cwd)
        source = "containment"
    else:
        cmd_parts = command.strip().split()
        base_cmd = cmd_parts[0] if cmd_parts else ""
        
        if base_cmd in VFS_COMMANDS:
            output, new_cwd = vfs.execute_vfs_command(session_id, command, cwd)
            source = "vfs"
        else:
            output = llm_engine.generate_response(command, cwd)
            source = "llm"
    
    if new_cwd != cwd:
        db.update_session(session_id, cwd=new_cwd)
    
    behavior.update_session_threat(session_id, command)
    db.log_command(session_id, command, output, source)
    
    return output