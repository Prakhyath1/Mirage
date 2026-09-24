import os
import shlex
import time
from . import db

STATIC_DIRS = ["bin", "etc", "home", "usr", "var", "opt", "tmp", "root", "sbin", "lib"]
STATIC_FILES = ["README.txt"]

def initialize_session_files(session_id):
    if db.get_virtual_file(session_id, "/.init_complete"):
        return
    
    users = [
        {"name": "root", "uid": 0, "gid": 0, "comment": "root", "home": "/root", "shell": "/bin/bash"},
        {"name": "admin", "uid": 1000, "gid": 1000, "comment": "Admin", "home": "/home/admin", "shell": "/bin/bash"},
        {"name": "devops", "uid": 1001, "gid": 1001, "comment": "DevOps", "home": "/home/devops", "shell": "/bin/bash"},
    ]
    
    lines = []
    for u in users:
        line = f"{u['name']}:x:{u['uid']}:{u['gid']}:{u['comment']}:{u['home']}:{u['shell']}"
        lines.append(line)
    db.save_virtual_file(session_id, "/etc/passwd", "\n".join(lines))
    
    shadow_lines = []
    for u in users:
        shadow_lines.append(f"{u['name']}:$6$salt$hash:19000:0:99999:7:::")
    db.save_virtual_file(session_id, "/etc/shadow", "\n".join(shadow_lines), is_honeytoken=1)
    
    db.save_virtual_file(session_id, "/.init_complete", "true")

def execute_vfs_command(session_id, command, cwd):
    try:
        parts = shlex.split(command)
    except ValueError:
        return "bash: syntax error near unexpected token", cwd

    if not parts:
        return "", cwd

    cmd = parts[0]
    args = parts[1:]

    initialize_session_files(session_id)

    if cmd == "pwd":
        return cwd, cwd
    elif cmd == "ls":
        return handle_ls(session_id, cwd, args), cwd
    elif cmd == "cd":
        return "", handle_cd_path(session_id, cwd, args)
    elif cmd == "cat":
        return handle_cat(session_id, cwd, args), cwd
    elif cmd == "echo":
        return handle_echo(session_id, cwd, parts), cwd
    elif cmd == "mkdir":
        return handle_mkdir(session_id, cwd, args), cwd
    elif cmd == "rm":
        return handle_rm(session_id, cwd, args), cwd
    elif cmd == "touch":
        return handle_touch(session_id, cwd, args), cwd
    elif cmd == "nmap":
        return handle_nmap(args), cwd
    else:
        return None, cwd

def handle_nmap(args):
    if not args:
        return "nmap: missing target"
    target = args[0]
    return f"""Starting Nmap 7.92 at {time.ctime()}
Nmap scan report for {target}
Host is up (0.00042s latency).
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
Nmap done: 1 IP address (1 host up) scanned in 2.34 seconds"""

def handle_ls(session_id, cwd, args):
    long_format = "-l" in args
    display_items = []
    
    if cwd != "/":
        display_items.append({"name": "..", "is_dir": True})
    
    if cwd == "/":
        for d in STATIC_DIRS:
            display_items.append({"name": d, "is_dir": True})
    
    db_files = db.list_virtual_files(session_id, cwd)
    for f in db_files:
        fname = os.path.basename(f['path'])
        if fname and fname not in [".init_complete"]:
            display_items.append({"name": fname, "is_dir": f.get('is_dir', False)})
    
    if long_format:
        lines = [f"total {len(display_items)}"]
        for item in display_items:
            type_char = "d" if item['is_dir'] else "-"
            lines.append(f"{type_char}rw-r--r-- 1 root root 4096 Jan 01 12:00 {item['name']}")
        return "\n".join(lines)
    else:
        return "  ".join([item['name'] for item in display_items])

def handle_cd_path(session_id, cwd, args):
    if not args:
        return "/home/ubuntu"
    target = args[0]
    if target == "..":
        return os.path.dirname(cwd) if cwd != "/" else "/"
    elif target == "~":
        return "/home/ubuntu"
    elif target.startswith("/"):
        return target
    else:
        return os.path.join(cwd, target)

def handle_cat(session_id, cwd, args):
    if not args:
        return "usage: cat [file]"
    
    fname = args[0]
    full_path = os.path.normpath(fname if fname.startswith("/") else os.path.join(cwd, fname))
    
    if full_path == "/etc/shadow":
        db.log_event(session_id, "HONEYTOKEN_ACCESS", f"File: {full_path}")
    
    file_obj = db.get_virtual_file(session_id, full_path)
    
    if file_obj:
        if file_obj['is_honeytoken']:
            db.log_event(session_id, "HONEYTOKEN_ACCESS", f"File: {full_path}")
        return file_obj['content']
    else:
        return f"cat: {fname}: No such file or directory"

def handle_echo(session_id, cwd, parts):
    if ">" in parts:
        try:
            idx = parts.index(">")
            content = " ".join(parts[1:idx]).strip('"').strip("'")
            filename = parts[idx + 1]
            full_path = filename if filename.startswith("/") else os.path.join(cwd, filename)
            db.save_virtual_file(session_id, full_path, content)
            return ""
        except Exception:
            return "bash: syntax error"
    return " ".join(parts[1:])

def handle_mkdir(session_id, cwd, args):
    for dirname in args:
        db.save_virtual_file(session_id, os.path.join(cwd, dirname), "", is_dir=True)
    return ""

def handle_rm(session_id, cwd, args):
    if "-rf" in args:
        args.remove("-rf")
    for fname in args:
        db.delete_virtual_file(session_id, os.path.join(cwd, fname))
    return ""

def handle_touch(session_id, cwd, args):
    for fname in args:
        db.save_virtual_file(session_id, os.path.join(cwd, fname), "")
    return ""