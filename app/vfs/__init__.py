"""Virtual filesystem (STEP 4).

Simulated file operations backed by the SQLite virtual_files table.
Every path goes through path_resolver.resolve() — the VFS can never
read or write outside the virtual tree.

Public contract (preserved from T1/T2):
    initialize_session_files(session_id)
    execute_vfs_command(session_id, command, cwd) -> (output|None, new_cwd)
"""

import time

from .. import config
from .. import db
from .. import logger
from . import path_resolver
from . import parser

log = logger.get_logger("vfs")

STATIC_DIRS = ["bin", "etc", "home", "usr", "var", "opt", "tmp", "root", "sbin", "lib"]
STATIC_FILES = ["README.txt"]

FAKE_USERS = [
    {"name": "root", "uid": 0, "gid": 0, "comment": "root", "home": "/root", "shell": "/bin/bash"},
    {"name": config.DEFAULT_USER, "uid": 1000, "gid": 1000, "comment": "Admin", "home": config.DEFAULT_HOME, "shell": "/bin/bash"},
    {"name": "devops", "uid": 1001, "gid": 1001, "comment": "DevOps", "home": "/home/devops", "shell": "/bin/bash"},
]


def initialize_session_files(session_id):
    if db.get_virtual_file(session_id, "/.init_complete"):
        return

    lines = [
        f"{u['name']}:x:{u['uid']}:{u['gid']}:{u['comment']}:{u['home']}:{u['shell']}"
        for u in FAKE_USERS
    ]
    db.save_virtual_file(session_id, "/etc/passwd", "\n".join(lines))

    shadow_lines = [f"{u['name']}:$6$salt$hash:19000:0:99999:7:::" for u in FAKE_USERS]
    db.save_virtual_file(session_id, "/etc/shadow", "\n".join(shadow_lines), is_honeytoken=1)

    db.save_virtual_file(session_id, "/.init_complete", "true")


def execute_vfs_command(session_id, command, cwd):
    """Execute a command inside the virtual filesystem.

    Returns (output, new_cwd). output is None when the command is not a
    VFS builtin (caller falls back to the LLM engine).
    """
    try:
        pipeline = parser.parse(command)
    except parser.ParseError as e:
        return str(e), cwd

    if not pipeline.stages:
        return "", cwd

    initialize_session_files(session_id)

    argv = pipeline.stages[0]
    cmd = argv[0]
    args = argv[1:]
    new_cwd = cwd

    # stdin for piped stages (only the second stage is simulated).
    stdin_data = None
    if len(pipeline.stages) > 1:
        stdin_data = _run_pipe_source(session_id, pipeline.stages[0], cwd)
        argv2 = pipeline.stages[1]
        cmd = argv2[0]
        args = argv2[1:]
        output = _run_builtin(session_id, cmd, args, cwd, stdin=stdin_data)
        if output is None:
            return None, cwd
        output = _apply_redirect(session_id, output, pipeline.redirect, cwd)
        return output, cwd

    output = _run_builtin(session_id, cmd, args, cwd)
    if output is None:
        return None, cwd

    if cmd == "cd":
        return "", output  # handler returns the new cwd as its output

    output = _apply_redirect(session_id, output, pipeline.redirect, cwd)
    return output, cwd


def _run_builtin(session_id, cmd, args, cwd, stdin=None):
    handlers = {
        "pwd": _handle_pwd,
        "ls": _handle_ls,
        "cat": _handle_cat,
        "echo": _handle_echo,
        "mkdir": _handle_mkdir,
        "rm": _handle_rm,
        "touch": _handle_touch,
        "nmap": _handle_nmap,
        "whoami": _handle_whoami,
        "id": _handle_id,
        "uname": _handle_uname,
        "cd": _handle_cd_builtin,
    }
    handler = handlers.get(cmd)
    if handler is None:
        return None
    if stdin is not None and cmd not in ("cat", "grep", "head"):
        return f"{cmd}: stdin not supported for this command"
    return handler(session_id, cwd, args, stdin=stdin)


def _run_pipe_source(session_id, argv, cwd):
    """Run the source stage of a pipe and return its output as stdin."""
    cmd, args = argv[0], argv[1:]
    output = _run_builtin(session_id, cmd, args, cwd)
    return output if output is not None else ""


def _session_file_cap_reached(session_id, target):
    """True when creating a *new* file would exceed MAX_SESSION_FILES.

    Overwriting an existing path never grows the session's file count.
    """
    if db.get_virtual_file(session_id, target) is not None:
        return False
    return db.count_virtual_files(session_id) >= config.MAX_SESSION_FILES


# --- Builtins ---------------------------------------------------------------

def _handle_pwd(session_id, cwd, args, stdin=None):
    return cwd


def _handle_whoami(session_id, cwd, args, stdin=None):
    return config.DEFAULT_USER


def _handle_id(session_id, cwd, args, stdin=None):
    return f"uid=1000({config.DEFAULT_USER}) gid=1000({config.DEFAULT_USER}) groups=1000({config.DEFAULT_USER})"


def _handle_uname(session_id, cwd, args, stdin=None):
    return "Linux mirage 5.15.0-generic #1 SMP x86_64 GNU/Linux"


def _handle_ls(session_id, cwd, args, stdin=None):
    # Read the flags before filtering them out of the path list — otherwise
    # "-l" is gone by the time we look for it and long format never renders.
    long_format = any(a.startswith("-") and "l" in a for a in args)
    args = [a for a in args if not a.startswith("-")]
    display_items = []

    if cwd != "/":
        display_items.append({"name": "..", "is_dir": True})

    if cwd == "/":
        for d in STATIC_DIRS:
            display_items.append({"name": d, "is_dir": True})

    db_files = db.list_virtual_files(session_id, cwd)
    for f in db_files:
        fname = path_resolver.basename(f['path'])
        if fname and fname not in (".init_complete",):
            display_items.append({"name": fname, "is_dir": f.get('is_dir', False)})

    display_items = display_items[:config.MAX_LIST_ENTRIES]

    if long_format:
        lines = [f"total {len(display_items)}"]
        for item in display_items:
            type_char = "d" if item['is_dir'] else "-"
            lines.append(f"{type_char}rw-r--r-- 1 root root 4096 Jan 01 12:00 {item['name']}")
        return "\n".join(lines)
    return "  ".join([item['name'] for item in display_items])


def _handle_cd_builtin(session_id, cwd, args, stdin=None):
    """cd handler — returns the new cwd (consumed by execute_vfs_command)."""
    if not args or args[0] in ("~",):
        return config.DEFAULT_HOME
    target = path_resolver.safe_resolve(cwd, args[0])
    if target is None:
        return cwd  # escape attempt: stay put
    return target


def _handle_cat(session_id, cwd, args, stdin=None):
    if stdin is not None:
        return stdin  # cat piped output straight through
    if not args:
        return "usage: cat [file]"

    target = path_resolver.safe_resolve(cwd, args[0])
    if target is None:
        return f"cat: {args[0]}: Operation not permitted"

    file_obj = db.get_virtual_file(session_id, target)
    if file_obj:
        if file_obj['is_honeytoken']:
            from .. import honeytokens
            honeytokens.trip(session_id, target)
        if target == "/etc/shadow":
            # Credential-bearing file: a non-root shell can never read it.
            # Keyed on the *resolved* path so no ../-spelling slips past,
            # and applied with or without containment (CONTRACTS invariant 5).
            return f"cat: {args[0]}: Permission denied"
        return file_obj['content']
    return f"cat: {args[0]}: No such file or directory"


def _handle_echo(session_id, cwd, args, stdin=None):
    if stdin is not None:
        return stdin
    return " ".join(args)


def _handle_mkdir(session_id, cwd, args, stdin=None):
    for dirname in args:
        target = path_resolver.safe_resolve(cwd, dirname)
        if target is None:
            return f"mkdir: cannot create directory `{dirname}': Operation not permitted"
        if len(target.split("/")) > config.MAX_PATH_DEPTH:
            return f"mkdir: cannot create directory `{dirname}': File name too long"
        if _session_file_cap_reached(session_id, target):
            return f"mkdir: cannot create directory `{dirname}': Too many open files in system"
        db.save_virtual_file(session_id, target, "", is_dir=True)
    return ""


def _handle_rm(session_id, cwd, args, stdin=None):
    args = [a for a in args if not a.startswith("-")]
    for fname in args:
        target = path_resolver.safe_resolve(cwd, fname)
        if target is None:
            return f"rm: cannot remove `{fname}': Operation not permitted"
        db.delete_virtual_file(session_id, target)
    return ""


def _handle_touch(session_id, cwd, args, stdin=None):
    for fname in args:
        target = path_resolver.safe_resolve(cwd, fname)
        if target is None:
            return f"touch: cannot touch `{fname}': Operation not permitted"
        if _session_file_cap_reached(session_id, target):
            return f"touch: cannot touch `{fname}': Too many open files in system"
        db.save_virtual_file(session_id, target, "")
    return ""


def _handle_nmap(session_id, cwd, args, stdin=None):
    if not args:
        return "nmap: missing target"
    target = args[0]
    from .. import simulated
    return simulated.nmap_scan(target)


def _apply_redirect(session_id, output, redirect, cwd):
    """Write piped/redirected output to a virtual file (bounded)."""
    if redirect is None:
        return output

    mode, filename = redirect
    if not filename:
        return "bash: syntax error near unexpected token `newline'"

    target = path_resolver.safe_resolve(cwd, filename)
    if target is None:
        return "bash: Operation not permitted"

    if len(output) > config.MAX_FILE_SIZE:
        return "bash: echo: write error: No space left on device"

    existing = db.get_virtual_file(session_id, target)
    if existing is None and db.count_virtual_files(session_id) >= config.MAX_SESSION_FILES:
        # The session hit its file cap: creating yet another file is refused
        # (writing to an existing file is still fine).
        return f"bash: {filename}: Too many open files in system"
    if mode == "append" and existing:
        output = (existing['content'] or "") + output

    db.save_virtual_file(session_id, target, output)
    return ""
