"""Command classifier (STEP 7).

Maps a parsed command to a security category:
  SAFE        — informational, harmless (ls, pwd, whoami, uname, ...)
  RECON       — reconnaissance (nmap, netcat enumeration): run + flag
  SENSITIVE   — suspicious but survivable (cat shadow, sudo -l): run + flag
  DESTRUCTIVE — destructive/dangerous (rm -rf /, mkfs, dd): blocked in containment
  UNKNOWN     — not recognized: LLM engine handles it, never the host

Classification is based on the parsed pipeline (command name + arguments),
not substring matching — "history" in a filename no longer scores like the
history command, and "cat /etc/passwd" is classified exactly.
"""

from . import config
from . import logger

log = logger.get_logger("classifier")

# Command -> category. First match wins; args may refine below.
BASE_CATEGORIES = {
    # --- SAFE: read-only, informational ------------------------------------
    "pwd": config.CATEGORY_SAFE,
    "ls": config.CATEGORY_SAFE,
    "cd": config.CATEGORY_SAFE,
    "echo": config.CATEGORY_SAFE,
    "touch": config.CATEGORY_SAFE,
    "mkdir": config.CATEGORY_SAFE,
    "whoami": config.CATEGORY_SAFE,
    "id": config.CATEGORY_SAFE,
    "uname": config.CATEGORY_SAFE,
    "hostname": config.CATEGORY_SAFE,
    "date": config.CATEGORY_SAFE,
    "uptime": config.CATEGORY_SAFE,
    "cat": config.CATEGORY_SAFE,     # refined by path below
    "head": config.CATEGORY_SAFE,
    "tail": config.CATEGORY_SAFE,
    "grep": config.CATEGORY_SAFE,
    "find": config.CATEGORY_SAFE,
    "file": config.CATEGORY_SAFE,
    "stat": config.CATEGORY_SAFE,
    "wc": config.CATEGORY_SAFE,
    "env": config.CATEGORY_SAFE,
    "printenv": config.CATEGORY_SAFE,
    "ps": config.CATEGORY_SAFE,
    "history": config.CATEGORY_SAFE,

    # --- RECON: network/service enumeration --------------------------------
    "nmap": config.CATEGORY_RECON,
    "netstat": config.CATEGORY_RECON,
    "ss": config.CATEGORY_RECON,
    "arp": config.CATEGORY_RECON,
    "ifconfig": config.CATEGORY_RECON,
    "ip": config.CATEGORY_RECON,
    "ping": config.CATEGORY_RECON,
    "dig": config.CATEGORY_RECON,
    "nslookup": config.CATEGORY_RECON,
    "traceroute": config.CATEGORY_RECON,

    # --- SENSITIVE: privilege/credential probing ---------------------------
    "sudo": config.CATEGORY_SENSITIVE,
    "su": config.CATEGORY_SENSITIVE,
    "chown": config.CATEGORY_SENSITIVE,
    "chmod": config.CATEGORY_SENSITIVE,
    "passwd": config.CATEGORY_SENSITIVE,
    "ssh": config.CATEGORY_SENSITIVE,
    "scp": config.CATEGORY_SENSITIVE,
    "rsync": config.CATEGORY_SENSITIVE,
    "crontab": config.CATEGORY_SENSITIVE,
    "useradd": config.CATEGORY_SENSITIVE,
    "usermod": config.CATEGORY_SENSITIVE,
    "kill": config.CATEGORY_SENSITIVE,
    "pkill": config.CATEGORY_SENSITIVE,
    "ln": config.CATEGORY_SENSITIVE,

    # --- SENSITIVE: download/upload tooling --------------------------------
    "curl": config.CATEGORY_SENSITIVE,
    "wget": config.CATEGORY_SENSITIVE,
    "nc": config.CATEGORY_SENSITIVE,
    "netcat": config.CATEGORY_SENSITIVE,

    # --- DESTRUCTIVE: always flagged, blocked under containment -------------
    "rm": config.CATEGORY_DESTRUCTIVE,   # refined: only -r/-rf escalates
    "dd": config.CATEGORY_DESTRUCTIVE,
    "mkfs": config.CATEGORY_DESTRUCTIVE,
    "mount": config.CATEGORY_DESTRUCTIVE,
    "umount": config.CATEGORY_DESTRUCTIVE,
    "shutdown": config.CATEGORY_DESTRUCTIVE,
    "reboot": config.CATEGORY_DESTRUCTIVE,
    "halt": config.CATEGORY_DESTRUCTIVE,
    "fdisk": config.CATEGORY_DESTRUCTIVE,
    "wipefs": config.CATEGORY_DESTRUCTIVE,
}

# Credential-bearing files: reading these is SENSITIVE even though cat is SAFE.
SENSITIVE_PATHS = ("/etc/shadow", "/etc/passwd")

# Arguments that escalate rm from DESTRUCTIVE to actively blocked always.
RM_RECURSIVE = {"-r", "-rf", "-fr", "--recursive"}


def classify(pipeline) -> str:
    """Classify a parsed pipeline into one of the config.CATEGORY_* values."""
    if not pipeline or not pipeline.stages:
        return config.CATEGORY_UNKNOWN

    # A pipeline is at least as severe as its most severe stage.
    categories = [classify_stage(argv) for argv in pipeline.stages]
    severity_order = [
        config.CATEGORY_UNKNOWN,
        config.CATEGORY_SAFE,
        config.CATEGORY_RECON,
        config.CATEGORY_SENSITIVE,
        config.CATEGORY_DESTRUCTIVE,
    ]
    return max(categories, key=severity_order.index)


def classify_stage(argv) -> str:
    """Classify one command (argv list)."""
    if not argv:
        return config.CATEGORY_UNKNOWN

    cmd = argv[0]
    args = argv[1:]
    base = BASE_CATEGORIES.get(cmd)

    if base is None:
        # e.g. "python -c ..." or "bash script.sh": interpreters run via LLM.
        return config.CATEGORY_UNKNOWN

    # --- Refinements ---------------------------------------------------------
    if cmd == "cat":
        # Reading credential files is SENSITIVE.
        for arg in args:
            if any(p in arg for p in SENSITIVE_PATHS):
                return config.CATEGORY_SENSITIVE
        return config.CATEGORY_SAFE

    if cmd == "rm":
        if any(arg in RM_RECURSIVE for arg in args):
            return config.CATEGORY_DESTRUCTIVE
        return config.CATEGORY_SENSITIVE

    if cmd in ("sudo", "su"):
        # sudo rm -rf etc. — use the underlying command's severity.
        if args:
            return classify_stage(args)
        return config.CATEGORY_SENSITIVE

    if cmd in ("wget", "curl", "nc", "netcat") and base == config.CATEGORY_SENSITIVE:
        return config.CATEGORY_SENSITIVE

    return base
