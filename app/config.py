"""Central Mirage configuration.

All tunable limits live here so the sandbox (T3) can enforce bounded
resources without hard-coded magic numbers scattered across modules.
"""

# --- Session defaults -------------------------------------------------------

# Never derive this from the host (e.g. os.getlogin() / $USER): the honeypot
# must present a consistent fake identity, not leak the real one.
DEFAULT_USER = "admin"
DEFAULT_HOME = f"/home/{DEFAULT_USER}"
DEFAULT_CWD = DEFAULT_HOME

# --- Resource limits (STEP 9) ----------------------------------------------

MAX_COMMAND_LENGTH = 512          # chars; anything longer is rejected outright
MAX_ARGS = 16                     # tokens per command after parsing
MAX_ARG_LENGTH = 256              # chars per single token
MAX_OUTPUT_LENGTH = 4096          # chars; sandbox output is truncated to this
MAX_FILE_SIZE = 64 * 1024         # bytes; writes larger than this are rejected
MAX_LIST_ENTRIES = 200            # per ls listing
MAX_SESSION_FILES = 500           # virtual files per session before refusing new writes
MAX_PATH_DEPTH = 12               # path components; deeper paths are rejected

# --- Threat scoring thresholds (behavior.py) --------------------------------

THREAT_LEVELS = {"Low": 5, "Medium": 15, "High": float("inf")}

# --- Classification categories (classifier.py) -------------------------------

CATEGORY_SAFE = "SAFE"              # informational, harmless
CATEGORY_SENSITIVE = "SENSITIVE"    # suspicious but survivable: run + flag
CATEGORY_DESTRUCTIVE = "DESTRUCTIVE"  # blocked when containment active
CATEGORY_RECON = "RECON"            # reconnaissance: run + flag
CATEGORY_UNKNOWN = "UNKNOWN"        # -> LLM engine, never the host
