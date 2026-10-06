"""Command parser (STEP 6).

Tokenizes a command string into a structure the sandbox can execute:
  - simple commands (argv list)
  - output redirection (> file, >> file)
  - pipes (cmd1 | cmd2)

Parsing is pure text via shlex — no shell is ever spawned.
"""

import shlex

from .. import config
from .. import logger

log = logger.get_logger("vfs.parser")


class ParseError(Exception):
    """Raised when a command cannot be parsed (bash-style syntax error)."""


class Pipeline:
    """A parsed command pipeline.

    Attributes:
        stages:   list of argv lists, one per piped stage (len 1 = no pipe)
        redirect: None or ("append"|"truncate", virtual_path)
        raw:      the original command string
    """

    def __init__(self, stages, redirect=None, raw=""):
        self.stages = stages
        self.redirect = redirect
        self.raw = raw


def parse(command: str) -> Pipeline:
    """Parse a command string into a Pipeline.

    Raises ParseError on unbalanced quotes or unterminated redirection.
    Raises nothing for empty input — returns an empty Pipeline instead.
    """
    if not isinstance(command, str):
        raise ParseError("command must be a string")

    command = command.strip()
    if not command:
        return Pipeline([], raw=command)

    if len(command) > config.MAX_COMMAND_LENGTH:
        raise ParseError(f"command too long (max {config.MAX_COMMAND_LENGTH})")

    # Split on unquoted pipes first, then shlex each stage.
    try:
        segments = _split_pipes(command)
    except ValueError:
        raise ParseError("bash: syntax error near unexpected token `|'")

    stages = []
    redirect = None
    for i, seg in enumerate(segments):
        seg = seg.strip()
        if not seg:
            raise ParseError("bash: syntax error near unexpected token `|'")

        tokens, seg_redirect = _tokenize(seg)
        if seg_redirect is not None:
            if i != len(segments) - 1:
                # redirection mid-pipeline: treat as a pipe stage error,
                # matching bash's "ambiguous redirect" strictness loosely
                raise ParseError("bash: syntax error near redirection")
            redirect = seg_redirect

        if not tokens and redirect is None:
            raise ParseError("bash: syntax error near unexpected token")

        stages.append(tokens)

    if not stages:
        raise ParseError("bash: syntax error")

    # Enforce per-stage arg limits.
    for tokens in stages:
        if len(tokens) > config.MAX_ARGS + 1:  # +1 for the command itself
            raise ParseError(f"too many arguments (max {config.MAX_ARGS})")
        for tok in tokens:
            if len(tok) > config.MAX_ARG_LENGTH:
                raise ParseError(f"argument too long (max {config.MAX_ARG_LENGTH})")

    return Pipeline(stages, redirect=redirect, raw=command)


def _split_pipes(command: str):
    """Split a command on unquoted `|` characters."""
    segments = []
    current = []
    in_single = in_double = False
    escaped = False
    for ch in command:
        if escaped:
            current.append(ch)
            escaped = False
            continue
        if ch == "\\" and in_double:
            current.append(ch)
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "|" and not in_single and not in_double:
            segments.append("".join(current))
            current = []
            continue
        current.append(ch)
    if in_single or in_double:
        raise ValueError("unbalanced quotes")
    segments.append("".join(current))
    return segments


def _tokenize(segment: str):
    """shlex-tokenize one pipeline segment.

    Returns (tokens, redirect) where redirect is None or
    ("append"|"truncate", path_token).
    """
    # Handle > and >> by pulling them out before shlex (shlex in POSIX mode
    # treats > as a normal token, which works, but >> would be split as
    # two > tokens — handle both explicitly for clarity).
    redirect = None
    if ">>" in segment:
        before, _, after = segment.partition(">>")
        redirect = ("append", after.strip())
        segment = before
    elif ">" in segment:
        before, _, after = segment.partition(">")
        redirect = ("truncate", after.strip())
        segment = before

    try:
        tokens = shlex.split(segment)
    except ValueError:
        raise ParseError("bash: syntax error (unbalanced quote)")

    return tokens, redirect
