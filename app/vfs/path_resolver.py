"""Safe path resolution for the virtual filesystem (STEP 5).

SECURITY-CRITICAL: every path entering or leaving the VFS must go through
this module. It anchors resolution at a virtual root ("/") and guarantees
the result stays inside the virtual tree — no host filesystem access, ever.

The resolver works on pure strings: it never calls os.path.realpath,
never touches the filesystem, and therefore cannot be tricked by
symlinks or bind mounts on the host.
"""

import posixpath

from .. import config
from .. import logger

log = logger.get_logger("vfs.path_resolver")

# Sentinel error raised when a path tries to escape the virtual tree.
class PathEscapedError(Exception):
    """Raised when a path cannot be resolved inside the virtual root."""


def resolve(cwd: str, target: str) -> str:
    """Resolve `target` relative to `cwd` (or absolute if it starts with /).

    Returns a normalized, canonical path inside the virtual tree.
    Raises PathEscapedError if the path escapes "/" (e.g. via ../..),
    is malformed, or exceeds config.MAX_PATH_DEPTH.
    """
    if not isinstance(target, str) or not isinstance(cwd, str):
        raise PathEscapedError("invalid path type")

    if len(target) > config.MAX_ARG_LENGTH or len(cwd) > config.MAX_PATH_DEPTH * 64:
        raise PathEscapedError("path too long")

    # Anchor: cwd must already be inside the virtual tree.
    if not cwd.startswith("/"):
        raise PathEscapedError(f"cwd outside virtual root: {cwd!r}")

    if target.startswith("~"):
        # ~/ expands to the fake user's home, never the host's.
        target = config.DEFAULT_HOME + target[1:]

    if target.startswith("/"):
        joined = target
    else:
        joined = posixpath.join(cwd, target)

    # normpath collapses ../ and . — but it can also climb above "/" only
    # in the sense of returning "/": posixpath.normpath("/../x") == "/x".
    # So after normalization the result is always inside the tree. We still
    # verify explicitly to guard against future edits.
    normalized = posixpath.normpath(joined)

    if not normalized.startswith("/"):
        raise PathEscapedError(f"path escaped virtual root: {target!r}")

    depth = len([p for p in normalized.split("/") if p])
    if depth > config.MAX_PATH_DEPTH:
        raise PathEscapedError(f"path too deep: {target!r}")

    # A path that resolves to a directory must not carry a trailing slash
    # (canonical form), so DB lookups match exactly.
    if len(normalized) > 1 and normalized.endswith("/"):
        normalized = normalized.rstrip("/")

    return normalized


def safe_resolve(cwd: str, target: str) -> str:
    """Like resolve(), but returns None instead of raising. Convenience for
    command handlers that want to render a bash-style error."""
    try:
        return resolve(cwd, target)
    except PathEscapedError as e:
        log.warning("path escape attempt: %s", e)
        return None


def parent(path: str) -> str:
    """Canonical parent of a canonical virtual path."""
    if path == "/":
        return "/"
    resolved = safe_resolve("/", path)
    if resolved is None:
        return "/"
    return posixpath.dirname(resolved) or "/"


def basename(path: str) -> str:
    """Basename of a virtual path (works on unresolved strings too)."""
    return posixpath.basename(path.rstrip("/"))
