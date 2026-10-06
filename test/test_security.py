"""Security tests (STEPS 18-20): path escapes, parser, classifier, containment,
honeytokens, audit trail, bounded resources, and host-leakage guards.

Run: python3 -m pytest test/test_security.py -v
"""

import ast
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import classifier
from app import config
from app import db
from app import honeytokens
from app import llm_engine
from app import router
from app import sandbox
from app import vfs
from app.vfs import parser
from app.vfs import path_resolver


@pytest.fixture()
def test_db(monkeypatch):
    """Point db at a temp database for the duration of a test."""
    tmp = tempfile.mkdtemp()
    test_path = os.path.join(tmp, "test.db")
    monkeypatch.setattr(db, "DB_PATH", test_path)
    db.init_db()
    yield test_path


@pytest.fixture()
def no_llm(monkeypatch):
    """Force the LLM fallback offline so leak/log checks stay hermetic.

    The engine behind llm_engine is T2's agent stack; the HTTP transport
    lives in the provider module (app.agent.providers.ollama), so stub it
    there. generate_response degrades to the generic fallback on any
    transport failure, keeping tests fast and deterministic whether or
    not an Ollama happens to be running on this box.
    """
    from app.agent.providers import ollama as ollama_provider

    def refused(*args, **kwargs):
        raise ConnectionError("connection refused")

    monkeypatch.setattr(ollama_provider.requests, "post", refused)


# --- Path resolver: escape attempts ------------------------------------------

def test_resolve_anchors_at_root():
    # Absolute-looking traversal that escapes the virtual root must resolve
    # inside it, never to a host path.
    result = path_resolver.resolve("/home/admin", "../../../../etc/passwd")
    assert result.startswith("/")
    assert ".." not in result


def test_resolve_rejects_deep_paths():
    deep = "/".join(["a"] * (config.MAX_PATH_DEPTH + 2))
    with pytest.raises(path_resolver.PathEscapedError):
        path_resolver.resolve("/", deep)


def test_safe_resolve_returns_none_on_escape():
    # The security property: an escape-heavy path still resolves *inside*
    # the virtual tree — either rejected outright (None) or anchored at "/"
    # with no ".." component left. Never a host path like "../etc/shadow".
    result = path_resolver.safe_resolve("/", "../" * 10 + "etc/shadow")
    assert result is None or (
        result.startswith("/") and ".." not in result.split("/")
    )


def test_resolve_tilde_maps_to_fake_home():
    assert path_resolver.resolve("/", "~") == config.DEFAULT_HOME


# --- Parser ------------------------------------------------------------------

def test_parse_simple_command():
    p = parser.parse("ls -la /home/admin")
    assert p.stages == [["ls", "-la", "/home/admin"]]
    assert p.redirect is None


def test_parse_pipe():
    p = parser.parse("cat /etc/passwd | grep root")
    assert len(p.stages) == 2
    assert p.stages[1] == ["grep", "root"]


def test_parse_redirect():
    p = parser.parse("echo hello > /tmp/out.txt")
    assert p.redirect == ("truncate", "/tmp/out.txt")


def test_parse_rejects_unbalanced_quotes():
    with pytest.raises(parser.ParseError):
        parser.parse("echo 'unterminated")


def test_parse_rejects_oversized_command():
    with pytest.raises(parser.ParseError):
        parser.parse("echo " + "a" * (config.MAX_COMMAND_LENGTH + 1))


# --- Classifier ---------------------------------------------------------------

def test_classify_safe():
    assert classifier.classify(parser.parse("ls -la")) == config.CATEGORY_SAFE


def test_classify_recon():
    assert classifier.classify(parser.parse("nmap 10.0.2.15")) == config.CATEGORY_RECON


def test_classify_cat_passwd_sensitive():
    # Exact classification: cat is SAFE but /etc/passwd makes it SENSITIVE.
    assert classifier.classify(parser.parse("cat /etc/passwd")) == config.CATEGORY_SENSITIVE


def test_classify_rm_recursive_destructive():
    assert classifier.classify(parser.parse("rm -rf /")) == config.CATEGORY_DESTRUCTIVE


def test_classify_rm_plain_not_destructive():
    # Plain rm (no -r) is SENSITIVE, not DESTRUCTIVE.
    assert classifier.classify(parser.parse("rm notes.txt")) == config.CATEGORY_SENSITIVE


def test_classify_sudo_uses_underlying_command():
    assert classifier.classify(parser.parse("sudo rm -rf /")) == config.CATEGORY_DESTRUCTIVE


def test_classify_filename_with_history_is_not_history_cmd():
    # The old substring scorer treated "history" in a filename like the
    # command. Argv-based classification must not.
    assert classifier.classify(parser.parse("cat my_history_notes.txt")) == config.CATEGORY_SAFE


def test_classify_unknown():
    assert classifier.classify(parser.parse("frobnicate --all")) == config.CATEGORY_UNKNOWN


# --- Containment / sandbox -----------------------------------------------------

def test_containment_blocks_destructive(test_db):
    db.get_or_create_session("sess-block")
    output = sandbox.execute("sess-block", "rm -rf /", "/", containment=True)
    assert "not permitted" in output.lower() or "denied" in output.lower()


def test_containment_degrades_shadow(test_db):
    session = db.get_or_create_session("sess-shadow")
    output = sandbox.execute("sess-shadow", "cat /etc/shadow", session["cwd"], containment=True)
    # The fake shadow content must never reach the attacker under containment.
    assert "$6$salt$hash" not in output
    assert "denied" in output.lower()


def test_sandbox_shadow_read_trips_canary(test_db):
    # Reading /etc/shadow must trip the canary and record an event —
    # whatever the spelling of the path and whatever the session's state.
    session = db.get_or_create_session("sess-trip")
    cwd = session["cwd"]
    for command in ("cat /etc/shadow", "cat /home/admin/../../etc/shadow"):
        sandbox.execute("sess-trip", command, cwd, containment=True)
    events = [e["event_type"] for e in db.get_session_events("sess-trip")]
    assert events.count("HONEYTOKEN_ACCESS") == 2


def test_shadow_content_never_leaks_with_or_without_containment(test_db):
    # CONTRACTS invariant 5: /etc/shadow content never reaches an attacker,
    # containment or not, whichever way the path is spelled.
    session = db.get_or_create_session("sess-leak")
    cwd = session["cwd"]
    for containment in (False, True):
        for command in ("cat /etc/shadow", "cat /etc/../etc/shadow"):
            output = sandbox.execute("sess-leak", command, cwd, containment=containment)
            assert "$6$salt$hash" not in output, command
            assert "denied" in output.lower(), command


def test_containment_survives_midflight_escalation(test_db):
    # A session that escalated to High cannot dodge the policy: the sandbox
    # re-classifies per call.
    db.get_or_create_session("sess-mid")
    db.update_session("sess-mid", containment_active=1)
    output = sandbox.execute("sess-mid", "shutdown -h now", "/", containment=True)
    assert "denied" in output.lower() or "not permitted" in output.lower()


# --- Honeytokens ----------------------------------------------------------------

def test_honeytoken_escalation_updates_level_and_containment(test_db):
    # A trip must recompute the level immediately and activate containment
    # on the spot when it lands in High — not on the next scored command.
    db.get_or_create_session("sess-esc")
    db.update_session("sess-esc", threat_score=10, threat_level="Medium")
    honeytokens.trip("sess-esc", "/home/admin/.env")  # +15 -> 25 = High
    session = db.get_session_by_id("sess-esc")
    assert session["threat_score"] == 25
    assert session["threat_level"] == "High"
    assert session["containment_active"] == 1
    events = [e["event_type"] for e in db.get_session_events("sess-esc")]
    assert "CONTAINMENT_ACTIVATED" in events


def test_honeytoken_is_honeytoken(test_db):
    db.get_or_create_session("sess-check")
    assert honeytokens.is_honeytoken("sess-check", "/etc/shadow") is True
    assert honeytokens.is_honeytoken("sess-check", "/etc/passwd") is False


def test_honeytoken_trip_records_event_and_escalates(test_db):
    db.get_or_create_session("sess-honey")
    before = db.get_session_by_id("sess-honey")["threat_score"] or 0
    honeytokens.trip("sess-honey", "/home/admin/.env")
    after = db.get_session_by_id("sess-honey")["threat_score"] or 0
    assert after > before
    event_types = [e["event_type"] for e in db.get_session_events("sess-honey")]
    assert "HONEYTOKEN_ACCESS" in event_types


# --- Audit trail: exactly one log row per command ------------------------------

def test_command_logged_exactly_once(test_db):
    # router → sandbox is the production path; a command that flows through
    # both must still land in the logs exactly once (the double-logging bug
    # this guards against produced two rows with conflicting sources).
    router.process_command("sess-log", "ls")
    rows = db.get_session_commands("sess-log", limit=10)
    assert len(rows) == 1
    assert rows[0]["command"] == "ls"
    assert rows[0]["source"] == "vfs"  # builtin served by the virtual filesystem


def test_blocked_command_still_logged_once(test_db, monkeypatch):
    # Escalating to High would normally trigger an (optional, LLM-backed)
    # summary refresh — stub it so the test stays hermetic.
    from app import threat_summary
    monkeypatch.setattr(threat_summary, "generate_and_store", lambda session_id: None)

    db.get_or_create_session("sess-blocklog")
    db.update_session("sess-blocklog", containment_active=1)
    router.process_command("sess-blocklog", "rm -rf /")
    rows = db.get_session_commands("sess-blocklog", limit=10)
    assert len(rows) == 1
    assert rows[0]["source"] == "containment"
    events = [e["event_type"] for e in db.get_session_events("sess-blocklog")]
    assert "SANDBOX_BLOCK" in events


def test_unparsable_command_logged_once_via_llm(test_db, no_llm):
    # Empty input parses to an empty pipeline (no stages), so the router's
    # LLM-direct branch is the only logging point, and it must log exactly
    # once.
    router.process_command("sess-empty", "")
    rows = db.get_session_commands("sess-empty", limit=10)
    assert len(rows) == 1
    assert rows[0]["source"] == "llm"


# --- Bounded resources -----------------------------------------------------------

def test_oversized_write_refused(test_db):
    # MAX_FILE_SIZE: a redirect that would store more than the cap is
    # refused with a disk-full style error, never stored unbounded.
    session = db.get_or_create_session("sess-bounds")
    db.save_virtual_file(
        "sess-bounds", "/home/admin/big.txt", "x" * (config.MAX_FILE_SIZE + 1)
    )
    out, _ = vfs.execute_vfs_command(
        "sess-bounds", "cat /home/admin/big.txt > /home/admin/copy.txt", session["cwd"]
    )
    assert "no space left" in out.lower()
    assert db.get_virtual_file("sess-bounds", "/home/admin/copy.txt") is None


def test_sandbox_output_truncated(test_db):
    # MAX_OUTPUT_LENGTH is enforced in the sandbox no matter which backend
    # produced the bytes — build an oversized file in the DB, then cat it.
    session = db.get_or_create_session("sess-trunc")
    db.save_virtual_file(
        "sess-trunc", "/tmp/big.txt", "x" * (config.MAX_OUTPUT_LENGTH + 100)
    )
    output = sandbox.execute("sess-trunc", "cat /tmp/big.txt", session["cwd"])
    assert len(output) <= config.MAX_OUTPUT_LENGTH


def test_session_file_cap_refuses_new_files(test_db):
    # MAX_SESSION_FILES: a session that hit the cap cannot create more
    # files, but overwriting an existing one still works.
    session = db.get_or_create_session("sess-cap")
    db.save_virtual_file("sess-cap", "/home/admin/keep.txt", "kept")
    target_count = config.MAX_SESSION_FILES
    original_count = db.count_virtual_files("sess-cap")
    rows_needed = max(0, target_count - original_count)
    for i in range(rows_needed):
        db.save_virtual_file("sess-cap", f"/tmp/filler_{i}.txt", "x")
    assert db.count_virtual_files("sess-cap") >= config.MAX_SESSION_FILES

    out_touch, _ = vfs.execute_vfs_command(
        "sess-cap", "touch /tmp/brand_new.txt", session["cwd"]
    )
    assert db.get_virtual_file("sess-cap", "/tmp/brand_new.txt") is None
    assert "too many open files" in out_touch.lower()

    out_echo, _ = vfs.execute_vfs_command(
        "sess-cap", "echo hello > /home/admin/keep.txt", session["cwd"]
    )
    assert db.get_virtual_file("sess-cap", "/home/admin/keep.txt")["content"] == "hello"


def test_ls_long_format_renders(test_db):
    # Regression for the flag-ordering bug: "-l" used to be filtered out of
    # args before the long-format check, so `ls -l` never rendered long form.
    session = db.get_or_create_session("sess-lsl")
    out, _ = vfs.execute_vfs_command("sess-lsl", "ls -l", session["cwd"])
    assert out.startswith("total ")
    out2, _ = vfs.execute_vfs_command("sess-lsl", "ls -la", session["cwd"])
    assert out2.startswith("total ")


# --- Host-leakage (STEP 19) -----------------------------------------------------
#
# The honeypot presents a fixed decoy identity ("admin" on host "mirage").
# Nothing an attacker can observe — output strings, virtual file contents,
# session state — may ever reveal the real host's username, hostname, or
# filesystem layout.

HOST_USERNAME = None  # the host user this suite runs as; None under some CI sandboxes
try:
    HOST_USERNAME = os.getlogin()
except OSError:
    HOST_USERNAME = os.environ.get("USER") or os.environ.get("LOGNAME")

# When the host username collides with the fixed decoy, the decoy checks are
# vacuous — the honeypot cannot avoid presenting the host's name if the
# host's name IS the decoy. CI/dev boxes (ubuntu, runner) never collide.
LEAK_USER = HOST_USERNAME if HOST_USERNAME and HOST_USERNAME != config.DEFAULT_USER else None


def _all_outputs(session_id, cwd):
    """Every observable string a fresh session can produce, plus stored files."""
    commands = [
        "whoami", "id", "uname -a", "pwd", "ls", "ls -l", "ls /",
        "cat /etc/passwd", "ps aux", "netstat -tlnp",
        "nmap 10.0.2.10", "nmap 10.0.2.15",
    ]
    seen = []
    for command in commands:
        seen.append(sandbox.execute(session_id, command, cwd))
    for f in db.list_virtual_files(session_id):
        if f.get("content"):
            seen.append(f["content"])
    session = db.get_session_by_id(session_id)
    seen.append(str(session.get("cwd", "")))
    seen.append(str(session.get("threat_level", "")))
    return seen


def test_no_host_username_in_any_output(test_db, no_llm):
    # config.DEFAULT_USER is the only identity the honeypot ever presents.
    # The real host username ("ubuntu" on this box) must never appear in any
    # output, any stored file, or session state.
    db.get_or_create_session("sess-leak-user")
    outputs = _all_outputs("sess-leak-user", config.DEFAULT_CWD)
    for out in outputs:
        if LEAK_USER:
            assert LEAK_USER not in out, out
    assert "ubuntu" not in " ".join(outputs).lower()


def test_no_host_hostname_in_any_output(test_db, no_llm):
    # uname/hostname always present the decoy "mirage", never the real host.
    db.get_or_create_session("sess-leak-host")
    outputs = _all_outputs("sess-leak-host", config.DEFAULT_CWD)
    for out in outputs:
        if LEAK_USER:
            assert LEAK_USER not in out, out
    for out in outputs:
        assert "ip-" not in out.lower(), out  # AWS hostnames look like ip-10-0-...
    whoami_out = sandbox.execute("sess-leak-host", "whoami", config.DEFAULT_CWD)
    assert whoami_out == config.DEFAULT_USER
    uname_out = sandbox.execute("sess-leak-host", "uname -a", config.DEFAULT_CWD)
    assert uname_out.startswith("Linux mirage")


def test_no_host_paths_in_any_output(test_db, no_llm):
    # Every observable path lives under the virtual root: nothing like the
    # real "/home/ubuntu/..." may ever be returned or stored.
    db.get_or_create_session("sess-leak-path")
    outputs = _all_outputs("sess-leak-path", config.DEFAULT_CWD)
    for out in outputs:
        lowered = out.lower()
        if LEAK_USER:
            assert f"/home/{LEAK_USER.lower()}" not in lowered, out
        assert "/home/ubuntu" not in lowered, out


def test_path_tricks_never_yield_host_paths(test_db, no_llm):
    # Traversal, ~, and deep escapes all resolve inside the virtual tree.
    db.get_or_create_session("sess-leak-tricks")
    cwd = config.DEFAULT_CWD
    probes = [
        ("cat /home/admin/../../../../etc/shadow", True),   # resolves to /etc/shadow
        ("cat /etc/./shadow", True),
        ("cat ~/../../etc/shadow", True),
        ("cd ../../../..", False),                          # stays inside the tree
        ("cat /proc/self/environ", False),                  # no such virtual file
    ]
    for command, _decl in probes:
        output = sandbox.execute("sess-leak-tricks", command, cwd)
        assert isinstance(output, str)
        if LEAK_USER:
            assert f"/home/{LEAK_USER}" not in output, output
        assert "/home/ubuntu" not in output.lower(), output
        if command.startswith("cat ") and "shadow" in command:
            # Whatever the spelling, shadow content must never come back.
            assert "$6$salt$hash" not in output


def test_no_identity_or_net_or_process_apis_in_source():
    # Static guard: no module in app/ may derive identity from the host,
    # touch the process table, or open sockets — the honeypot must be pure
    # simulation. (sqlite3 in db.py and the FastAPI server itself are exempt:
    # neither reads host identity nor opens outbound sockets.)
    import pathlib

    banned_modules = {"socket", "subprocess", "shutil", "pty", "multiprocessing",
                      "urllib", "telnetlib", "ftplib"}
    forbidden_os = {"getlogin", "environ", "system", "popen", "execve", "fork", "kill"}
    # realpath chases host symlinks; expanduser pulls the real $HOME.
    # abspath is allowed — db.py uses it on __file__, never on attacker input.
    forbidden_os_path = {"realpath", "expanduser"}

    app_dir = pathlib.Path(__file__).resolve().parent.parent / "app"
    for path in sorted(app_dir.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in banned_modules, \
                        f"{path.name}: forbidden import {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                assert root not in banned_modules, \
                    f"{path.name}: forbidden import from {node.module}"
            elif isinstance(node, ast.Attribute):
                value = node.value
                if isinstance(value, ast.Name) and value.id == "os":
                    assert node.attr not in forbidden_os, \
                        f"{path.name}: forbidden os.{node.attr}"
                if (isinstance(value, ast.Attribute) and value.attr == "path"
                        and isinstance(value.value, ast.Name) and value.value.id == "os"):
                    assert node.attr not in forbidden_os_path, \
                        f"{path.name}: forbidden os.path.{node.attr}"


def test_config_identity_is_fixed_decoy():
    # The identity constants are literal decoys — not derived from env/host.
    import pathlib

    source = pathlib.Path(config.__file__).read_text()
    assert 'DEFAULT_USER = "admin"' in source
    assert config.DEFAULT_USER == "admin"
    assert config.DEFAULT_HOME == f"/home/{config.DEFAULT_USER}" == "/home/admin"
