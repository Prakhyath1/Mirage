"""Dashboard (T4) tests: the Streamlit operator view must actually render
against the current T3 seams.

The dashboard rotted invisibly before this file existed — pandas had removed
Styler.applymap (instant crash on render), pandas wasn't pinned in
requirements.txt, and a bare `streamlit run` couldn't even import the app
package. These tests pin all three:

  render      the full script renders against a seeded temp DB through
              Streamlit's AppTest — db seams, pandas Styler API, structure;
  anchoring   `from app import db` resolves in Streamlit's sys.path context
              (script dir only, no repo root, cwd anywhere);
  placement   st.rerun() stays the final statement — when it lived at the
              top of the script the page looped forever showing only the
              title, because st.rerun() discards everything after the call.
"""

import os
import subprocess
import sys
import textwrap

import pytest
import streamlit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import db
from app import honeytokens
from streamlit.testing.v1 import AppTest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARD_PATH = os.path.join(REPO_ROOT, "dashboard", "dashboard.py")
DASHBOARD_DIR = os.path.dirname(DASHBOARD_PATH)


@pytest.fixture()
def seeded_db(monkeypatch, tmp_path):
    """A temp DB holding one session, one log row, and one honeytoken trip,
    so every dashboard section renders content instead of its empty state."""
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "dashboard.db"))
    db.init_db()
    db.get_or_create_session("dash-1")
    db.log_command("dash-1", "whoami", "admin", "sandbox")
    honeytokens.trip("dash-1", "/home/admin/.env")
    yield


def test_dashboard_renders_every_section(seeded_db, monkeypatch):
    # The script ends with time.sleep(2) + st.rerun(), which under AppTest
    # loops until the run timeout and leaves the element tree unparsed.
    # The render path is identical with a no-op rerun, so patch it and let
    # the script run to completion.
    monkeypatch.setattr(streamlit, "rerun", lambda *a, **k: None)

    at = AppTest.from_file(DASHBOARD_PATH)
    at.run(timeout=15)

    assert len(at.exception) == 0
    assert [t.value for t in at.title] == ["🪞 Mirage Honeypot Dashboard"]
    assert [m.label for m in at.metric] == [
        "Total Sessions",
        "Active Sessions",
        "High Threat Actors",
        "Honeytoken Trips",
    ]
    values = {m.label: int(m.value) for m in at.metric}
    assert values["Total Sessions"] == 1
    assert values["Active Sessions"] == 1
    assert values["Honeytoken Trips"] == 1
    # Sessions table, honeytoken events, command logs — all three sections
    # have data, so none took the st.info empty branch. Rendering the
    # sessions table is what exercises the pandas Styler API.
    assert len(at.dataframe) == 3
    # The Auto Refresh toggle registered before anything else rendered.
    assert len(at.checkbox) == 1


def test_repo_root_anchoring_survives_streamlit_run_path(tmp_path):
    """`streamlit run dashboard/dashboard.py` executes the script with its own
    directory — not the repo root — on sys.path, from whatever cwd the
    operator launched. The dashboard's _REPO_ROOT anchoring must make
    `from app import db` resolve in exactly that context."""
    with open(DASHBOARD_PATH) as fh:
        prologue = fh.read().split("st.set_page_config", 1)[0]
    # Guard the extraction: the isolated prologue must contain the import
    # whose resolution this test is about.
    assert "from app import db" in prologue

    code = textwrap.dedent(f"""\
        import sys
        # Streamlit's context: the script's dir is on sys.path, the repo root
        # is not, and the cwd (a scratch dir) must not rescue the import.
        sys.path.insert(0, {DASHBOARD_DIR!r})
        sys.path = [p for p in sys.path if p not in ({REPO_ROOT!r}, "")]
        # Streamlit executes the app script with __file__ set in its module
        # globals (see streamlit/runtime/scriptrunner/exec_code.py) — the
        # anchoring is built on os.path.abspath(__file__). Reproduce that.
        exec({prologue!r}, {{"__file__": {DASHBOARD_PATH!r}}})
        print("ANCHOR_OK")
    """)
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert result.returncode == 0, result.stderr
    assert "ANCHOR_OK" in result.stdout


def test_refresh_rerun_is_the_last_statement():
    """st.rerun() restarts the script immediately — anything after the call
    never renders. The original dashboard called it near the top, so with
    auto-refresh on (the default) the page looped forever showing only the
    title. Pin the fix: the rerun call ends the script."""
    with open(DASHBOARD_PATH) as fh:
        source = fh.read()
    assert source.rstrip().endswith("st.rerun()"), (
        "st.rerun() must be the final statement in dashboard/dashboard.py, "
        "or auto-refresh restarts the script before any element renders"
    )
