"""Production report: sqlite3.OperationalError: no such table: items.

`readiness._database_state` explicitly catches any exception while probing the database — a
`BEGIN IMMEDIATE` against a brand new, empty SQLite file succeeds, because the file itself is
writable even though it holds no tables. `readiness._backlog`, called right after it from
`readiness.check`, carries no such guard and queries the `items` table directly. An instance that
boots against an empty database — the exact scenario `hullwork.doctor.database_built` exists to
diagnose, where `HULLWORK_DATABASE_URL` is unset and SQLite creates an empty file beside the real
one — makes `/ready` raise an unhandled `sqlite3.OperationalError` instead of answering 503.
"""

from pathlib import Path

import pytest

from hullwork import readiness
from hullwork.config import Settings
from hullwork.db import make_engine, make_session_factory


def test_ready_check_does_not_crash_on_a_database_with_no_tables(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'empty.db'}"
    settings = Settings(database_url=url)
    session = make_session_factory(make_engine(url))()

    try:
        report = readiness.check(session, settings, error_reporting=False)
    finally:
        session.close()

    assert report.ready is False


def test_status_says_the_schema_is_missing_instead_of_raising(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**The symptom had three causes and the test above covers one.**

    The agent that wrote the fix above found `readiness.check`, fixed it at the right layer, and its
    gate went green — while `hullwork status` still printed a raw traceback, from `readiness_notes`
    and then from `lease.state`. The red-green gate proves *a test that failed now passes*, exactly
    what it promises, and that is not the same claim as *the reported problem is gone*. A human ran
    the command again. That is what the human gate is for.

    Guarding all three was the wrong shape — the fact is singular — so `_cmd_status` asks
    `doctor.database_built` once, which is the check written for this after the 2026-07-29 failure.
    Asserted through `main`, because the defect was that a careful sentence existed and no path
    reached it.
    """
    import io

    from hullwork.cli import main as cli_main
    from hullwork.config import get_settings

    monkeypatch.setenv("HULLWORK_DATABASE_URL", f"sqlite:///{tmp_path / 'empty.db'}")
    monkeypatch.chdir(tmp_path)
    get_settings.cache_clear()

    err = io.StringIO()
    monkeypatch.setattr("sys.stderr", err)
    code = cli_main(["status"], out=io.StringIO())
    get_settings.cache_clear()

    assert code == 1
    assert "Traceback" not in err.getvalue()
    assert "holds no tables" in err.getvalue()
