"""`database is locked`: who was holding the write lock, and for how long. Item 081.

Measured on the live instance in one day: 58 events on the receiver's `UPDATE items SET
forge_checked_at=…`, and two on **`INSERT INTO deliveries`** — an inbound webhook failing to be
stored, which loses an error for ever, because a tracker notifies once per issue and never retries.

**Two plausible causes were measured and both were wrong**, which is the reason this file states
what
it excludes as well as what it asserts:

* *"`busy_timeout` is missing"* — it is not. pysqlite sets 5000ms by default and SQLAlchemy inherits
  it. Adding the pragma would have been a no-op documented as a fix.
* *"a read snapshot is promoted to a write across a network call"* — cannot happen by this route.
  pysqlite emits no `BEGIN` before a `SELECT`, so a read holds no snapshot; the `BEGIN` arrives with
  the first write.

What was actually happening: `attempts.record` flushed instead of committing, so the **first
recorded
step of an attempt took the write lock and held it until the attempt ended** — and between two steps
sits a model phase or a whole test suite. 12m56s, measured, against a 5s timeout.
"""

import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from hullwork import attempts
from hullwork.config import get_settings
from hullwork.db import make_engine, make_session_factory
from hullwork.models import AttemptPhase, Item, ItemState, Project

ROOT = Path(__file__).resolve().parent.parent

MANIFEST: dict[str, object] = {
    "version": 1,
    "project": "p",
    "git": {"provider": "forgejo", "repo": "o/r"},
    "errors": {"provider": "glitchtip"},
    "autofix": {"agent": "none", "lanes": {"green": ["valueerror"]}},
}


@pytest.fixture
def database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    path = tmp_path / "contention.db"
    monkeypatch.setenv("HULLWORK_DATABASE_URL", f"sqlite:///{path}")
    get_settings.cache_clear()
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.cmd_opts = None
    command.upgrade(cfg, "head")
    yield path
    get_settings.cache_clear()


def _other_writer(path: Path, *, timeout: float = 5.0) -> str:
    """What the receiver's sweep does every sixty seconds, from its own connection.

    A real second connection, because the failure exists only between them: a double cannot hold a
    SQLite write lock and so cannot be refused by one.
    """
    conn = sqlite3.connect(path, timeout=timeout, isolation_level=None)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("UPDATE items SET forge_checked_at=datetime('now') WHERE id=1")
        conn.commit()
        return "ok"
    except sqlite3.OperationalError as exc:
        return str(exc)
    finally:
        conn.close()


def _an_attempt_in_progress(path: Path) -> tuple[object, object, object]:
    engine = make_engine(f"sqlite:///{path}")
    session = make_session_factory(engine)()
    project = Project(
        slug="p", forge="forgejo", repo="o/r",
        webhook_secret_hash="x",  # noqa: S106
        manifest=MANIFEST,
    )
    session.add(project)
    session.flush()
    item = Item(
        project_id=project.id, fingerprint="fp", title="ValueError: boom",
        state=ItemState.IN_PROGRESS,
    )
    session.add(item)
    session.commit()
    attempt = attempts.start(session, item)
    session.commit()
    return session, attempt, engine


# --- what the timeout is, so nobody adds it again as a fix --------------------------------------


def test_the_busy_timeout_is_already_five_seconds(database: Path) -> None:
    """Not a feature of this codebase — pysqlite's default, inherited.

    Recorded as a test because "add a `busy_timeout`" is the first thing anybody reaches for on
    reading `database is locked`, and doing it here changes nothing at all. The number is what makes
    the real cause obvious: a 5s wait cannot explain a failure against a lock held for minutes.
    """
    with make_session_factory(make_engine(f"sqlite:///{database}"))() as session:
        assert session.execute(text("PRAGMA busy_timeout")).scalar_one() == 5000


def test_a_read_holds_no_write_lock_by_this_route(database: Path) -> None:
    """The other rejected cause. pysqlite emits no `BEGIN` before a `SELECT`.

    So "a read snapshot promoted to a write across a network call" — real in SQLite, and the shape a
    timeout genuinely cannot fix — is unreachable through SQLAlchemy here. Asserted, because the fix
    it implies is a scattering of commits before every network call, and that would be a large
    change
    made for a reason that does not hold.
    """
    engine = make_engine(f"sqlite:///{database}")
    with make_session_factory(engine)() as session:
        session.execute(text("SELECT count(*) FROM items")).scalar_one()
        raw = session.connection().connection.dbapi_connection
        assert raw is not None
        assert raw.in_transaction is False, "a select left no transaction open"

        # Another writer succeeds while that select's session is still alive.
        assert _other_writer(database) == "ok"


# --- the real cause, asserted by effect ---------------------------------------------------------


def test_recording_a_step_does_not_hold_the_lock_for_the_rest_of_the_attempt(
    database: Path,
) -> None:
    """**The 58-event failure, and the two that lost data.**

    `attempts.record` flushed, so the insert opened a transaction that nothing closed until the
    attempt finished — with a model phase or a whole suite run between steps. Everything else
    writing
    to that file was refused for the duration.

    Asserted from a **second connection**, the way the receiver's sweep and the request path
    actually
    arrive. Before the fix, the second call here returns `database is locked`.
    """
    session, attempt, engine = _an_attempt_in_progress(database)
    try:
        assert _other_writer(database) == "ok", "nothing is held before the first step"

        attempts.record(
            session, attempt, AttemptPhase.BASELINE, "pytest",  # type: ignore[arg-type]
            exit_code=0, output="720 passed",
        )

        # This is the moment the attempt spends most of its life in: one step recorded, minutes of
        # sandbox work still to come.
        assert _other_writer(database) == "ok", (
            "the write lock is still held after recording a step, so every other writer is refused "
            "for the rest of the attempt"
        )

        attempts.record(
            session, attempt, AttemptPhase.REPRODUCE, "agent",  # type: ignore[arg-type]
            exit_code=0, output="wrote a test",
        )
        assert _other_writer(database) == "ok"
    finally:
        session.close()  # type: ignore[attr-defined]
        engine.dispose()  # type: ignore[attr-defined]


def test_a_recorded_step_survives_the_dispatcher_dying(database: Path) -> None:
    """The half that is a promise rather than a lock. `start`'s docstring:

    > *written before anything runs, so a crash still leaves a trace*

    With a flush that was false for every step: a killed dispatcher rolled back the whole
    uncommitted transaction and the trail went with it. Simulated by abandoning the session without
    committing, which is what a `docker kill` amounts to.
    """
    session, attempt, engine = _an_attempt_in_progress(database)
    attempt_id = attempt.id  # type: ignore[attr-defined]
    attempts.record(
        session, attempt, AttemptPhase.BASELINE, "pytest",  # type: ignore[arg-type]
        exit_code=1, output="1 failed",
    )
    session.close()  # type: ignore[attr-defined]
    engine.dispose()  # type: ignore[attr-defined]

    fresh = sqlite3.connect(database)
    try:
        rows = fresh.execute(
            "SELECT phase, exit_code FROM attempt_steps WHERE attempt_id=?", (attempt_id,)
        ).fetchall()
    finally:
        fresh.close()

    assert rows == [("baseline", 1)], "the step outlived the process that recorded it"


def test_the_step_is_still_ordered_and_moves_the_phase(database: Path) -> None:
    """Committing must not change what `record` records. Ordinals stay dense and in order."""
    session, attempt, engine = _an_attempt_in_progress(database)
    try:
        for phase in (AttemptPhase.BASELINE, AttemptPhase.REPRODUCE, AttemptPhase.RED_GATE):
            attempts.record(session, attempt, phase, f"cmd-{phase.value}")  # type: ignore[arg-type]

        steps = sorted(attempt.steps, key=lambda step: step.ordinal)  # type: ignore[attr-defined]
        assert [step.ordinal for step in steps] == [0, 1, 2]
        assert [step.phase for step in steps] == [
            AttemptPhase.BASELINE, AttemptPhase.REPRODUCE, AttemptPhase.RED_GATE
        ]
        assert attempt.phase_reached is AttemptPhase.RED_GATE  # type: ignore[attr-defined]
    finally:
        session.close()  # type: ignore[attr-defined]
        engine.dispose()  # type: ignore[attr-defined]
