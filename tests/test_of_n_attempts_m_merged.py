"""What became of every attempt, counted honestly. Item 119.

DR-0005 gives each instance the job of counting its own outcomes; `status` could say what was
waiting and what was running, and not what had come of what it had already done.

**Everything here is shaped by the twenty attempts on the live instance**, and the one that matters
most is attempt 10: `rehearsal: true` and `pr-open`, because a rehearsal runs every gate and writes
its patch to disk. A funnel that counted it reports five pull requests where the forge holds four —
wrong, in the flattering direction, on the line an outsider reads first.
"""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from hullwork import outcomes
from hullwork.attempts import finish, start
from hullwork.config import get_settings
from hullwork.db import make_engine, make_session_factory
from hullwork.models import AttemptOutcome, Base, Item, Lane, Project


@pytest.fixture
def session(tmp_path: Path) -> Iterator[Session]:
    """Overrides `conftest`'s deliberately: this one needs a database **on disk**.

    Closed and disposed for the reason `conftest` gives — an undisposed engine holds its pool open,
    which on a file-backed SQLite is an open descriptor and on `sqlite://` is the whole database.
    """
    engine = make_engine(f"sqlite:///{tmp_path / 'funnel.db'}")
    Base.metadata.create_all(engine)
    made = sessionmaker(bind=engine)()
    try:
        yield made
    finally:
        made.close()
        engine.dispose()


def _item(session: Session, fingerprint: str) -> Item:
    project = session.query(Project).one_or_none()
    if project is None:
        project = Project(
            slug="p", forge="forgejo", repo="o/r", webhook_secret_hash="x",  # noqa: S106
        )
        session.add(project)
        session.flush()
    row = Item(project_id=project.id, fingerprint=fingerprint, lane=Lane.GREEN, title="t")
    session.add(row)
    session.flush()
    return row


def _attempt(
    session: Session,
    fingerprint: str,
    outcome: AttemptOutcome | None,
    *,
    rehearsal: bool = False,
    pull_request: str | None = None,
    merged: bool = False,
) -> None:
    attempt = start(session, _item(session, fingerprint))
    attempt.pull_request_ref = pull_request
    if merged:
        attempt.merge_commit = "deadbee"
    if outcome is not None:
        finish(session, attempt, outcome, rehearsal=rehearsal)
    session.commit()


def _the_live_instance(session: Session) -> None:
    """The twenty attempts as they stand in production, including the awkward one."""
    for n in range(9):  # nine rehearsals that reached various verdicts
        _attempt(session, f"r{n}", AttemptOutcome.NOT_REPRODUCIBLE, rehearsal=True)
    # **Attempt 10**: a rehearsal that reached `pr-open`, with a patch on disk and no forge state.
    _attempt(session, "r9", AttemptOutcome.PR_OPEN, rehearsal=True, pull_request="#0")

    for n in range(4):
        _attempt(session, f"pr{n}", AttemptOutcome.PR_OPEN, pull_request=f"#{n + 6}", merged=True)
    _attempt(session, "nr", AttemptOutcome.NOT_REPRODUCIBLE)
    _attempt(session, "f", AttemptOutcome.FAILED)
    _attempt(session, "br1", AttemptOutcome.BASELINE_RED)
    _attempt(session, "br2", AttemptOutcome.BASELINE_RED)
    _attempt(session, "ab1", AttemptOutcome.ABANDONED)
    _attempt(session, "ab2", AttemptOutcome.ABANDONED)


def test_it_agrees_with_the_forge_on_the_live_instances_own_history(session: Session) -> None:
    """**The measurement, as an assertion.** Four pull requests exist on the forge and four were
    merged; six runs got a fair try and four did not. Every number here was cross-checked against
    the real database and the real forge before this test existed."""
    _the_live_instance(session)

    counted = outcomes.funnel(session)

    assert counted.fair_try == 6
    assert counted.pull_requests == 4, "five would be the rehearsal leaking in"
    assert counted.merged == 4
    assert counted.not_reproducible == 1
    assert counted.failed == 1
    assert counted.did_not_count == 4
    assert counted.rehearsals == 10


def test_a_rehearsal_that_reached_pr_open_is_not_a_pull_request(session: Session) -> None:
    """The single most likely way for this line to lie, and it is not hypothetical: attempt 10 on
    the live instance is exactly this. A rehearsal runs every gate and publishes nothing."""
    _attempt(session, "only", AttemptOutcome.PR_OPEN, rehearsal=True, pull_request="#1")

    counted = outcomes.funnel(session)

    assert counted.pull_requests == 0
    assert counted.fair_try == 0
    assert counted.rehearsals == 1
    assert any("publish nothing" in line for line in outcomes.lines(counted)), (
        "an operator who has only rehearsed must not read silence as nothing having happened"
    )


def test_what_never_counted_is_named_rather_than_dropped_or_folded_in(session: Session) -> None:
    """Both wrong answers are easy and neither is honest. Folding them into the denominator counts
    the project's broken suite as the agent's failure; dropping them hides that a third of the runs
    never got to try."""
    _attempt(session, "pr", AttemptOutcome.PR_OPEN, pull_request="#1", merged=True)
    _attempt(session, "br", AttemptOutcome.BASELINE_RED)
    _attempt(session, "ab", AttemptOutcome.ABANDONED)

    counted = outcomes.funnel(session)
    said = " ".join(outcomes.lines(counted))

    assert counted.fair_try == 1, "the two that never counted are not in the denominator"
    assert counted.never_counted == {
        AttemptOutcome.BASELINE_RED: 1,
        AttemptOutcome.ABANDONED: 1,
    }
    assert "baseline-red (the project's suite was already failing)" in said
    assert "abandoned (the infrastructure got in the way)" in said


def test_an_attempt_in_flight_is_neither_a_success_nor_a_failure(session: Session) -> None:
    """It has no outcome yet. Counting it as anything is inventing one, and `status` is typed most
    often while a dispatcher is in the middle of something."""
    _attempt(session, "running", None)

    counted = outcomes.funnel(session)

    assert counted.in_flight == 1
    assert counted.fair_try == 0 and counted.did_not_count == 0
    assert any("neither" in line for line in outcomes.lines(counted))


def test_no_percentage_is_printed_anywhere(session: Session) -> None:
    """**A fraction, never a rate.** `4 of 6` carries the same information without asserting a
    precision six samples do not have — and a percentage invites comparison between two instances
    running different code on different repositories, which is a number that belongs to nobody.
    """
    _the_live_instance(session)

    said = " ".join(outcomes.lines(outcomes.funnel(session)))

    assert "%" not in said
    assert "4 of those 4 pull request(s) were merged" in said


def test_an_instance_that_has_attempted_nothing_says_nothing(session: Session) -> None:
    """Silence rather than a row of zeros, which reads like failure rather than like a beginning."""
    assert outcomes.lines(outcomes.funnel(session)) == []


def test_status_prints_it_and_json_carries_the_raw_counts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """End to end through the command an operator types — and `--json` keeps the numbers rather than
    the sentences, so anybody who wants a percentage computes their own."""
    from hullwork.cli import main as cli_main

    url = f"sqlite:///{tmp_path / 'status.db'}"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    with make_session_factory(engine)() as db:
        _the_live_instance(db)

    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "ingest")
    get_settings.cache_clear()
    try:
        text, payload = io.StringIO(), io.StringIO()
        cli_main(["status"], out=text)
        cli_main(["status", "--json"], out=payload)
        printed = text.getvalue()
        machine = json.loads(payload.getvalue())["attempts"]
    finally:
        get_settings.cache_clear()

    assert "Attempts:" in printed
    assert "6 attempt(s) got a fair try" in printed
    assert machine["pull_requests"] == 4
    assert machine["merged"] == 4
    assert machine["rehearsals"] == 10
    assert machine["never_counted"] == {"baseline-red": 2, "abandoned": 2}
