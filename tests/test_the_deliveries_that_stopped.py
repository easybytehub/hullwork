"""Whether the webhook path is still delivering. Item 158.

**Found by item 155's gate on 2026-08-06**, following an upstream event that had reached the tracker
and never became an item. Two independent faults on our own deployment: the token the tracker held
answered `401`, and the tracker's container could not route to the receiver's address at all. The
last delivery was eight days old.

It was invisible because the **inventory sweep** covers for it — polling the tracker per project, it
had been filing items all along. So the loop kept working with half its input gone, and nothing
anywhere said so: `status` reports what has happened, `doctor` reports what is broken, and neither
knew a webhook had not arrived since July.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import SecretStr
from sqlalchemy.orm import Session

from hullwork import doctor
from hullwork.config import Settings
from hullwork.doctor import State
from hullwork.models import Delivery, Project


def _project(session: Session, slug: str = "acme", *, tracker: str | None = "acme") -> Project:
    project = Project(
        slug=slug,
        forge="forgejo",
        repo=f"owner/{slug}",
        webhook_secret_hash="x" * 64,
        manifest={"project": slug},
        tracker_project=tracker,
    )
    session.add(project)
    session.commit()
    return project


def _deliveries(session: Session, project: Project, ago: list[timedelta]) -> None:
    """Deliveries at the given ages. Distinct payload hashes, because `(project, provider id, hash)`
    is unique — that constraint *is* the deduplication this product is built on.
    """
    now = datetime.now(UTC)
    for n, delta in enumerate(ago):
        session.add(
            Delivery(
                project_id=project.id,
                provider="glitchtip",
                payload_hash=f"{n:064d}",
                received_at=now - delta,
            )
        )
    session.commit()


def _with_tracker(**extra: object) -> Settings:
    return Settings(
        database_url="sqlite://",
        tracker_url="https://tracker.example",
        tracker_token=SecretStr("t"),
        **extra,  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------------------------
# Three answers, and the middle one is why this is not two
# --------------------------------------------------------------------------------------------


def test_no_tracker_configured_is_expected_rather_than_a_warning(session: Session) -> None:
    """The item's third criterion. An instance with no tracker has never received a webhook, and
    that is a deliberate gap — `expected` exists so it is neither hidden nor sent to be fixed.
    """
    _project(session, tracker=None)

    found = doctor.deliveries_are_still_arriving(session, Settings(database_url="sqlite://"))

    assert [f.state for f in found] == [State.EXPECTED]
    assert "no tracker configured" in found[0].detail


def test_configured_and_nothing_ever_arrived_is_unknown(session: Session) -> None:
    """A project registered ten minutes ago and one whose webhook was never pasted into the tracker
    look identical from here. Answering either would be inventing one — and it names the command
    that prints the URL again, because the token cannot be shown twice.
    """
    _project(session)

    found = doctor.deliveries_are_still_arriving(session, _with_tracker())

    assert [f.state for f in found] == [State.UNKNOWN]
    assert "no delivery has ever arrived" in found[0].detail
    assert "rotate-secret acme" in found[0].detail


def test_arrived_and_then_stopped_is_broken_and_says_it_used_to_work(session: Session) -> None:
    """**The case that was live on our own instance for eight days.** The useful sentence is *"it
    used to work"*, so both the age and the date are in the message, and so are the two causes in
    the order they were actually found.
    """
    project = _project(session)
    # Hourly for a while, then eight days of silence.
    _deliveries(
        session,
        project,
        [timedelta(days=8) + timedelta(hours=n) for n in range(6)],
    )

    found = doctor.deliveries_are_still_arriving(session, _with_tracker())

    assert [f.state for f in found] == [State.BROKEN]
    detail = found[0].detail
    assert "deliveries stopped" in detail
    assert "8d" in detail, "how long, in a unit a human reads"
    assert "token" in detail and "cannot reach this address" in detail, "both causes, in order"
    assert "inventory sweep" in detail, "say why nothing else complained"


def test_a_project_that_is_simply_quiet_is_not_broken(session: Session) -> None:
    """A project whose errors are rare is not a project whose webhook is dead, and an alarm that
    fires on a good week is an alarm somebody switches off.
    """
    project = _project(session)
    # Monthly deliveries, the last one three weeks ago: quiet, and normal for this project.
    _deliveries(session, project, [timedelta(days=21 + 30 * n) for n in range(4)])

    found = doctor.deliveries_are_still_arriving(session, _with_tracker())

    assert [f.state for f in found] == [State.OK]
    assert "within the" in found[0].detail


# --------------------------------------------------------------------------------------------
# The threshold, which the item said may not be a guess
# --------------------------------------------------------------------------------------------


def test_the_threshold_comes_from_the_projects_own_traffic() -> None:
    """**Derived, not chosen**, because a fixed number is wrong in both directions at once: a
    project with an error an hour is broken after a day of silence, and one with an error a month is
    fine after three weeks.
    """
    hourly = doctor._how_quiet_is_too_quiet([3600.0] * 5)
    monthly = doctor._how_quiet_is_too_quiet([30 * 86400.0] * 5)

    assert hourly == doctor._QUIET_FLOOR_SECONDS, "the floor protects a chatty project from itself"
    assert monthly == doctor._QUIET_CEILING_SECONDS, "and the ceiling stops it being unfalsifiable"
    assert doctor._how_quiet_is_too_quiet([5 * 86400.0]) == 10 * 86400.0, "twice the longest gap"


def test_a_project_with_one_delivery_falls_back_to_the_floor() -> None:
    """No gaps to learn from, so the floor — and the floor is a week, with the reason written where
    the constant is.
    """
    assert doctor._how_quiet_is_too_quiet([]) == doctor._QUIET_FLOOR_SECONDS
    assert doctor._QUIET_FLOOR_SECONDS == 7 * 86400


# --------------------------------------------------------------------------------------------
# It has to be asked, and asked where it can be answered
# --------------------------------------------------------------------------------------------


def test_the_check_is_wired_into_the_doctor_command() -> None:
    """The defect underneath item 158 was not a missing check, it was a missing *question*. A check
    nothing calls is the same silence with more code in it.
    """
    text = Path(doctor.__file__).read_text(encoding="utf-8")

    assert "findings.extend(deliveries_are_still_arriving(session, settings))" in text
    assert '"deliveries",\n                State.UNKNOWN,\n                "not asked' in text, (
        "an unqueryable database has to say the question was not asked, not report OK"
    )


def test_no_active_project_is_ok_rather_than_silent(session: Session) -> None:
    """Nothing to check is knowledge too — item 144's category error, one step out."""
    found = doctor.deliveries_are_still_arriving(session, _with_tracker())

    assert [f.state for f in found] == [State.OK]
    assert "no active project" in found[0].detail


def test_the_column_refuses_a_naive_timestamp_so_the_check_need_not(session: Session) -> None:
    """**Why the check has no timezone defence in it.**

    This test was written to exercise one — a row with a naive `received_at`, the way an older build
    might have left it — and could not create the row: `UtcDateTime` refuses at write time. So the
    guarantee lives in the column, and a branch for it in `doctor` would be code that can never run
    pretending to be care.
    """
    project = _project(session)

    session.add(
        Delivery(
            project_id=project.id,
            provider="glitchtip",
            payload_hash="1" * 64,
            received_at=datetime.now(UTC).replace(tzinfo=None),
        )
    )
    with pytest.raises(Exception, match="naive datetime"):
        session.commit()
    session.rollback()
