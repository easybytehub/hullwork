"""A merged fix whose verdict can never arrive. Item 121.

**Measured on the live instance, 2026-08-02.** Four merged fixes; three `quiet` with a date on which
they become `held`, and one that will never be either: its item has no tracker permalink, so its
occurrences cannot be read. `status` said `merged fixes: 4   held: 0`, which invites a reader to
expect four when the window closes. The honest number is three.

And a permanent skip wrote no verdict, so `due` kept selecting that item every six hours for ever —
against its own docstring, which says the window is applied where it is so a settled item *"stops
costing requests"*.

The distinction the whole item turns on: **two of the five skip paths can never resolve and three
are a bad afternoon.** Recording a verdict for one of the three would abandon a real answer.
"""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import Session
from test_recurrence import DEPLOYED, MERGED_AT, NOW, FakeForge, FakeTracker, _merged_fix, session

from hullwork import recurrence
from hullwork.config import get_settings
from hullwork.models import Item
from hullwork.recurrence import Verdict

__all__ = ["session"]  # re-exported fixture, imported for its own sake


def _another(session: Session, **kwargs: object) -> Item:
    """`_merged_fix` again, with a fingerprint that does not collide with the last one.

    It writes one fingerprint and the pair `(project, fingerprint)` is unique, so a test that wants
    two merged fixes has to rename as it goes.
    """
    made = _merged_fix(session, **kwargs)  # type: ignore[arg-type]
    made.fingerprint = f"fp-{900 + session.query(Item).count()}"
    session.commit()
    return made


def test_an_item_with_no_permalink_settles_instead_of_being_asked_for_ever(
    session: Session,
) -> None:
    """**The measured case**: item 9 on the live instance, merged 2026-07-29, undecidable since.

    Settling is what stops the cost — four forge requests a day, for ever, on a question whose
    answer cannot change.
    """
    item = _merged_fix(session, permalink=None)

    watched = recurrence.watch(session, FakeForge(), FakeTracker([]), now=NOW)

    assert [w.verdict for w in watched] == [Verdict.SKIPPED]
    session.refresh(item)
    assert item.recurrence_verdict == Verdict.SKIPPED.value
    assert "no tracker permalink" in (item.recurrence_note or "")
    assert recurrence.due(session, now=NOW + timedelta(days=1)) == [], (
        "a question whose answer cannot change must stop being asked"
    )


def test_a_pull_request_reference_with_no_number_settles_too(session: Session) -> None:
    """The second permanent path. The forge cannot be asked about a reference with no number in it,
    and no future pass will find one there."""
    item = _merged_fix(session, ref="a branch name, somehow")

    watched = recurrence.watch(session, FakeForge(), FakeTracker([]), now=NOW)

    assert [w.verdict for w in watched] == [Verdict.SKIPPED]
    session.refresh(item)
    assert item.recurrence_verdict == Verdict.SKIPPED.value
    assert recurrence.due(session, now=NOW + timedelta(days=1)) == []


@pytest.mark.parametrize(
    ("what", "forge", "tracker"),
    [
        ("the forge could not be asked", FakeForge(fails=True), FakeTracker([])),
        ("the tracker could not be read", FakeForge(), FakeTracker([], fails=True)),
        ("the pull request is still open", FakeForge(merged=False), FakeTracker([])),
    ],
)
def test_a_transient_skip_is_not_recorded_and_is_asked_again(
    session: Session, what: str, forge: FakeForge, tracker: FakeTracker
) -> None:
    """**Where the wrong choice loses a real answer.** All three of these clear by themselves: a
    forge comes back, a tracker comes back, a pull request gets merged. Writing `skipped` for any of
    them would abandon an item over one bad afternoon — permanently, since `due` then stops asking.
    """
    item = _merged_fix(session)

    watched = recurrence.watch(session, forge, tracker, now=NOW)

    assert [w.verdict for w in watched] == [Verdict.SKIPPED], what
    session.refresh(item)
    assert item.recurrence_verdict is None, f"{what}: recorded a verdict that must stay open"
    assert item.recurrence_note, "and it still says what happened this pass"
    assert [i.id for i in recurrence.due(session, now=NOW + timedelta(days=1))] == [item.id]


def test_the_count_status_was_missing(session: Session) -> None:
    """`merged: 4, held: 0` read as a promise of four. `undecided` is the number that makes it a
    statement about three."""
    decided = _another(session)
    _another(session, permalink=None)

    recurrence.watch(session, FakeForge(), FakeTracker([(DEPLOYED, MERGED_AT - timedelta(1))]),
                     now=NOW)

    merged, holding, recurred = recurrence.counted(session)
    assert (merged, holding, recurred) == (2, 0, 0), "the three M9 defined, unchanged"
    assert recurrence.undecided(session) == 1
    session.refresh(decided)
    assert decided.recurrence_verdict == Verdict.QUIET.value, "the other one is still in the window"

    # **And a skip that never reached a merge is not one of these.** The unparseable reference
    # settles before the forge is asked, so nothing is merged and there is no held-or-not question
    # to be undecided about. Counting it would inflate the number that exists to deflate another.
    never_merged = _another(session, ref="a branch name, somehow")
    recurrence.watch(session, FakeForge(), FakeTracker([]), now=NOW)

    session.refresh(never_merged)
    assert never_merged.recurrence_verdict == Verdict.SKIPPED.value
    assert recurrence.undecided(session) == 1, "still one: this skip was never a merged fix"


def test_status_names_them_and_json_carries_the_number(
    session: Session, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Printed beside the numbers it qualifies, because a reader who sees only `merged: 2` will
    subtract the wrong way."""
    from hullwork.cli import main as cli_main

    _another(session)
    _another(session, permalink=None)
    recurrence.watch(session, FakeForge(), FakeTracker([]), now=NOW)

    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "ingest")
    get_settings.cache_clear()
    try:
        text, machine = io.StringIO(), io.StringIO()
        cli_main(["status"], out=text)
        cli_main(["status", "--json"], out=machine)
        printed = text.getvalue()
        payload = json.loads(machine.getvalue())["merged_fixes"]
    finally:
        get_settings.cache_clear()

    assert "cannot be decided: 1" in printed
    assert payload["cannot_be_decided"] == 1
    assert payload["merged"] == 2


def test_nothing_undecidable_prints_nothing_extra(session: Session) -> None:
    """An instance whose merges can all be decided reads exactly as it did before this item: a
    number that is always zero teaches a reader to skip the line it is on."""
    from hullwork.cli import main as cli_main

    _merged_fix(session)
    recurrence.watch(session, FakeForge(), FakeTracker([]), now=NOW)
    assert recurrence.undecided(session) == 0

    out = io.StringIO()
    get_settings.cache_clear()
    try:
        cli_main(["status"], out=out)
    finally:
        get_settings.cache_clear()

    assert "merged fixes: 1" in out.getvalue()
    assert "cannot be decided" not in out.getvalue()


def test_the_window_still_closes_for_the_ones_that_can_be_decided(session: Session) -> None:
    """The guard on all of the above: settling the undecidable must not settle anything else.
    A `quiet` fix still becomes `held` when its fourteen days are up."""
    item = _merged_fix(session)

    recurrence.watch(session, FakeForge(), FakeTracker([]), now=NOW)
    session.refresh(item)
    assert item.recurrence_verdict == Verdict.QUIET.value

    later = MERGED_AT + timedelta(days=recurrence.WATCH_DAYS, hours=1)
    recurrence.watch(session, FakeForge(), FakeTracker([]), now=later)
    session.refresh(item)

    assert item.recurrence_verdict == Verdict.HELD.value
    assert datetime.now(UTC) is not None  # the clock is the test's, never the code's
