"""The front door: what needs you, then one line per project. Item 237.

It was every item on the instance in one table. With one project that is a list; with two it is two
projects' bugs interleaved and **whose** is the column a reader has to scan for — which is the
mixing the operator asked to stop:

> ¿No será mejor plantear esto mismo, pero a nivel de proyecto? Así no mezclamos cosas.

So the door answers one question and lists one thing, and the number against a project is **what is
waiting on a person** rather than how much exists. A count of items reads the same on a project that
is fine and one that is stuck, and the whole of a front door is *which of these wants me*.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from hullwork import page
from hullwork.config import Settings, get_settings
from hullwork.db import make_engine
from hullwork.models import Base, DependencyReport, Item, ItemState, Lane, Project

SIGNED_IN = page.Acting(csrf="c", offered=True)


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path}/door.db"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    session = sessionmaker(bind=engine)()
    for slug in ("shop", "warehouse"):
        session.add(
            Project(
                slug=slug, forge="forgejo", repo=f"acme/{slug}",
                webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
            )
        )
    session.commit()
    yield session
    get_settings.cache_clear()


def _an_item(db: Session, slug: str, state: ItemState) -> Item:
    project = db.query(Project).filter(Project.slug == slug).one()
    seen = db.query(Item).count()
    one = Item(
        project_id=project.id, fingerprint=f"f{seen}", title="KeyError: 'total'",
        state=state, lane=Lane.AMBER, last_seen=dt.datetime.now(dt.UTC),
    )
    db.add(one)
    db.commit()
    return one


def _report(db: Session, slug: str, **fields: object) -> None:
    project = db.query(Project).filter(Project.slug == slug).one()
    db.merge(
        DependencyReport(
            project_id=project.id, taken_at=dt.datetime.now(dt.UTC), **fields
        )
    )
    db.commit()


def _door(db: Session) -> str:
    return page.front_door(db, Settings(), acting=SIGNED_IN)


def _line_for(db: Session, slug: str) -> str:
    """The project's own row, and **not** its entry in the rail, which carries the same name and
    the same href one element up. Slicing on the name alone found the rail first.

    A row of the subject table since item 247, so the slice is `<tr>`-shaped; the rail's copy of the
    name is not inside one, which is what keeps this pointing at the right element.
    """
    shown = _door(db)
    marker = f'<a class="thing" href="projects/{slug}">{slug}</a>'
    assert marker in shown, f"{slug} is not listed on the door"
    at = shown.index(marker)
    return shown[shown.rindex("<tr", 0, at) : shown.index("</tr>", at)]


# --- what it says -------------------------------------------------------------------------------


def test_it_answers_whether_anything_needs_you(db: Session) -> None:
    """The one question a person opens this to ask, and the reason the door stopped being a table
    of every item on the instance."""
    shown = _door(db)

    assert "Nothing needs you" in shown


def test_every_project_is_one_line(db: Session) -> None:
    _an_item(db, "shop", ItemState.NEW)

    shown = _door(db)

    assert ">shop</a>" in shown
    assert ">warehouse</a>" in shown


def test_the_number_is_what_waits_on_a_person(db: Session) -> None:
    """**Not how much exists.** Four items nobody is blocked on and one waiting for a decision are
    different situations, and a count of items renders them identically."""
    _an_item(db, "shop", ItemState.NEW)
    _an_item(db, "shop", ItemState.READY)
    _an_item(db, "shop", ItemState.WAITING_APPROVAL)

    line = _line_for(db, "shop")

    # **Two states, two sentences** (item 247): this line summed `waiting-approval` and `human-only`
    # and called both *waiting on you*, two lines under a headline that counts only the first — and
    # which had just said *Nothing needs you*. A decision is owed on one; the other is work no agent
    # may attempt, and nothing is owed until somebody chooses to do it.
    assert "1 awaiting your decision" in line
    assert "3 item(s)" in line, "how much there is is still said, after what needs doing"


def test_a_project_with_nothing_waiting_says_so_quietly(db: Session) -> None:
    """Nothing rather than a zero: item 073's rule, which is that a signal on every row all the time
    is not a signal. The dash it used to print was that signal in punctuation — the row now says it
    by having nothing in the column where an action goes."""
    line = _line_for(db, "warehouse")

    assert "awaiting your decision" not in line
    assert 'class="do"></td>' in line


# --- and what it must not flatten ---------------------------------------------------------------


def test_the_three_dependency_states_survive_the_summary(db: Session) -> None:
    """**DR-0024's condition, one level up.** A project whose report failed must never read like one
    with nothing published against it — that is the failure this whole half must not have, and a
    one-line summary is exactly where it would be lost."""
    _report(db, "shop", asked=False, pinned=9, note="could not reach OSV", findings=[])
    _report(
        db, "warehouse", asked=True, pinned=50,
        findings=[{"package": "x", "version": "1", "source": "s", "advisories": []}],
    )

    could_not = _line_for(db, "shop")
    counted = _line_for(db, "warehouse")

    assert "could not ask OSV" in could_not
    assert "published against" not in could_not, "a failed request reads as a clean report"
    assert "1 package(s) with something published" in counted


def test_a_project_nobody_has_asked_about_is_a_fourth_state(db: Session) -> None:
    """*Not asked yet* is not *nothing published*, and the six-hour clock is what makes the first
    one temporary rather than a thing to go and do."""
    line = _line_for(db, "shop")

    assert "not asked about yet" in line


def test_a_project_that_is_not_watched_says_it_on_the_door(db: Session) -> None:
    """The state an operator forgets they left something in — and the one where every other number
    on the line is about to stop moving."""
    db.query(Project).filter(Project.slug == "shop").one().active = False
    db.commit()

    assert "not watched" in _line_for(db, "shop")


def test_no_project_lines_are_about_another_project(db: Session) -> None:
    """**The mixing this item removed.** Every number on a line is that project's; the door was one
    table of every item on the instance, with the project as a column to scan."""
    _an_item(db, "shop", ItemState.WAITING_APPROVAL)

    assert "awaiting your decision" in _line_for(db, "shop")
    assert "awaiting your decision" not in _line_for(db, "warehouse")
