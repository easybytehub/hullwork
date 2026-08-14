"""The daily views are tables of subjects too. DR-0028, item 247.

Errors was already a table and still broke the decision in two places: `state` printed itself
twenty-five times down a column, and the order was the clock's rather than *who is blocked* — which
put the one item waiting for a person at the top by luck.

The door said two things about one number in consecutive lines: **Nothing needs you** in the
headline, and *2 waiting on you* in the project row underneath. Both were right; one name for them
was not.

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
    session.add(Project(
        slug="shop", forge="forgejo", repo="acme/shop",
        webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
    ))
    session.commit()
    yield session
    get_settings.cache_clear()


def _item(db: Session, state: ItemState, title: str = "boom", lane: Lane = Lane.GREEN) -> Item:
    row = Item(
        project_id=1, fingerprint=f"{title}-{state.value}", state=state, lane=lane,
        title=title, last_seen=dt.datetime.now(dt.UTC), first_seen=dt.datetime.now(dt.UTC),
    )
    db.add(row)
    db.commit()
    return row


class TestErrorsIsGroupedByWhoIsBlocked:
    def test_the_state_is_the_heading_and_not_a_column(self, db: Session) -> None:
        """Twenty-five rows reading `done` is the column DR-0028 is named after."""
        for n in range(3):
            _item(db, ItemState.DONE, title=f"closed {n}")

        shown = page.items(db, acting=SIGNED_IN)

        assert "Closed" in shown
        assert shown.count("merged, rejected, or answered") == 1
        assert "<th>state</th>" not in shown

    def test_what_the_reader_owns_comes_first(self, db: Session) -> None:
        """**The order was the clock's.** `last_seen desc` put the one item waiting for a person at
        the top by luck; at two hundred items it is wherever the clock left it."""
        _item(db, ItemState.WAITING_APPROVAL, title="decide me")
        for n in range(3):
            _item(db, ItemState.DONE, title=f"closed {n}")

        shown = page.items(db, acting=SIGNED_IN)

        assert shown.index("Waiting on you") < shown.index("Closed")

    def test_closed_is_last_whatever_else_is_there(self, db: Session) -> None:
        _item(db, ItemState.DONE, title="closed")
        _item(db, ItemState.READY, title="queued")

        shown = page.items(db, acting=SIGNED_IN)

        assert shown.index("Queued") < shown.index("Closed")

    def test_the_grouping_is_the_one_the_front_page_uses(self) -> None:
        """**Not a second vocabulary.** Two lists that group the same states under different names
        drift the first time either changes, which is what DR-0027 spent an item undoing."""
        assert {key for _, key, _, _, _ in page._COLUMNS} == set(page._WHO_IS_BLOCKED)

    def test_an_empty_group_is_not_rendered(self, db: Session) -> None:
        _item(db, ItemState.DONE, title="closed")

        shown = page.items(db, acting=SIGNED_IN)

        assert "Waiting on you" not in shown

    def test_the_sentence_above_the_list_describes_the_order_it_has(self, db: Session) -> None:
        """It said *most recently seen first*, which stopped being true the moment it grouped."""
        _item(db, ItemState.DONE, title="closed")

        shown = page.items(db, acting=SIGNED_IN)

        assert "Grouped by who is blocked" in shown
        assert "Most recently seen first" not in shown

    def test_an_item_that_can_never_be_attempted_says_so_where_it_fits(self, db: Session) -> None:
        """`never` is a fact about the item. In the context cell it was clipped to `N…`, and a
        truncated warning reads as a rendering fault rather than as a state."""
        db.query(Project).one().active = False
        db.commit()
        _item(db, ItemState.READY, title="unreachable")

        row = page.items(db, acting=SIGNED_IN).split('<tr class="subject">')[1]

        assert "never" in row.split('<td class="at">')[0]


class TestTheDoorSaysOneThingAboutOneNumber:
    def test_a_decision_and_work_only_a_person_can_do_are_two_sentences(
        self, db: Session
    ) -> None:
        """**The contradiction this item found.** The headline counts `waiting-approval` and said
        *Nothing needs you*; the project row summed `human-only` into the same words two lines
        below. Both numbers were right; one name for them was not."""
        _item(db, ItemState.HUMAN_ONLY, title="only a person")

        shown = page.front_door(db, Settings(), acting=SIGNED_IN)

        assert "Nothing needs you" in shown
        assert "1 only a person can do" in shown
        assert "waiting on you" not in shown

    def test_a_decision_owed_is_counted_as_one(self, db: Session) -> None:
        _item(db, ItemState.WAITING_APPROVAL, title="decide me")

        shown = page.front_door(db, Settings(), acting=SIGNED_IN)

        assert "1 awaiting your decision" in shown
        assert "Nothing needs you" not in shown

    def test_a_project_is_a_row_of_the_same_table(self, db: Session) -> None:
        shown = page.front_door(db, Settings(), acting=SIGNED_IN)

        assert '<table class="subjects narrow">' in shown
        assert '<a class="thing" href="projects/shop">shop</a>' in shown

    def test_the_paragraph_explaining_the_list_is_gone(self, db: Session) -> None:
        """It was re-read every day by somebody who understood it the first time."""
        shown = page.front_door(db, Settings(), acting=SIGNED_IN)

        assert "the number is what is waiting on a person rather than how much" not in shown


class TestTheRailCountsWhatItsViewCounts:
    def test_a_package_pinned_twice_is_one_of_each(self, db: Session) -> None:
        """`Dependencies 25` beside a view saying `20 packages`: two true numbers of two different
        things, in one eye-line."""
        db.merge(DependencyReport(
            project_id=1, taken_at=dt.datetime.now(dt.UTC), asked=True, pinned=9,
            findings=[
                {"package": "thing", "version": "1.0", "source": "a", "advisories": []},
                {"package": "thing", "version": "2.0", "source": "a", "advisories": []},
                {"package": "other", "version": "1.0", "source": "a", "advisories": []},
            ],
        ))
        db.commit()

        assert page.how_much_of_each(db, 1).dependencies == 2

    def test_a_report_that_could_not_ask_counts_nothing(self, db: Session) -> None:
        """**Carrying findings, which is the only shape where the guard fires.** With an empty list
        the count is zero either way, and the first version of this test passed with `asked`
        deleted from the condition — an advisory list that silently reads as current when the
        question never reached OSV is the failure DR-0024 exists to prevent."""
        db.merge(DependencyReport(
            project_id=1, taken_at=dt.datetime.now(dt.UTC), asked=False, pinned=9,
            findings=[{"package": "stale", "version": "1.0", "source": "a", "advisories": []}],
        ))
        db.commit()

        assert page.how_much_of_each(db, 1).dependencies == 0


class TestWhatTheDeployedPageSaid:
    """Two defects visible on the door the moment it was deployed, and neither was on the list."""

    def test_a_phrase_that_is_not_a_duration_does_not_get_ago(self) -> None:
        """`_ago` answers `just now` under a minute, and every caller appending *ago* to it
        rendered **just now ago** — on the door, on an idle instance, which is most of the time."""
        assert page._since(None) == "not recorded"
        assert page._since(dt.datetime.now(dt.UTC)) == "just now"
        assert page._since(dt.datetime.now(dt.UTC) - dt.timedelta(hours=3)) == "3h ago"

    def test_no_caller_appends_ago_to_it_by_hand(self) -> None:
        """**Asserted on the source**, because the four that did were found by reading the rendered
        page rather than by a test — and a fifth would be written the same way."""
        import inspect

        assert ")} ago" not in inspect.getsource(page), "a caller composes the phrase by hand"

    def test_the_project_line_counts_packages_like_its_view(self, db: Session) -> None:
        """`25 published against what it pins` beside a view that says `20 packages`: the rail's
        fault, in the door's own words."""
        db.merge(DependencyReport(
            project_id=1, taken_at=dt.datetime.now(dt.UTC), asked=True, pinned=9,
            findings=[
                {"package": "thing", "version": "1.0", "source": "a", "advisories": []},
                {"package": "thing", "version": "2.0", "source": "a", "advisories": []},
            ],
        ))
        db.commit()

        shown = page.front_door(db, Settings(), acting=SIGNED_IN)

        assert "1 package(s) with something published" in shown
