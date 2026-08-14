"""Somebody has to ask the forge. Item 253.

The operator, having merged one:

> no es reactivo, no? porque he cerrado el PR y sigue ahí: **Already open — a draft pull request is
> waiting for a person**

Correct, and the measurement on the live instance said so plainly: two rows reading *already open*,
both `merged=True` at the forge. `opened_where` was written the moment the dispatcher opened the
pull request and **never read back**.

The error side has had this watcher since item 121, and item 138 split the two facts it hides:
*not merged* means both *nobody has looked at it* and *a person said no*, and an item stayed
`pr-open` for ever in both cases. This is that split on `UpgradeVerdict`.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from hullwork import page, upgrades
from hullwork.config import Settings, get_settings
from hullwork.db import make_engine
from hullwork.forge import ForgeError, MergeState
from hullwork.models import Base, DependencyReport, Project, UpgradeVerdict

SIGNED_IN = page.Acting(csrf="c", offered=True)
WHERE = "https://forge.example/acme/shop/pulls/11"


@dataclass
class FakeForge:
    """A forge that answers about a pull request and records what it was asked."""

    answer: MergeState = field(default_factory=lambda: MergeState(merged=False, state="open"))
    asked: list[tuple[str, int]] = field(default_factory=list)
    refuse: bool = False

    def merge_state(self, repo: str, number: int) -> MergeState:
        if self.refuse:
            raise ForgeError("the forge said no")
        self.asked.append((repo, number))
        return self.answer


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path}/watch.db"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    session = sessionmaker(bind=engine)()
    session.add(Project(
        slug="shop", forge="forgejo", repo="acme/shop",
        webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
        manifest={"version": 1, "autofix": {"open_upgrades": True}},
    ))
    session.commit()
    yield session
    get_settings.cache_clear()


def _opened(db: Session, **fields: object) -> UpgradeVerdict:
    row = UpgradeVerdict(
        project_id=1, package="nanoid", was="3.3.12", to="3.3.18", outcome="clean",
        tried_at=dt.datetime.now(dt.UTC), **{"opened_where": WHERE, **fields},
    )
    db.add(row)
    db.commit()
    return row


def _showing(db: Session) -> str:
    """The dependency view, with one advisory published against the pinned version."""
    db.merge(DependencyReport(
        project_id=1, taken_at=dt.datetime.now(dt.UTC), asked=True, pinned=9,
        findings=[{
            "package": "nanoid", "version": "3.3.12", "source": "frontend/package-lock.json",
            "advisories": [{"id": "GHSA-x", "summary": "s", "fixed": ["3.3.18"]}],
        }],
    ))
    db.commit()
    shown = page.dependencies(db, Settings(), "shop", acting=SIGNED_IN)
    assert shown is not None
    return shown


class TestTheForgeIsAsked:
    def test_a_merged_pull_request_stops_asking_for_a_review(self, db: Session) -> None:
        """**The operator's own report.** Merged on the forge, and the page kept saying *a draft
        pull request is waiting for a person* — because nothing ever asked."""
        _opened(db)
        forge = FakeForge(MergeState(merged=True, state="merged"))

        said = upgrades.watch_opened(db, forge)

        assert said is not None and "merged" in said
        db.expire_all()
        assert db.query(UpgradeVerdict).one().opened_state == "merged"
        assert "Already open" not in _showing(db)
        assert "Merged" in _showing(db)

    def test_one_closed_without_merging_says_so_and_keeps_the_reason(self, db: Session) -> None:
        """**The worse half, and the one nobody has hit yet.** A closed pull request changes
        nothing on its own: the lock file is untouched and the advisory is still published, so the
        row would have gone on displaying somebody's explicit *no* as work they still owed."""
        _opened(db)
        forge = FakeForge(MergeState(merged=False, state="closed", labels=("wontfix",)))

        upgrades.watch_opened(db, forge)

        db.expire_all()
        row = db.query(UpgradeVerdict).one()
        assert row.opened_state == "closed"
        assert row.open_note is not None and "closed the pull request without merging" in (
            row.open_note
        )
        shown = _showing(db)
        assert "You closed these" in shown
        assert "Already open" not in shown

    def test_a_reviewer_who_gave_no_reason_is_not_given_one(self, db: Session) -> None:
        """`rejection_reason` answers `None` for *not given*, which is a fact about the review and
        not a blank to fill in. Item 110's rule, which this repository keeps rediscovering."""
        _opened(db)

        upgrades.watch_opened(db, FakeForge(MergeState(merged=False, state="closed", labels=())))

        db.expire_all()
        assert "gave no reason" in str(db.query(UpgradeVerdict).one().open_note)

    def test_an_open_one_is_left_alone(self, db: Session) -> None:
        _opened(db)

        assert upgrades.watch_opened(db, FakeForge()) is None

        db.expire_all()
        assert db.query(UpgradeVerdict).one().opened_state == "open"
        assert "Already open" in _showing(db)

    def test_asking_records_when_it_asked(self, db: Session) -> None:
        """**Found by reintroduction, and by nothing else.** Deleting the line that stamps
        `open_checked_at` broke no test: the two below that watch the clock set it in their own
        fixtures, so they proved the filter reads it and never that anything writes it.

        Without the stamp a pull request that stays open is asked about on **every turn** of the
        loop, which is every few seconds on an idle instance — the exact cost item 121 removed from
        the other watcher, reintroduced silently here.
        """
        _opened(db)

        upgrades.watch_opened(db, FakeForge())

        db.expire_all()
        assert db.query(UpgradeVerdict).one().open_checked_at is not None


class TestItStopsCosting:
    def test_a_settled_one_is_never_asked_about_again(self, db: Session) -> None:
        """Merged is merged, and a person who closed one has answered. This is where the watch
        stops costing requests — item 121's lesson, one noun along."""
        _opened(db, opened_state="merged", open_checked_at=dt.datetime(2020, 1, 1, tzinfo=dt.UTC))
        forge = FakeForge()

        assert upgrades.watch_opened(db, forge) is None

        assert forge.asked == []

    def test_one_asked_about_a_minute_ago_waits_for_the_report_s_clock(self, db: Session) -> None:
        """A pull request open for a week must cost one request per report cycle, not one per turn
        — the loop turns every few seconds when there is nothing else to do."""
        _opened(db, opened_state="open", open_checked_at=dt.datetime.now(dt.UTC))
        forge = FakeForge()

        assert upgrades.watch_opened(db, forge) is None

        assert forge.asked == []

    def test_one_asked_about_seven_hours_ago_is_asked_again(self, db: Session) -> None:
        _opened(db, opened_state="open", open_checked_at=(
            dt.datetime.now(dt.UTC) - dt.timedelta(seconds=upgrades.RECHECK_SECONDS + 60)
        ))
        forge = FakeForge(MergeState(merged=True, state="merged"))

        assert upgrades.watch_opened(db, forge) is not None

        assert forge.asked == [("acme/shop", 11)]

    def test_a_reference_with_no_number_is_recorded_rather_than_retried(self, db: Session) -> None:
        """Permanent: a stored reference the forge cannot be asked about cannot be asked about
        however many times this runs. `recurrence._settled`'s reasoning."""
        _opened(db, opened_where="https://forge.example/acme/shop/pulls/")
        forge = FakeForge()

        assert upgrades.watch_opened(db, forge) is None

        db.expire_all()
        assert db.query(UpgradeVerdict).one().opened_state == "unreadable"
        assert forge.asked == []


class TestTheFilterSeesTheRowsThatExist:
    def test_a_row_never_asked_about_is_selected(self, db: Session) -> None:
        """**`NULL NOT IN (…)` is `NULL`, and `NULL` is not true.**

        The first version filtered with `notin_(("merged", "closed"))` alone, which is correct for
        every row that has a state and excludes every row that does not — that is *every row that
        exists* the day this ships, and they are the only ones with anything to learn. The watcher
        did nothing at all, and a watcher that does nothing reports exactly what a watcher that
        found nothing reports.
        """
        _opened(db)  # opened_state is NULL, as it is for every row written before item 253
        forge = FakeForge(MergeState(merged=True, state="merged"))

        upgrades.watch_opened(db, forge)

        assert forge.asked == [("acme/shop", 11)], "the row that has never been asked about"


class TestAForgeThatWillNotAnswer:
    def test_it_changes_nothing(self, db: Session) -> None:
        """**A verdict written for one bad afternoon is worse than a stale row.** The same rule
        `open_requested` follows when the forge is down for a minute."""
        _opened(db)

        assert upgrades.watch_opened(db, FakeForge(refuse=True)) is None

        db.expire_all()
        row = db.query(UpgradeVerdict).one()
        assert row.opened_state is None
        assert row.open_checked_at is None, "an unanswered question is not a question asked"

    def test_no_forge_at_all_is_not_an_error(self, db: Session) -> None:
        """The ordinary state of a process with no forge configured, and of the receiver."""
        _opened(db)

        assert upgrades.watch_opened(db, None) is None


class TestTheRowCarriesItsEvidence:
    def test_a_merged_row_still_links_to_the_pull_request(self, db: Session) -> None:
        """The link is the evidence of what happened, not an invitation to review it."""
        _opened(db, opened_state="merged")

        assert "#11 ↗" in _showing(db)

    def test_a_closed_row_still_links_to_it(self, db: Session) -> None:
        _opened(db, opened_state="closed", open_note="a person closed it")

        shown = _showing(db)

        assert "#11 ↗" in shown
        assert "a person closed it" in shown

    def test_it_is_not_offered_to_be_opened_again(self, db: Session) -> None:
        """**A person looked at it and said no.** Offering the button again is asking them to say
        it twice — item 138 made the same answer terminal for an item."""
        _opened(db, opened_state="closed", open_note="a person closed it")

        assert "open-upgrade" not in _showing(db)
