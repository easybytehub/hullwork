"""What the page may say about an upgrade this instance tried. DR-0026, item 233, DR-0028.

The dependency section could name 25 upgrades and say nothing about any of them, closing with *only
the half of this product that holds a Docker socket can answer it*. It answers it now, one per idle
turn, and this file is what the page is allowed to claim about the answer.

**Rewritten for DR-0028 and deliberately not rewritten much.** The claims are the same and they are
what these tests are for; what changed is where the page puts them. A verdict is still about a pair
of versions — `48.0.1 → 49.0.0` and `48.0.1 → 50.0.0` are still two answers — but the package is
now one row carrying both, so a test that asserted two lines asserts two destinations in one. And a
verdict about a version no longer pinned is still not shown at all: nothing marks it stale on
screen, so it reads as current, which is worse than the silence it replaces.

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
from hullwork.models import Base, DependencyReport, Project, UpgradeVerdict

SIGNED_IN = page.Acting(csrf="c", offered=True)

FINDING = {
    "package": "cryptography",
    "version": "48.0.1",
    "source": "requirements.txt",
    "advisories": [
        {"id": "GHSA-g6cj", "summary": "one", "fixed": ["49.0.0"]},
        {"id": "GHSA-jwv3", "summary": "two", "fixed": ["49.0.0", "50.0.0"]},
    ],
}


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path}/tried.db"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    session = sessionmaker(bind=engine)()
    project = Project(
        slug="shop", forge="forgejo", repo="acme/shop",
        webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
    )
    session.add(project)
    session.flush()
    session.merge(
        DependencyReport(
            project_id=project.id, taken_at=dt.datetime.now(dt.UTC), asked=True,
            pinned=50, findings=[FINDING],
        )
    )
    session.commit()
    yield session
    get_settings.cache_clear()


def _verdict(db: Session, outcome: str, *, was: str = "48.0.1", to: str = "49.0.0") -> None:
    project = db.query(Project).one()
    db.merge(
        UpgradeVerdict(
            project_id=project.id, package="cryptography", was=was, to=to,
            outcome=outcome, detail="18 passed", tried_at=dt.datetime.now(dt.UTC),
        )
    )
    db.commit()


def _view(db: Session) -> str:
    return page.dependencies(db, Settings(), "shop", acting=SIGNED_IN) or ""


# --- what it says happened -----------------------------------------------------------------


def test_a_clean_upgrade_says_what_clean_means(db: Session) -> None:
    """**Not *this is safe*.** The suite passed before and after, which is the only thing that was
    measured, and the difference between those two sentences is the entire product."""
    _verdict(db, "clean")

    shown = _view(db)

    assert "cryptography" in shown and "48.0.1" in shown and "49.0.0" in shown
    assert "passed your suite before the change and after it" in shown
    assert "never opens one by itself" in shown
    assert "Not tried yet" not in shown, "it says both at once"


def test_a_breaking_upgrade_is_the_finding(db: Session) -> None:
    _verdict(db, "breaks")

    shown = _view(db)

    assert "Breaks your suite" in shown
    assert "your tests stopped passing" in shown
    assert 'class="dot refused"' in shown


def test_each_published_version_is_its_own_answer(db: Session) -> None:
    """OSV publishes two fixed versions when an advisory was fixed on two release branches, and
    they are two questions with two answers.

    **One row now carries both** (DR-0028): the package is the subject, so the two destinations are
    in it rather than on two lines that share a name. What must not happen is either one vanishing.
    """
    _verdict(db, "clean", to="49.0.0")
    _verdict(db, "breaks", to="50.0.0")

    shown = _view(db)

    assert shown.count("<tr class=\"subject\">") == 1, "one package is one row"
    assert "49.0.0" in shown
    assert "50.0.0" in shown


def test_nothing_tried_yet_says_who_will_try_it(db: Session) -> None:
    """The old sentence handed the question back to the reader — *only the half that holds a Docker
    socket can answer it* — which is true and useless to somebody reading a page."""
    shown = _view(db)

    assert "What happened when it was tried" not in shown, "no second list (DR-0028)"
    assert "one per idle turn" in shown
    assert "Not tried yet" in shown


# --- and what it must never claim ------------------------------------------------------------


def test_a_verdict_about_a_version_no_longer_pinned_is_not_shown(db: Session) -> None:
    """**The stale one.** A row saying `47.0.0 → 48.0.0 is clean` about a version this repository
    stopped pinning wears no mark of its age, so it reads as a current statement about a current
    pin. Dropping it is the only honest render."""
    _verdict(db, "clean", was="47.0.0", to="48.0.0")

    shown = _view(db)

    assert "47.0.0" not in shown
    assert "What happened when it was tried" not in shown


def test_a_build_that_refused_is_not_painted_as_a_broken_suite(db: Session) -> None:
    """`will-not-install` is the build failing. Rendering it red would be this instance telling
    somebody their tests fail on an upgrade whose tests never ran."""
    _verdict(db, "will-not-install")

    shown = _view(db)

    assert "the build refused it, so your suite never ran" in shown
    assert "your suite fails on it" not in shown


def test_a_suite_already_failing_claims_nothing_either_way(db: Session) -> None:
    """The one state where the honest answer is *I could not tell you* — and it needs a person, not
    a colour that reads as bad news about the upgrade."""
    _verdict(db, "already-red")

    shown = _view(db)

    assert "own test suite was already failing" in shown
    assert "your suite fails on it" not in shown


def test_a_red_baseline_is_said_once_rather_than_once_per_pair(db: Session) -> None:
    """**Item 234, as the page renders it.** `simplecheck` produced 50 identical rows in an hour:
    the fact is about the project, not about any of the upgrades, and repeating it per pair buries
    whatever else the list has to say."""
    for to in ("49.0.0", "50.0.0"):
        _verdict(db, "already-red", to=to)

    shown = _view(db)

    assert shown.count("own test suite was already failing") == 1, "once, in the band's heading"
    assert "That covers 2 upgrade(s)" in shown
    assert "cryptography" in shown, "the packages it covers are not named"


def test_a_red_baseline_does_not_bury_a_real_verdict(db: Session) -> None:
    """The one that matters is the one that is not `already-red`. A project part-way through a
    recovery has both, and the summary must not swallow the row."""
    _verdict(db, "already-red", to="49.0.0")
    _verdict(db, "breaks", to="50.0.0")

    shown = _view(db)

    # **The real verdict wins the row** (DR-0028): a package takes the state that most needs a
    # person, so one pair being unclaimable never hides the one that broke.
    assert "Breaks your suite" in shown
    assert "50.0.0" in shown
    assert "Nothing could be claimed" not in shown, "the red pair is not this package's state"


def test_an_outcome_this_page_does_not_know_is_shown_rather_than_swallowed(db: Session) -> None:
    """A verdict `bump` adds tomorrow must not vanish from the page because this table was not
    updated: an unknown state is still a state, and rendering nothing would report *not tried*."""
    _verdict(db, "cannot-parse")

    shown = _view(db)

    assert "it ended as cannot-parse" in shown
