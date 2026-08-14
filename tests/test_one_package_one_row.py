"""The dependency view is a table of packages. DR-0028, item 246.

The view it replaces was 11,330px — 12.6 screens — for twenty-six findings, because each fact was
a paragraph and the outcome of a package lived in a second list six screens below its advisory.
What is under test is the shape that fixed it, and the three faults that shape's prototype had:

* one row per **package**, carrying every version of it that is pinned;
* the state's sentence in the **heading**, said once, never once per row;
* **no action column** — the control renders in the row that has one and nowhere else.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from hullwork import page
from hullwork.config import get_settings
from hullwork.db import make_engine
from hullwork.models import Base, DependencyReport, Project, UpgradeVerdict

SIGNED_IN = page.Acting(csrf="c", offered=True)


def _finding(
    package: str, version: str, fixed: list[str], source: str = "uv.lock"
) -> dict[str, object]:
    return {
        "package": package, "version": version, "source": source,
        "advisories": [{"id": f"GHSA-{package}", "summary": "something", "fixed": fixed}],
    }


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path}/rows.db"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    session = sessionmaker(bind=engine)()
    session.add(Project(
        slug="shop", forge="forgejo", repo="acme/shop",
        webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
        manifest={"project": "shop", "autofix": {"open_upgrades": True}},
    ))
    session.commit()
    yield session
    get_settings.cache_clear()


def _report(db: Session, findings: list[dict[str, object]]) -> None:
    db.merge(DependencyReport(
        project_id=1, taken_at=dt.datetime.now(dt.UTC), asked=True,
        pinned=99, findings=findings,
    ))
    db.commit()


def _verdict(db: Session, package: str, was: str, to: str, outcome: str, **kept: object) -> None:
    db.add(UpgradeVerdict(project_id=1, package=package, was=was, to=to, outcome=outcome, **kept))
    db.commit()


def _view(db: Session, *, acting: page.Acting = SIGNED_IN) -> str:
    project = db.query(Project).one()
    return page.what_is_published_against_it(db, project, acting=acting)


class TestThePackageIsTheRow:
    def test_a_package_pinned_three_times_is_one_row(self, db: Session) -> None:
        """**The fault the first prototype had.** `brace-expansion` is pinned at three versions in
        one lock file, and rendering a row per pinned version made it three rows that share a name.
        """
        _report(db, [
            _finding("brace-expansion", "1.1.15", ["5.0.7"], "package-lock.json"),
            _finding("brace-expansion", "2.1.1", ["5.0.7"], "package-lock.json"),
            _finding("brace-expansion", "5.0.6", ["5.0.7"], "package-lock.json"),
        ])

        shown = _view(db)

        assert shown.count('<tr class="subject">') == 1
        assert "1.1.15" in shown and "2.1.1" in shown

    def test_the_report_handing_the_same_pair_twice_is_one_row(self, db: Session) -> None:
        """Measured on the operator's own instance: 26 findings, 25 distinct pairs, 21 packages —
        `brace-expansion 5.0.6` arrives twice with the same source. The page does not multiply
        it."""
        _report(db, [
            _finding("brace-expansion", "5.0.6", ["5.0.7"]),
            _finding("brace-expansion", "5.0.6", ["5.0.7"]),
        ])

        shown = _view(db)
        row = shown.split('<tr class="subject">')[1].split("</tr>")[0]

        assert shown.count('<tr class="subject">') == 1
        # **And the version is not printed twice inside it.** Counting rows alone let a defect that
        # appended the same pinned version per finding pass, which is what the operator's own report
        # hands over: 26 findings, 25 distinct pairs.
        assert row.count("5.0.6") == 1

    def test_neither_side_of_the_move_is_a_cartesian_product(self, db: Session) -> None:
        """**Found by rendering it**: pairing every pinned version with every published destination
        printed `5.0.6` thirty times and stretched the table to 7,208px."""
        _report(db, [
            _finding("thing", "1.0", ["2.0", "3.0", "4.0"]),
            _finding("thing", "1.1", ["2.0", "3.0", "4.0"]),
        ])

        row = _view(db).split('<tr class="subject">')[1].split("</tr>")[0]

        assert row.count("1.0") == 1
        assert row.count("2.0") == 1

    def test_a_package_with_nowhere_to_go_still_says_what_it_is(self, db: Session) -> None:
        """The one row a reader can do nothing about was also the one rendering an empty span where
        its version should be."""
        _report(db, [_finding("left-pad", "1.0.0", [])])

        row = _view(db).split('<tr class="subject">')[1].split("</tr>")[0]

        assert "left-pad" in row
        assert "1.0.0" in row


class TestTheStateThatMostNeedsAPerson:
    def test_a_package_takes_the_state_that_needs_a_person(self, db: Session) -> None:
        """One version ready to open and another stuck is a row you can act on. A row is a place to
        act, so the quietest version must not hide the loudest."""
        # **Two pinned versions in two states**, which is the only shape where the rule fires:
        # within one pinned version the order inside `_state_of` decides, and a test that used one
        # finding measured that instead — it passed with the rule inverted.
        _report(db, [
            _finding("thing", "1.0", ["2.0"]),
            _finding("thing", "9.0", ["9.9"]),
        ])
        _verdict(db, "thing", "1.0", "2.0", "clean", artefact={"files": {"a": "b"}})
        _verdict(db, "thing", "9.0", "9.9", "cannot-move")

        shown = _view(db)

        assert "Ready to open" in shown
        assert "The pin would not move" not in shown

    def test_an_outcome_this_page_does_not_know_is_still_shown(self, db: Session) -> None:
        _report(db, [_finding("thing", "1.0", ["2.0"])])
        _verdict(db, "thing", "1.0", "2.0", "cannot-parse")

        assert "it ended as cannot-parse" in _view(db)

    def test_a_refusal_is_the_one_sentence_a_row_still_says(self, db: Session) -> None:
        """Each refusal differs — *already open from an earlier run* and *the forge refused it* are
        not the same sentence — so this one cannot move to a heading."""
        _report(db, [_finding("thing", "1.0", ["2.0"])])
        _verdict(
            db, "thing", "1.0", "2.0", "clean",
            asked_to_open_at=dt.datetime.now(dt.UTC), open_note="the forge refused it",
        )

        shown = _view(db)

        assert "Asked for, and not opened" in shown
        assert "the forge refused it" in shown


class TestTheSentenceIsSaidOnce:
    def test_the_state_is_explained_in_the_heading_not_in_the_rows(self, db: Session) -> None:
        """**The fault the first prototype had**: seventeen rows reading *passed, but nothing kept
        to open it from*. A column repeating one sentence is a column that should not exist."""
        _report(db, [_finding(f"pkg{n}", "1.0", ["2.0"]) for n in range(4)])
        for n in range(4):
            _verdict(db, f"pkg{n}", "1.0", "2.0", "clean")

        shown = _view(db)

        assert shown.count("passed your suite before the change and after it") == 1
        assert shown.count('<tr class="subject">') == 4

    def test_the_band_names_every_package_it_covers(self, db: Session) -> None:
        """Saying it once must not mean saying it about nobody."""
        _report(db, [_finding(f"pkg{n}", "1.0", ["2.0"]) for n in range(3)])
        for n in range(3):
            _verdict(db, f"pkg{n}", "1.0", "2.0", "clean")

        shown = _view(db)

        for n in range(3):
            assert f"pkg{n}" in shown


class TestTheActionHasNoColumn:
    def test_the_control_renders_only_where_it_exists(self, db: Session) -> None:
        """It was empty in twenty-five rows of twenty-six, paying width to say nothing."""
        _report(db, [
            _finding("openable", "1.0", ["2.0"]),
            _finding("not-openable", "1.0", ["2.0"]),
        ])
        _verdict(db, "openable", "1.0", "2.0", "clean", artefact={"files": {"a": "b"}})
        _verdict(db, "not-openable", "1.0", "2.0", "cannot-move")

        shown = _view(db)

        assert shown.count('value="open-upgrade"') == 1

    def test_a_reader_who_cannot_act_is_offered_nothing(self, db: Session) -> None:
        _report(db, [_finding("thing", "1.0", ["2.0"])])
        _verdict(db, "thing", "1.0", "2.0", "clean", artefact={"files": {"a": "b"}})

        shown = _view(db, acting=page.READING)

        assert "open-upgrade" not in shown
        assert "Signing in is what offers the control" in shown

    def test_an_open_one_is_a_link_and_not_a_button(self, db: Session) -> None:
        _report(db, [_finding("thing", "1.0", ["2.0"])])
        _verdict(
            db, "thing", "1.0", "2.0", "clean",
            artefact={"files": {"a": "b"}}, opened_where="https://forge/pull/10",
        )

        shown = _view(db)

        assert 'href="https://forge/pull/10"' in shown
        assert "open-upgrade" not in shown


class TestWhatTheViewMustNotBecome:
    def test_there_is_no_second_list(self, db: Session) -> None:
        """**The fault DR-0028 exists for.** What OSV publishes about a package and what this
        instance did about it were two sections six screens apart."""
        _report(db, [_finding("thing", "1.0", ["2.0"])])
        _verdict(db, "thing", "1.0", "2.0", "clean")

        shown = _view(db)

        assert "What happened when it was tried" not in shown
        assert shown.count('<tr class="subject">') == 1

    def test_the_advisory_texts_stay_behind_the_disclosure(self, db: Session) -> None:
        _report(db, [_finding("thing", "1.0", ["2.0"])])

        row = _view(db).split('<tr class="subject">')[1].split("</tr>")[0]

        assert "something" not in row.split("<details")[0]
        assert "something" in row
