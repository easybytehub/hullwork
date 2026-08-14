"""A project whose own suite is already failing is asked once, not fifty times. Item 234.

Item 233 shipped at 07:40 and the dispatcher did exactly what it was built to do: `simplecheck`'s
suite cannot reach a database inside the sandbox, so it is red before anything is touched, and every
pair in the queue got its own clone, image build and suite run to print *your suite was already
failing* again.

`already-red` is the honest verdict — no claim can be made either way. **What is wrong is what it
costs to say it fifty times.** The baseline is a property of the project at a commit, not of the
upgrade, so measuring it once answers every question in that queue at the same time.

The way back in is a new dependency report, taken on this instance's own clock every six hours: a
repository that fixes its suite is picked up again without anybody typing anything.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from hullwork import bump, upgrades
from hullwork.config import Settings, get_settings
from hullwork.db import make_engine
from hullwork.models import Base, DependencyReport, Project, UpgradeVerdict

MANIFEST = {
    "project": "shop",
    "git": {"provider": "forgejo", "repo": "acme/shop"},
    "errors": {"provider": "glitchtip"},
    "runtime": {
        "base": "python:3.12",
        "install": "pip install -r requirements.txt",
        "dependencies": ["requirements.txt"],
    },
    "tests": "pytest",
}

FINDING = {
    "package": "cryptography",
    "version": "48.0.1",
    "source": "requirements.txt",
    "advisories": [{"id": "GHSA-g6cj", "summary": "one", "fixed": ["49.0.0", "50.0.0"]}],
}

AN_HOUR_AGO = dt.datetime.now(dt.UTC) - dt.timedelta(hours=1)


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path}/baseline.db"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "read-only")
    get_settings.cache_clear()
    session = sessionmaker(bind=engine)()
    project = Project(
        slug="shop", forge="forgejo", repo="acme/shop",
        webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
        manifest=MANIFEST,
    )
    session.add(project)
    session.flush()
    # **Taken an hour ago**, so a verdict can be placed on either side of it. A report taken *now*
    # could only ever be older than the verdict, which is one of the two states under test.
    session.merge(
        DependencyReport(
            project_id=project.id, taken_at=AN_HOUR_AGO, asked=True, pinned=50, findings=[FINDING],
        )
    )
    session.commit()
    yield session
    get_settings.cache_clear()


class _Tried:
    """A `verify_one` that answers as it is told and remembers being asked."""

    def __init__(self, verdict: bump.Verdict = bump.Verdict.CLEAN) -> None:
        self.verdict = verdict
        self.asked: list[str] = []

    def __call__(
        self,
        checkout: Path,
        paths: Sequence[str],
        read: object,
        manifest: object,
        dep: object,
        versions: list[str],
        out: object,
    ) -> bump.Report:
        self.asked.append(versions[0])
        name, was = dep.name, dep.version  # type: ignore[attr-defined]
        return bump.Report(
            package=name,
            was=was,
            answers=(
                bump.Answer(
                    verdict=self.verdict, package=name, was=was, to=versions[0], detail="1 failed"
                ),
            ),
        )


class _Cloned:
    def __call__(self, settings: Settings, project: Project, into: Path) -> Path:
        (into / "requirements.txt").write_text("cryptography==48.0.1\n")
        return into


def _verdict(db: Session, outcome: str, *, when: dt.datetime, to: str = "49.0.0") -> None:
    project = db.query(Project).one()
    db.merge(
        UpgradeVerdict(
            project_id=project.id, package="cryptography", was="48.0.1", to=to,
            outcome=outcome, detail="", tried_at=when,
        )
    )
    db.commit()


def _turn(db: Session, tried: _Tried, monkeypatch: pytest.MonkeyPatch) -> str | None:
    monkeypatch.setattr(upgrades, "verify_one", tried)
    return upgrades.verify_next(db, get_settings(), clone=_Cloned())


# --- when it stops -----------------------------------------------------------------------------


def test_a_red_baseline_stops_the_queue_for_that_project(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**The whole item.** 25 findings and ~50 published versions between them, each costing a
    clone, an image build and a suite run, to print the same sentence fifty times."""
    _verdict(db, "already-red", when=dt.datetime.now(dt.UTC))
    tried = _Tried()

    said = _turn(db, tried, monkeypatch)

    assert said is None
    assert tried.asked == [], "it built an image to ask a question already answered"


def test_a_report_taken_since_puts_it_back_in_the_queue(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**The way back in, and it needs nobody to type anything.** A repository that fixes its suite
    is picked up on this instance's own six-hourly clock — a stop with no way out of it would be a
    project silently dropped for ever."""
    _verdict(db, "already-red", when=AN_HOUR_AGO - dt.timedelta(minutes=5))
    tried = _Tried()

    said = _turn(db, tried, monkeypatch)

    assert said is not None
    assert tried.asked == ["50.0.0"]


def test_a_green_baseline_is_not_stopped_by_a_broken_upgrade(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`breaks` is a fact about one upgrade and says nothing about the next one. Stopping on it
    would turn the most valuable verdict this product produces into a reason to stop working."""
    _verdict(db, "breaks", when=dt.datetime.now(dt.UTC))
    tried = _Tried()

    said = _turn(db, tried, monkeypatch)

    assert said is not None
    assert tried.asked == ["50.0.0"]


def test_a_baseline_that_came_back_green_is_not_held_by_the_old_red(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the most recent verdict is the baseline. An older `already-red` still in the table is
    history, and reading the whole table for one would stop a project that had recovered."""
    _verdict(db, "already-red", when=AN_HOUR_AGO, to="49.0.0")
    _verdict(db, "clean", when=dt.datetime.now(dt.UTC), to="50.0.0")
    tried = _Tried()

    monkeypatch.setattr(upgrades, "verify_one", tried)
    db.merge(
        DependencyReport(
            project_id=db.query(Project).one().id, taken_at=AN_HOUR_AGO, asked=True,
            pinned=50,
            findings=[
                {**FINDING, "advisories": [{"id": "x", "summary": "s", "fixed": ["51.0.0"]}]}
            ],
        )
    )
    db.commit()

    assert upgrades.verify_next(db, get_settings(), clone=_Cloned()) is not None
    assert tried.asked == ["51.0.0"]
