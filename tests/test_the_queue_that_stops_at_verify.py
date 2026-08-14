"""The dispatcher verifies an upgrade and does not open one. DR-0026, item 233.

Since DR-0024 the instance knows there are 25 upgrades waiting on a real project. Nothing acted on
that: `refit.run` stages into an ephemeral session, and neither `work.py` nor `main.py` named it.

DR-0026 draws the line at `verify` — apply the version OSV published, build the image, run **the
project's own suite**, keep what happened — because the failure modes are not symmetrical. A
verification that is wrong costs a wrong sentence on a page; a pull request that is wrong costs
somebody's review time, in their repository, under this instance's name.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import datetime as dt
import subprocess
from collections.abc import Iterator, Sequence
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy.orm import Session, sessionmaker

from hullwork import bump, cli, upgrades, work
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
    "advisories": [
        {"id": "GHSA-g6cj", "summary": "one", "fixed": ["49.0.0"]},
        {"id": "GHSA-jwv3", "summary": "two", "fixed": ["49.0.0", "50.0.0"]},
    ],
}


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path}/queue.db"
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
    session.merge(
        DependencyReport(
            project_id=project.id, taken_at=dt.datetime.now(dt.UTC), asked=True,
            pinned=50, findings=[FINDING],
        )
    )
    session.commit()
    yield session
    get_settings.cache_clear()


class _Tried:
    """What `verify_one` was asked, and what it is told to answer."""

    def __init__(self, verdict: bump.Verdict | None = bump.Verdict.CLEAN) -> None:
        self.verdict = verdict
        self.asked: list[tuple[str, str, tuple[str, ...]]] = []

    def __call__(
        self,
        checkout: Path,
        paths: Sequence[str],
        read: object,
        manifest: object,
        dep: object,
        versions: list[str],
        out: object,
    ) -> bump.Report | None:
        self.asked.append((dep.name, dep.version, tuple(versions)))  # type: ignore[attr-defined]
        if self.verdict is None:
            return None
        return bump.Report(
            package=dep.name,  # type: ignore[attr-defined]
            was=dep.version,  # type: ignore[attr-defined]
            answers=(
                bump.Answer(
                    verdict=self.verdict,
                    package=dep.name,  # type: ignore[attr-defined]
                    was=dep.version,  # type: ignore[attr-defined]
                    to=versions[0],
                    detail="18 passed",
                ),
            ),
        )


class _Cloned:
    """A clone that is a directory with the file the finding names, and what it was handed."""

    def __init__(self) -> None:
        self.seen: list[str] = []

    def __call__(self, settings: Settings, project: Project, into: Path) -> Path:
        token = settings.forge_token
        self.seen.append(token.get_secret_value() if token else "")
        (into / "requirements.txt").write_text("cryptography==48.0.1\n")
        return into


# --- what it tries ---------------------------------------------------------------------------


def test_it_tries_one_and_keeps_what_happened(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**The item.** The report says which upgrades exist; this is the first thing that does
    anything with one."""
    tried = _Tried()
    monkeypatch.setattr(upgrades, "verify_one", tried)

    said = upgrades.verify_next(db, get_settings(), clone=_Cloned())

    assert said is not None and "cryptography 48.0.1 → 49.0.0 is clean" in said
    stored = db.query(UpgradeVerdict).one()
    assert (stored.package, stored.was, stored.to) == ("cryptography", "48.0.1", "49.0.0")
    assert stored.outcome == "clean"
    assert stored.detail == "18 passed"


def test_one_per_turn(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    """Each is a clone, an image build and a suite run. A queue that empties itself as fast as it
    can is a queue nobody can watch."""
    tried = _Tried()
    monkeypatch.setattr(upgrades, "verify_one", tried)

    upgrades.verify_next(db, get_settings(), clone=_Cloned())

    assert len(tried.asked) == 1


def test_the_second_turn_takes_the_next_pair(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**A verdict is about a pair of versions, not a package.** OSV publishes two fixed versions
    when an advisory was fixed on two release branches, and they are two questions."""
    tried = _Tried()
    monkeypatch.setattr(upgrades, "verify_one", tried)

    upgrades.verify_next(db, get_settings(), clone=_Cloned())
    upgrades.verify_next(db, get_settings(), clone=_Cloned())

    assert [asked[2] for asked in tried.asked] == [("49.0.0",), ("50.0.0",)]
    assert db.query(UpgradeVerdict).count() == 2


def test_nothing_left_to_try_says_nothing(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An idle instance is idle: no clone, no build, no row."""
    monkeypatch.setattr(upgrades, "verify_one", _Tried())
    for _ in range(3):
        upgrades.verify_next(db, get_settings(), clone=_Cloned())

    tried = _Tried()
    monkeypatch.setattr(upgrades, "verify_one", tried)

    nothing = upgrades.verify_next(db, get_settings(), clone=_Cloned())
    assert nothing is None
    assert tried.asked == []


# --- and what it must never do ---------------------------------------------------------------


def test_it_clones_with_the_credential_that_cannot_push(
    db: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**DR-0026's line, held by construction rather than by care.** A verification writes to no
    repository, so it has no business holding the token that could.

    Measured on the dispatcher's own clone rather than on a double: a test whose stand-in decides
    which token to read is a test of the stand-in. The one thing worth knowing here is which of the
    two credentials in `Settings` the code that runs in production reaches for, and only
    `cli._verify_one_upgrade` answers that.
    """
    monkeypatch.setenv("HULLWORK_FORGE_CODE_TOKEN", "can-push")
    get_settings.cache_clear()
    handed: list[str] = []

    def checkout(url: str, token: str, *, into: Path) -> object:
        handed.append(token)
        (into / "requirements.txt").write_text("cryptography==48.0.1\n")
        return SimpleNamespace(path=into)

    monkeypatch.setattr(work, "checkout", checkout)
    monkeypatch.setattr(upgrades, "verify_one", _Tried())

    cli._verify_one_upgrade(db, get_settings())

    assert handed == ["read-only"], "it clones with a token that can push"
    assert "can-push" not in handed


def test_a_build_that_refuses_is_not_a_broken_suite(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`will-not-install` is the build failing, which is a different fact from the suite failing —
    and rendering it as `breaks` would be this product's own worst failure."""
    monkeypatch.setattr(upgrades, "verify_one", _Tried(verdict=None))

    upgrades.verify_next(db, get_settings(), clone=_Cloned())

    assert db.query(UpgradeVerdict).one().outcome == "will-not-install"


def test_a_project_with_no_report_is_left_alone(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing is inferred from silence: a project nobody has asked OSV about has no upgrade to
    try, and trying one would be acting on a guess."""
    db.query(DependencyReport).delete()
    db.commit()
    tried = _Tried()
    monkeypatch.setattr(upgrades, "verify_one", tried)

    nothing = upgrades.verify_next(db, get_settings(), clone=_Cloned())
    assert nothing is None
    assert tried.asked == []


def test_a_report_that_could_not_be_taken_is_not_acted_on(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DR-0024's condition, carried forward: *could not ask OSV* is not an empty report, and it is
    certainly not a list of upgrades to go and try."""
    report = db.query(DependencyReport).one()
    report.asked = False
    db.commit()
    tried = _Tried()
    monkeypatch.setattr(upgrades, "verify_one", tried)

    nothing = upgrades.verify_next(db, get_settings(), clone=_Cloned())
    assert nothing is None
    assert tried.asked == []


# --- and what is not a fix at all (item 243) ----------------------------------------------------


def test_a_version_older_than_the_pin_is_never_tried(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**Seen on the page the moment item 242 put the history on it.** Four of six verdicts in an
    hour were downgrades: `brace-expansion 5.0.6 → 2.1.3`, `→ 3.0.3`, `→ 2.1.2`, `→ 1.1.16`.

    OSV publishes a fix per release branch, so an advisory carries all of them. To somebody pinned
    at 5.0.6 the ones below it are the same advisory fixed on somebody else's branch — and on a
    resolver that would accept one, taking it is a regression shipped as a security fix.
    """
    report = db.query(DependencyReport).one()
    report.findings = [
        {
            "package": "brace-expansion", "version": "5.0.6", "source": "requirements.txt",
            "advisories": [
                {"id": "GHSA-a", "summary": "s", "fixed": ["1.1.18", "2.1.4", "5.0.9"]}
            ],
        }
    ]
    db.commit()
    tried = _Tried()
    monkeypatch.setattr(upgrades, "verify_one", tried)

    for _ in range(4):
        upgrades.verify_next(db, get_settings(), clone=_Cloned())

    assert [asked[2] for asked in tried.asked] == [("5.0.9",)]


def test_two_versions_above_the_pin_are_both_tried(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**Not *only the newest*.** An advisory may be fixed at one and not the other, which is what
    item 233's *a verdict is about a pair of versions* exists for."""
    report = db.query(DependencyReport).one()
    report.findings = [
        {
            "package": "brace-expansion", "version": "5.0.6", "source": "requirements.txt",
            "advisories": [{"id": "GHSA-a", "summary": "s", "fixed": ["5.0.7", "5.0.10"]}],
        }
    ]
    db.commit()
    tried = _Tried()
    monkeypatch.setattr(upgrades, "verify_one", tried)

    for _ in range(3):
        upgrades.verify_next(db, get_settings(), clone=_Cloned())

    # And in the right order, which a string comparison gets wrong: `5.0.10` sorts before `5.0.9`.
    assert [asked[2] for asked in tried.asked] == [("5.0.7",), ("5.0.10",)]


def test_a_version_nobody_can_parse_is_tried_rather_than_dropped(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """OSV carries `1.2.3.RELEASE` and `2024-11-01` among the ordinary ones. A rule that guessed
    would hide a real fix, and hiding one is the only failure this half must not have."""
    report = db.query(DependencyReport).one()
    report.findings = [
        {
            "package": "thing", "version": "RELEASE-9", "source": "requirements.txt",
            "advisories": [{"id": "GHSA-a", "summary": "s", "fixed": ["RELEASE-10"]}],
        }
    ]
    db.commit()
    tried = _Tried()
    monkeypatch.setattr(upgrades, "verify_one", tried)

    upgrades.verify_next(db, get_settings(), clone=_Cloned())

    assert [asked[2] for asked in tried.asked] == [("RELEASE-10",)]


# --- what it keeps for later (item 245) -------------------------------------------------------


class _CloneOfARepository:
    """A clone that is a real git repository, so the sha comes from the tree rather than a double.

    `_Cloned` writes a directory, and a directory answers `working tree` — which would let a defect
    that stores no sha pass a test that mocked one.

    **The repository is a subdirectory of what it was handed**, which is what `work.checkout` does:
    it clones into `into/<name>`. Returning `into` itself made two different paths behave the same,
    so a defect reading the sha from the wrong one was invisible — found by reintroducing it.
    """

    def __init__(self) -> None:
        self.sha = ""

    def __call__(self, settings: Settings, project: Project, into: Path) -> Path:
        del settings, project
        into = into / "clone"
        into.mkdir()
        (into / "requirements.txt").write_text("cryptography==48.0.1\n")
        run = ["git", "-C", str(into)]
        subprocess.run([*run, "init", "-q"], check=True)  # noqa: S603
        subprocess.run([*run, "add", "-A"], check=True)  # noqa: S603
        subprocess.run(  # noqa: S603
            [*run, "-c", "user.email=t@example", "-c", "user.name=t", "commit", "-qm", "in"],
            check=True,
        )
        done = subprocess.run(  # noqa: S603
            [*run, "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        )
        self.sha = done.stdout.strip()
        return into


class _TriedWithAnArtefact(_Tried):
    """A verdict that carries what the passing run produced, which is what makes it openable.

    **It carries files whatever the verdict is**, and that is deliberate: `keepable` must refuse a
    verdict that did not pass *because of the verdict*, not because a `breaks` happens to arrive
    with nothing attached. Reintroducing the missing guard proved the point — the first version of
    the negative test below used a double with no files, so it passed with the guard deleted.
    """

    def __call__(self, *args: object, **kwargs: object) -> bump.Report | None:
        report = super().__call__(*args, **kwargs)  # type: ignore[arg-type]
        if report is None or not report.answers:
            return report
        answer = report.answers[0]
        return bump.Report(
            package=report.package,
            was=report.was,
            answers=(
                bump.Answer(
                    verdict=answer.verdict, package=answer.package, was=answer.was, to=answer.to,
                    detail=answer.detail,
                    files={"requirements.txt": b"cryptography==49.0.0\n"},
                    runs=bump.Runs(
                        command="pytest", before_exit=0, after_exit=0,
                        before_summary="18 passed", after_summary="18 passed",
                    ),
                ),
            ),
        )


def test_a_clean_verification_keeps_what_it_passed_with(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**Item 245's first criterion.** Without this the button can only re-run the resolver, and a
    lock regenerated twice can differ from the one the suite passed against."""
    monkeypatch.setattr(upgrades, "verify_one", _TriedWithAnArtefact())
    clone = _CloneOfARepository()

    upgrades.verify_next(db, get_settings(), clone=clone)

    stored = db.query(UpgradeVerdict).one()
    assert stored.outcome == "clean"
    assert stored.artefact is not None
    assert stored.artefact["files"] == {"requirements.txt": "cryptography==49.0.0\n"}
    assert stored.artefact["runs"]["after_summary"] == "18 passed"
    # **The commit the suite ran against**, read from the clone before it is deleted. A branch
    # rooted anywhere else contains a tree nobody tested.
    assert stored.base_sha == clone.sha


def test_a_verdict_that_did_not_pass_keeps_nothing(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A `breaks` has a finding and nothing to open. Storing files for it would be paying for a
    button that must never exist — and the refusal has to come from the verdict, so the double
    hands over an artefact and the guard is the only thing that can drop it."""
    monkeypatch.setattr(
        upgrades, "verify_one", _TriedWithAnArtefact(verdict=bump.Verdict.BREAKS)
    )

    upgrades.verify_next(db, get_settings(), clone=_CloneOfARepository())

    stored = db.query(UpgradeVerdict).one()
    assert stored.outcome == "breaks"
    assert stored.artefact is None
