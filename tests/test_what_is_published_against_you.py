"""The dependency report, on the instance and on the page. DR-0024, item 230.

Accepted 2026-08-11 with two conditions, and they are the interesting half:

> *el informe se guarda con cuándo se tomó, y "no pude preguntar a OSV" es una respuesta de primera
> clase, nunca una lista vacía.*

They are the same sentence twice. A report rendered without its timestamp is a claim about a moment
presented as a standing fact; an advisory list that silently reads empty when the request failed
says *you are fine* on no evidence at all. Either one turns the half of the product an evaluator
can use on their first day into the kind of green tick this product exists to distrust.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.orm import Session, sessionmaker

from hullwork import advisories, page
from hullwork.config import Settings, get_settings
from hullwork.db import make_engine
from hullwork.models import Base, DependencyReport, Project
from hullwork.osv import Advisory, Finding

LOCK = """[[package]]
name = "requests"
version = "2.31.0"
"""


class _Tree:
    def __init__(self, paths: tuple[str, ...]) -> None:
        self.paths = paths
        self.truncated = False


class _Forge:
    """A forge that lists a tree and reads files, which is all this needs."""

    def __init__(self, paths: tuple[str, ...] = ("uv.lock",), text: str | None = LOCK) -> None:
        self._paths = paths
        self._text = text
        self.read: list[str] = []

    def tree(self, repo: str) -> _Tree:
        return _Tree(self._paths)

    def read_file(self, repo: str, path: str) -> str | None:
        self.read.append(path)
        return self._text

    def close(self) -> None:
        pass


class _Refuses(_Forge):
    def tree(self, repo: str) -> _Tree:
        raise RuntimeError("403 Forbidden")


def _one_advisory(deps: Sequence[Any]) -> list[Finding]:
    return [
        Finding(
            dependency=deps[0],
            advisories=(
                Advisory(id="GHSA-xxxx", summary="a real one", fixed=("2.32.0", "2.31.1")),
            ),
        )
    ]


def _nothing(deps: Sequence[Any]) -> list[Finding]:
    return []


def _unreachable(deps: Sequence[Any]) -> list[Finding]:
    raise TimeoutError("api.osv.dev did not answer")


# --- reading and asking ------------------------------------------------------------------------


def test_it_reads_what_is_pinned_and_asks_about_it() -> None:
    """One forge listing, one file per lock, one batch to OSV. Nothing here needs a credential OSV
    does not take or a socket the receiver does not have."""
    forge = _Forge()

    report = advisories.about("acme/shop", forge, _one_advisory)

    assert forge.read == ["uv.lock"]
    assert report.asked is True
    assert report.pinned == 1
    assert report.findings[0]["package"] == "requests"
    assert report.findings[0]["advisories"][0]["fixed"] == ["2.32.0", "2.31.1"]


def test_a_forge_that_will_not_list_is_not_a_clean_report() -> None:
    """**The condition, half one.** Two halves can fail and they are different problems: this one
    names which."""
    report = advisories.about("acme/shop", _Refuses(), _one_advisory)

    assert report.asked is False
    assert "could not list" in (report.note or "")
    assert report.findings == []


def test_osv_being_unreachable_is_not_an_empty_report() -> None:
    """**The condition, half two, and the one that matters.** `asked=False` with a note is the
    answer; `findings=[]` with `asked=True` would be a page saying *you are fine* because the
    network was down."""
    report = advisories.about("acme/shop", _Forge(), _unreachable)

    assert report.asked is False
    assert report.pinned == 1, "it read the lock file before it failed, and says so"
    assert "could not reach OSV" in (report.note or "")


def test_nothing_pinned_is_its_own_sentence() -> None:
    """*Nothing published* and *nothing pinned* are different facts about different problems, and a
    report that blurred them would tell a project with no lock file that it is clean."""
    report = advisories.about("acme/shop", _Forge(paths=("README.md",)), _one_advisory)

    assert report.asked is True
    assert report.pinned == 0
    assert "nothing here pins a version" in (report.note or "")


def test_a_file_that_will_not_read_costs_only_itself() -> None:
    """A `package-lock.json` the forge refuses while `uv.lock` comes back fine is one file saying
    nothing, not a failed report."""
    forge = _Forge(paths=("package-lock.json", "uv.lock"), text=None)

    report = advisories.about("acme/shop", forge, _nothing)

    assert forge.read == ["package-lock.json", "uv.lock"]
    assert report.asked is True


# --- and what the page says about it ------------------------------------------------------------


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path}/adv.db"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    session = sessionmaker(bind=engine)()
    session.add(
        Project(
            slug="shop", forge="forgejo", repo="acme/shop",
            webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
        )
    )
    session.commit()
    yield session
    get_settings.cache_clear()


def _stored(db: Session, **fields: object) -> None:
    row = db.query(Project).one()
    db.merge(
        DependencyReport(
            project_id=row.id,
            taken_at=dt.datetime.now(dt.UTC) - dt.timedelta(hours=2),
            **fields,
        )
    )
    db.commit()


def _view(db: Session) -> str:
    """**Its own page since item 235.** This was a closed `<details>` on a project's view, and the
    operator said three times that he could not find things: a feature that spans projects is a
    page that spans projects."""
    signed_in = page.Acting(csrf="c", offered=True)
    return page.dependencies(db, Settings(), "shop", acting=signed_in) or ""


def test_the_page_says_when_it_was_asked(db: Session) -> None:
    """**The operator's first condition.** A dependency report is a claim about a moment; one
    rendered without its timestamp is the permanently-on signal item 073 deleted a check for."""
    _stored(db, asked=True, pinned=12, findings=[])

    shown = _view(db)

    assert "Asked 2h" in shown or "Asked 2 h" in shown


def test_could_not_ask_never_reads_as_clean(db: Session) -> None:
    """**The second condition, on the page.** The words have to say that nothing was learned —
    a fold headed *none published* over a failed request is the lie this guards against."""
    _stored(db, asked=False, pinned=9, note="read 9 pinned version(s) and could not reach OSV: x")

    shown = _view(db)

    # **Lowercased, because the sentence moved out of a `<details>` summary and into the body**
    # (item 235). What is asserted is the claim, not the sentence case it happens to carry.
    assert "could not ask" in shown.lower()
    assert "not an empty report" in shown
    # **Asserted on the claim, not on a substring of the document.** The old form sliced the whole
    # page around two phrases and looked for `none`, which the stylesheet supplies twenty times over
    # (`text-decoration: none`) — it passed for four months because the slice happened to miss them.
    assert "nothing published against" not in shown.lower(), "it reads clean over a failed request"


def test_nothing_published_says_how_many_it_asked_about(db: Session) -> None:
    """*None of twelve* and *none of nothing* are different answers, and only one of them is good
    news."""
    _stored(db, asked=True, pinned=12, findings=[])

    shown = _view(db)

    # The count was in the fold's summary — *none, of 12* — until item 235 unfolded the feature.
    # The claim is unchanged and it is the one that matters: **of how many**.
    assert "nothing published against any of the 12" in shown
    assert "12 pinned version(s)" in shown


def test_a_finding_carries_its_fix(db: Session) -> None:
    """An advisory with nothing to upgrade to is a different situation from one with two, and both
    happen. The versions come from OSV and a person picks."""
    _stored(
        db,
        asked=True,
        pinned=3,
        findings=[
            {
                "package": "requests",
                "version": "2.31.0",
                "source": "uv.lock",
                "advisories": [
                    {"id": "GHSA-xxxx", "summary": "a real one", "fixed": ["2.32.0"]},
                    {"id": "GHSA-yyyy", "summary": "no fix yet", "fixed": []},
                ],
            }
        ],
    )

    shown = _view(db)

    assert "requests" in shown and "2.31.0" in shown
    assert "2.32.0" in shown
    # One advisory of the two publishes nothing to move to; the package still has somewhere to go,
    # so it is not in the band for packages that do not.
    assert "Nothing published to upgrade to" not in shown


def test_a_project_nobody_has_asked_about_says_who_will(db: Session) -> None:
    """Not *run this command*: item 228's lesson, applied to the feature next to it."""
    shown = _view(db)

    assert "Not asked yet" in shown
    assert "on its own clock" in shown


def test_the_page_never_asks_osv_itself(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    """Item 142's rule, again: a render spends no request — not to a forge and not to OSV."""
    from hullwork import osv as osv_module

    def _refuse(*args: object, **kwargs: object) -> object:
        raise AssertionError("a page render asked OSV")

    monkeypatch.setattr(osv_module, "Osv", _refuse)
    _stored(db, asked=True, pinned=1, findings=[])

    assert "<h1>" in _view(db)


# --- and the clock asks it ----------------------------------------------------------------------


class _Scoped:
    def __init__(self, session: Session) -> None:
        self._session = session

    def __enter__(self) -> Session:
        return self._session

    def __exit__(self, *exc: object) -> None:
        return None


def test_the_sweep_asks_and_stores_it(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    """**The item, wired.** Every test above calls `advisories.about` directly; deleting the line
    that hangs it on the clock would leave them green and the instance silent — which is exactly
    what escaped in item 228, one item ago, in the function next door."""
    from hullwork import advisories as advisories_module
    from hullwork import main as main_module

    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "t")
    get_settings.cache_clear()
    monkeypatch.setattr(main_module, "make_forge", lambda settings: _Forge())
    monkeypatch.setattr(advisories_module, "asking", lambda timeout=20.0: _one_advisory)

    main_module._ask_what_is_published_against_what_they_pin(
        lambda: _Scoped(db),  # type: ignore[arg-type]
        get_settings(),
    )

    stored = db.query(DependencyReport).one()
    assert stored.asked is True
    assert stored.pinned == 1
    assert stored.findings[0]["package"] == "requests"
    assert stored.taken_at is not None


def test_it_does_not_ask_again_inside_the_interval(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Six hours, not sixty seconds: advisories are published on a human's schedule, and asking a
    public database every minute would be spending somebody else's API to learn nothing."""
    from hullwork import advisories as advisories_module
    from hullwork import main as main_module

    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "t")
    get_settings.cache_clear()
    forge = _Forge()
    monkeypatch.setattr(main_module, "make_forge", lambda settings: forge)
    monkeypatch.setattr(advisories_module, "asking", lambda timeout=20.0: _one_advisory)

    for _ in range(2):
        main_module._ask_what_is_published_against_what_they_pin(
            lambda: _Scoped(db),  # type: ignore[arg-type]
            get_settings(),
        )

    assert forge.read == ["uv.lock"], "it asked again inside the interval"


def test_the_sweep_itself_calls_it(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    """**And the escape happened anyway.** The test above says deleting the wiring would leave
    everything green, and then nothing checked it — so the mutation walked through, in the item
    right after the one where the identical thing happened.

    Predicting a hole is not covering it."""
    from hullwork import advisories as advisories_module
    from hullwork import main as main_module
    from hullwork.ingest import SweepResult

    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "t")
    get_settings.cache_clear()
    forge = _Forge()
    monkeypatch.setattr(main_module, "make_forge", lambda settings: forge)
    monkeypatch.setattr(advisories_module, "asking", lambda timeout=20.0: _one_advisory)
    monkeypatch.setattr(main_module, "make_tracker", lambda settings: None)
    monkeypatch.setattr(main_module, "make_inventory", lambda settings: None)
    nothing = SweepResult(deliveries=0, filed=0, resolved=0)
    monkeypatch.setattr(main_module, "sweep", lambda *a, **k: nothing)
    monkeypatch.setattr(
        main_module, "_measure_what_the_ingest_credential_may_do", lambda *a, **k: None
    )

    main_module._sweep_once(lambda: _Scoped(db), get_settings())  # type: ignore[arg-type]

    assert db.query(DependencyReport).count() == 1, "the sweep does not ask"


def test_a_finding_is_three_facts_and_not_its_prose(db: Session) -> None:
    """**Item 236, measured on the operator's own instance.** Every advisory's summary was joined
    inline with semicolons: ten lines for one row, twenty-five rows — and OSV carries a GHSA *and*
    a PYSEC identifier for the same advisory, so half of it was the other half word for word.

    The row is which package, at which version, and what to move to. The summaries are why somebody
    cares once they have decided to look, which is evidence, and evidence is what a fold is for.
    """
    _stored(
        db,
        asked=True,
        pinned=3,
        findings=[
            {
                "package": "cryptography",
                "version": "48.0.1",
                "source": "backend/uv.lock",
                "advisories": [
                    {"id": "GHSA-g6cj", "summary": "a Bleichenbacher oracle", "fixed": ["50.0.0"]},
                    {"id": "PYSEC-3552", "summary": "a Bleichenbacher oracle", "fixed": ["50.0.0"]},
                    {"id": "GHSA-jwv3", "summary": "path-building", "fixed": ["49.0.0"]},
                ],
            }
        ],
    )

    shown = _view(db)
    row = shown.split('<tr class="subject">')[1].split("</tr>")[0]

    assert "backend/uv.lock" in row
    # **Two identifiers, one advisory, one version to move to.** `50.0.0, 50.0.0, 49.0.0` is a list
    # that has been counted wrong, and it is what a reader would have had to de-duplicate by eye.
    assert "50.0.0 · 49.0.0" in row
    # The fold lives inside the row now, so *not in the row* is measured where it means something:
    # nothing before the disclosure opens is a summary.
    assert "Bleichenbacher" not in row.split("<details")[0], "the summaries are visible again"
    assert "Bleichenbacher" in shown, "and they have to still be on the page"


def test_the_summaries_are_behind_a_disclosure_and_say_how_many(db: Session) -> None:
    """A fold whose summary does not say what is inside it is a mystery box (item 167), and the
    count is the thing that tells a reader whether opening it is worth it."""
    _stored(
        db,
        asked=True,
        pinned=3,
        findings=[
            {
                "package": "requests", "version": "2.31.0", "source": "uv.lock",
                "advisories": [{"id": "GHSA-x", "summary": "a real one", "fixed": ["2.32.0"]}],
            }
        ],
    )

    shown = _view(db)

    # The count is the summary now (DR-0028): a disclosure whose label is a sentence spends a line
    # of the row saying what every other row also says.
    assert "<summary>1</summary>" in shown
    assert "GHSA-x" in shown and "a real one" in shown


def test_nothing_to_upgrade_to_is_said_in_the_row(db: Session) -> None:
    """**The worse case, and it stays out of the fold.** An upgrade nobody can make is the one thing
    on this page a reader cannot act on, and it must not need a click to find out."""
    _stored(
        db,
        asked=True,
        pinned=3,
        findings=[
            {
                "package": "left-pad", "version": "1.0.0", "source": "package-lock.json",
                "advisories": [{"id": "GHSA-z", "summary": "unfixed", "fixed": []}],
            }
        ],
    )

    shown = _view(db)
    row = shown.split('<tr class="subject">')[1].split("</tr>")[0]

    # **In the band's heading now** (DR-0028), which is where the sentence is said once — and the
    # row is still there, still named, still carrying its version.
    assert "Nothing published to upgrade to" in shown
    assert "left-pad" in row and "1.0.0" in row


def test_the_disclosure_spans_its_row_rather_than_the_pills_column() -> None:
    """**Seen in a browser, on atlas.** `.standing li` is a grid whose first column is 6.2rem wide
    for the count, and a `<details>` left in it set *What these 6 advisory(s) say* one word per
    line, five lines deep, on every row.

    Asserted on the rule because nothing in this repository draws anything — the browser is the only
    thing that could have caught it, and did.
    """
    from hullwork import page

    assert ".standing li > details" in page._STYLE
    assert "grid-column: 1 / -1" in page._STYLE.split(".standing li > details")[1][:60]
