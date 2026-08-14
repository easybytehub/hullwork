"""The push audit runs on the instance's own clock, and what is fine says nothing. Item 228.

The operator, reading a project's view:

> *`not asked yet — hullwork status records this when it runs`, ¿esto porque depende de un comando?
> debería de ser automático*

It did not depend on a command. **It depended on code that was never written**: the page read
`manifest["__ingest_can_push__"]`, a key that appears exactly twice in this repository and is read
both times. Running `hullwork status` would not have changed it either, and the docstring claiming
otherwise was wrong for two items.

The line answers *can the credential this instance ingests with also push code* — DR-0009's whole
subject. A signal that waits for somebody to remember is not a signal, which is item 073's rule
arriving from the other side: it deleted a check that was permanently on, and this one was
permanently unknown.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from hullwork import page
from hullwork.config import Settings, get_settings
from hullwork.db import make_engine
from hullwork.models import Base, Project


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path}/fact.db"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "t")
    get_settings.cache_clear()
    session = sessionmaker(bind=engine)()
    session.add(
        Project(
            slug="shop", forge="forgejo", repo="acme/shop",
            webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
            manifest={
                "project": "shop",
                "git": {"provider": "forgejo", "repo": "acme/shop"},
                "errors": {"provider": "glitchtip"},
            },
        )
    )
    session.commit()
    yield session
    get_settings.cache_clear()


def _view(db: Session) -> str:
    return page.project(db, Settings(), "shop", acting=page.Acting(csrf="c", offered=True)) or ""


# --- what the page says now -------------------------------------------------------------------


def test_a_project_that_is_fine_says_nothing_about_it(db: Session) -> None:
    """**`cached manifest validates` was the operator's second question**, and the answer is that
    it should not have been on the page: three internal words describing a normal state, at the
    volume of a fault. Item 203 — what is not fine, and a count of what is."""
    row = db.query(Project).one()
    row.ingest_token_can_push = False
    row.ingest_checked_at = dt.datetime.now(dt.UTC)
    db.commit()

    shown = _view(db)

    assert "validates" not in shown
    assert "What is wrong" not in shown, "a healthy project has a section headed *what is wrong*"


def test_a_credential_that_can_push_is_loud(db: Session) -> None:
    """DR-0009's subject: the receiver must not hold a credential that can push. When the forge
    says it can, that is the loudest thing this page has to say about a project."""
    row = db.query(Project).one()
    row.ingest_token_can_push = True
    row.ingest_checked_at = dt.datetime.now(dt.UTC)
    db.commit()

    shown = _view(db)

    assert "can write code" in shown
    assert "DR-0009" in shown
    assert 'class="bad"' in shown


def test_an_unmeasured_project_says_the_instance_will_ask_itself(db: Session) -> None:
    """**Not `hullwork status records this when it runs`.** That sentence sent a person to type a
    command that would not have helped, and the honest one says who is going to answer it."""
    shown = _view(db)

    assert "hullwork status" not in shown
    assert "not measured yet" in shown
    assert "on its own clock" in shown


def test_a_manifest_that_no_longer_reads_is_still_loud(db: Session) -> None:
    """The loudest thing that can be wrong with a project: every error from it lands red, silently
    by design, and until item 142 the only way to know was to read that function."""
    row = db.query(Project).one()
    row.manifest = {"project": "shop", "runtime": {"base": 5}}
    row.ingest_token_can_push = False
    row.ingest_checked_at = dt.datetime.now(dt.UTC)
    db.commit()

    shown = _view(db)

    assert "no longer validates" in shown
    assert "lands red" in shown


# --- and the clock measures it ----------------------------------------------------------------


class _Reader:
    """The forge, answering what the **account** may do — which is not the fact that is stored.

    `can_push` is the account's access. A token scoped to reads and issues is refused regardless,
    and on this project's own instance that flag was `True` for both projects while `POST /branches`
    answered `403 … scope(s): [write:repository]`. The probe below is what decides.
    """

    def __init__(self, can_push: bool) -> None:
        self._can_push = can_push
        self.asked: list[str] = []

    def can_write_code(self, repo: str) -> bool:
        self.asked.append(repo)
        return self._can_push

    def close(self) -> None:
        pass


def _sweep(
    db: Session, monkeypatch: pytest.MonkeyPatch, reader: _Reader, *, probe: bool | None = False
) -> None:
    """**Patched where they are defined.** The measurement imports both inside the function, so a
    name bound on `hullwork.main` is a name nothing looks at — the second time that has cost a
    round in this repository."""
    from hullwork import cli as cli_module
    from hullwork import main as main_module
    from hullwork.forge import factory

    monkeypatch.setattr(factory, "make_permission_reader", lambda settings: reader)
    monkeypatch.setattr(cli_module, "_scope_probe", lambda settings: lambda repo: probe)
    main_module._measure_what_the_ingest_credential_may_do(
        lambda: _Scoped(db),  # type: ignore[arg-type]
        get_settings(),
    )


class _Scoped:
    """The session factory's contract, over a session the test keeps open."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def __enter__(self) -> Session:
        return self._session

    def __exit__(self, *exc: object) -> None:
        return None


def test_the_sweep_measures_it_with_no_command_typed(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**The item.** The receiver already runs a clock; this is the fact that was waiting for a
    person to remember."""
    reader = _Reader(can_push=False)

    _sweep(db, monkeypatch, reader)

    row = db.query(Project).one()
    assert reader.asked == ["acme/shop"]
    assert row.ingest_token_can_push is False
    assert row.ingest_checked_at is not None, "a verdict with no timestamp is the old signal again"


def test_it_does_not_ask_again_before_the_interval(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two forge calls per active project per interval is the cost, and it is spent on the clock —
    not once a minute because the sweep runs once a minute."""
    reader = _Reader(can_push=False)
    _sweep(db, monkeypatch, reader)
    _sweep(db, monkeypatch, reader)

    assert reader.asked == ["acme/shop"], "it asked again inside the interval"


def test_it_asks_again_once_the_answer_is_old(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A verdict from three weeks ago is a different thing from one from ten minutes ago."""
    reader = _Reader(can_push=False)
    _sweep(db, monkeypatch, reader)
    row = db.query(Project).one()
    row.ingest_checked_at = dt.datetime.now(dt.UTC) - dt.timedelta(days=21)
    db.commit()

    _sweep(db, monkeypatch, reader)

    assert len(reader.asked) == 2


def test_rendering_a_page_spends_no_forge_request(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Item 142's rule, restated where the answer moved: the page reads a column, and a reader
    refreshing must not cost somebody their forge quota."""
    from hullwork.forge import factory

    def _refuse(settings: object) -> object:
        raise AssertionError("a page render asked the forge")

    monkeypatch.setattr(factory, "make_permission_reader", _refuse)

    assert re.search(r"<h1>", _view(db)), "the view did not render at all"


def test_the_sweep_itself_calls_it(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    """**Written because a mutation escaped.** Every test above calls the measurement directly, so
    deleting the one line that wires it into the sweep left them all green — a function that works
    and is called by nothing, which is the same shape as a route with no button (item 223).
    """
    from hullwork import cli as cli_module
    from hullwork import main as main_module
    from hullwork.forge import factory
    from hullwork.ingest import SweepResult

    reader = _Reader(can_push=False)
    monkeypatch.setattr(factory, "make_permission_reader", lambda settings: reader)
    monkeypatch.setattr(cli_module, "_scope_probe", lambda settings: None)
    monkeypatch.setattr(main_module, "make_forge", lambda settings: None)
    monkeypatch.setattr(main_module, "make_tracker", lambda settings: None)
    monkeypatch.setattr(main_module, "make_inventory", lambda settings: None)
    nothing = SweepResult(deliveries=0, filed=0, resolved=0)
    monkeypatch.setattr(main_module, "sweep", lambda *a, **k: nothing)

    main_module._sweep_once(lambda: _Scoped(db), get_settings())  # type: ignore[arg-type]

    assert reader.asked == ["acme/shop"], "the sweep does not measure it"


def test_the_accounts_access_is_not_what_is_stored(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**The alarm I nearly shipped.** The first thing the new clock recorded on the operator's own
    instance was `True` — from `can_push`, which is the *account's* access to the repository. Their
    token is refused with `403 … scope(s): [write:repository]`, which is what the module's own
    docstring describes measuring — so the page was one deploy from a permanent red *your
    credential can push* over a correct configuration.

    That is item 073's permanently-on signal, rebuilt by hand three items after it was deleted.
    """
    reader = _Reader(can_push=True)

    _sweep(db, monkeypatch, reader, probe=False)

    row = db.query(Project).one()
    assert row.ingest_token_can_push is False, "the account's answer was stored as the token's"
    assert "can write code" not in _view(db)


def test_a_token_that_really_can_write_code_is_loud(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """And the other direction, because a check that can only be quiet is not a check: when the
    probe says a request only a code scope allows was accepted, that is the fiction DR-0009 exists
    to prevent and it is measured rather than inferred."""
    reader = _Reader(can_push=True)

    _sweep(db, monkeypatch, reader, probe=True)

    assert db.query(Project).one().ingest_token_can_push is True
    assert "can write code" in _view(db)
