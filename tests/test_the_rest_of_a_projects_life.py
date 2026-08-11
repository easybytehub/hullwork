"""Everything a project needs after it is connected. Item 207, DR-0022.

Item 206 put registration on the page. This is the rest: re-read the manifest, disable, rotate the
webhook secret, name it in the tracker — the four that otherwise send somebody back to
`docker compose exec`.

One route with an action field rather than four routes, because the guard that keeps the write
surface readable is a list somebody has to read, and four names for one page's worth of buttons is
how that list stops being read.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from hullwork import operator
from hullwork.config import get_settings
from hullwork.db import make_engine
from hullwork.models import Base, Project

MANIFEST = """
project: mine
git: {provider: forgejo, repo: o/r}
tests: "pytest"
test_path: tests
"""


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path}/page.db"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.setenv("HULLWORK_BASE_URL", "https://hullwork.example")
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "tok-forge-must-never-render")
    get_settings.cache_clear()
    yield sessionmaker(bind=engine)()
    get_settings.cache_clear()


@pytest.fixture
def client() -> TestClient:
    from hullwork.main import app

    return TestClient(app)


class _Forge:
    """Both methods: a double missing `close` reported a defect of mine where theirs goes."""

    def read_manifest(self, repo: str) -> str:
        return MANIFEST

    def close(self) -> None:
        return None


def _connected(db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> str:
    from hullwork import cli

    operator.set_password(db, "correct horse")
    db.commit()
    client.post("/page/me/login", data={"password": "correct horse"})
    csrf = operator.acting(db, client.cookies.get(operator.COOKIE)) or ""
    monkeypatch.setattr(cli, "make_forge", lambda _s: _Forge())
    client.post(
        "/page/me/projects",
        data={"slug": "mine", "repo": "o/r", "forge": "forgejo", "csrf": csrf},
    )
    return csrf


def _act(client: TestClient, what: str, csrf: str, **extra: str) -> object:
    return client.post(
        "/page/me/projects/mine", data={"action": what, "csrf": csrf, **extra}
    )


# --- the four ------------------------------------------------------------------------------------


def test_it_disables_a_project(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    csrf = _connected(db, client, monkeypatch)

    _act(client, "disable", csrf)

    db.expire_all()
    assert db.query(Project).filter(Project.slug == "mine").one().active is False


def test_it_names_the_project_in_the_tracker(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The one with no reusable function until this item — it lived inside the CLI command."""
    csrf = _connected(db, client, monkeypatch)

    _act(client, "set-tracker", csrf, tracker_project="mine-on-glitchtip")

    db.expire_all()
    assert db.query(Project).filter(Project.slug == "mine").one().tracker_project == (
        "mine-on-glitchtip"
    )


def test_it_re_reads_the_manifest(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    csrf = _connected(db, client, monkeypatch)

    answered = _act(client, "refresh", csrf)

    assert answered.status_code == 200  # type: ignore[attr-defined]
    assert db.query(Project).filter(Project.slug == "mine").one().manifest


def test_a_rotated_secret_is_shown_once_and_says_what_it_broke(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same problem as minting, plus one: rotating **stops the URL the tracker is using**, and that
    belongs before the new value rather than after it."""
    csrf = _connected(db, client, monkeypatch)

    answered = _act(client, "rotate-secret", csrf)

    text = answered.text  # type: ignore[attr-defined]
    assert "/webhooks/" in text
    assert "only time" in text.lower()
    assert "stopped working" in text.lower(), "the old URL is dead and it has to say so"


# --- the guards ----------------------------------------------------------------------------------


def test_every_action_needs_the_csrf_pair(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _connected(db, client, monkeypatch)

    answered = _act(client, "disable", "not-the-one")

    assert answered.status_code == 403  # type: ignore[attr-defined]
    db.expire_all()
    assert db.query(Project).filter(Project.slug == "mine").one().active is True


def test_an_unknown_action_does_nothing_and_says_so(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**Never a default.** A form field that falls through to whichever branch is last is how a
    typo becomes a disabled project."""
    csrf = _connected(db, client, monkeypatch)

    answered = _act(client, "delete-everything", csrf)

    said = re.search(r'c-refused">([^<]*)', answered.text)  # type: ignore[attr-defined]
    assert said is not None
    db.expire_all()
    assert db.query(Project).filter(Project.slug == "mine").one().active is True


def test_there_is_exactly_one_new_route() -> None:
    """The guard that keeps the write surface readable is a list a person reads. Four names for one
    page's worth of buttons is how a list stops being read."""
    from hullwork import page
    from hullwork.main import app

    posts = {
        getattr(route, "path", "")
        for route in app.routes
        if "POST" in getattr(route, "methods", set())
        and getattr(route, "path", "").startswith(page.PREFIX)
    }

    assert f"{page.PREFIX}/{{token}}/projects/{{slug}}" in posts
    assert len(posts) == 6, sorted(posts)
