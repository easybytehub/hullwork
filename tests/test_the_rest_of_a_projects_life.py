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

import html as h
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
    """**Posted to `settings`, which is the view every one of these buttons is on** (item 250).

    It posted to `projects/mine` and was answered with a document written for somewhere else — the
    list of projects on a refusal and on `rotate-secret` — so every link on the page that came back
    resolved one level too deep.
    """
    return client.post(
        "/page/me/projects/mine/settings", data={"action": what, "csrf": csrf, **extra}
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

    # **Item 250 moved this one segment deeper and added none.** The five views a project has do
    # not need five routes: `feature` names the document that comes back, which a `POST` has to
    # answer with because the answer is served at the URL the form posted to.
    assert f"{page.PREFIX}/{{token}}/projects/{{slug}}/{{feature}}" in posts
    # Eight since item 219 added the instance's upkeep and the item's housekeeping, each on one
    # route with an action rather than three names and two. The number is asserted rather than the
    # membership because the point is that it stays small enough to read.
    assert len(posts) == 8, sorted(posts)


def test_every_action_says_what_it_did(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**Found by pressing them** (item 223). `refresh`, `disable` and `set-tracker` completed and
    rendered nothing — a control that appears to do nothing is a control somebody presses again,
    which on `refresh` is a second forge request and on `disable` is a minute of wondering whether
    the first one worked.

    The two that already spoke were a rotated secret and a refusal: the ones with something obvious
    to show. Silence on success is the easy half to forget.
    """
    csrf = _connected(db, client, monkeypatch)

    # **Read out of the outcome block, not out of the page.** The first version looked for the
    # tracker's name anywhere, and the view renders it in the form field it just set — so deleting
    # the answer entirely still passed. One question, two answers, again.
    def _answered(response: object) -> str:
        found = re.search(r'class="[^"]*outcome[^"]*">(.*?)</', response.text, re.S)  # type: ignore[attr-defined]
        return found.group(1) if found else ""

    assert "in the tracker" in _answered(
        _act(client, "set-tracker", csrf, tracker_project="mine-in-tracker")
    )
    assert "manifest again" in _answered(_act(client, "refresh", csrf))

    stopped = _answered(_act(client, "disable", csrf))
    assert "no longer watched" in stopped
    assert "Nothing was deleted" in stopped


def test_stopping_a_project_says_what_it_means_before_it_does_it(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**Item 226, found by doing it to a real instance while auditing it.** `Stop watching it` sat
    in the same row as `Re-read its manifest` — one idempotent, one that silently stops the product
    working for that project — and there was no way back from either the page or the terminal.

    Two submissions now, like `prune`: the first says what stopping means and changes nothing.
    """
    csrf = _connected(db, client, monkeypatch)

    warned = _act(client, "disable-preview", csrf)

    assert "no issue is filed" in warned.text  # type: ignore[attr-defined]
    assert "watching it again is one button" in warned.text  # type: ignore[attr-defined]
    assert db.query(Project).filter(Project.slug == "mine").one().active is True


def test_a_stopped_project_can_be_watched_again(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**Reversible in principle and irreversible in practice is the worst of both.** `disable`
    deletes nothing — that is its whole design — and until this the only undo was an `UPDATE`
    against a SQLite file inside a Docker volume."""
    csrf = _connected(db, client, monkeypatch)
    _act(client, "disable", csrf)

    assert db.query(Project).filter(Project.slug == "mine").one().active is False

    back = _act(client, "enable", csrf)

    # **Escaped, because the page escapes.** `'mine'` is `&#x27;mine&#x27;` in the served bytes,
    # and a test comparing against the unescaped form is testing a string nobody is sent.
    assert "Nothing was re-validated" in back.text  # type: ignore[attr-defined]
    assert h.escape("Watching 'mine' again", quote=True) in back.text  # type: ignore[attr-defined]
    db.expire_all()
    assert db.query(Project).filter(Project.slug == "mine").one().active is True
