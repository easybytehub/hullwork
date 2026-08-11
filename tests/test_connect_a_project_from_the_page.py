"""Registering a project without opening a shell. Item 206, DR-0022.

Item 205 counted the gap: nineteen subcommands in the terminal, four write routes on the page. This
is the one that forces a shell in the first hour, and the receiver already holds every credential it
needs — `forge_token` is *issue write and content read*, which is exactly what reading a
repository's
`hullwork.yml` takes.

The operator's argument, which DR-0022 records: a security property nobody reaches protects nobody.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

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


def _signed_in(db: Session, client: TestClient) -> str:
    """A session, and the CSRF token that goes with it — what every write route already needs."""
    operator.set_password(db, "correct horse")
    db.commit()
    client.post("/page/me/login", data={"password": "correct horse"})
    return operator.acting(db, client.cookies.get(operator.COOKIE)) or ""


def _the_forge_answers(monkeypatch: pytest.MonkeyPatch, text: str = MANIFEST) -> None:
    """The repository read `add_project` makes. The receiver's own credential does this today."""
    from hullwork import cli

    class _Forge:
        """**Both methods, and the second is why this is a comment.** A double missing `close` made
        the route report `'_Forge' object has no attribute 'close'` as if the operator had typed
        something wrong — the third hand-built double to drift from its protocol today."""

        def read_manifest(self, repo: str) -> str:
            return text

        def close(self) -> None:
            return None

    monkeypatch.setattr(cli, "make_forge", lambda _settings: _Forge())


# --- the door that replaces the shell -------------------------------------------------------------


def test_a_project_is_registered_from_the_page(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole item, and the step that currently sends somebody to `docker compose exec`."""
    csrf = _signed_in(db, client)
    _the_forge_answers(monkeypatch)

    answered = client.post(
        "/page/me/projects",
        data={"slug": "mine", "repo": "o/r", "forge": "forgejo", "csrf": csrf},
    )

    assert answered.status_code == 200
    assert db.query(Project).filter(Project.slug == "mine").one_or_none() is not None


def test_the_webhook_url_is_shown_once_and_said_to_be_once(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A copy-exactly-once value in a browser is worse than in a terminal — scrollback, history, a
    screenshot. DR-0022's answer is that this is a presentation requirement, so the page says
    plainly that this is the only time, and what to do when it is lost."""
    csrf = _signed_in(db, client)
    _the_forge_answers(monkeypatch)

    answered = client.post(
        "/page/me/projects",
        data={"slug": "mine", "repo": "o/r", "forge": "forgejo", "csrf": csrf},
    )

    assert "/webhooks/" in answered.text
    assert "only time" in answered.text.lower()
    assert "rotate-secret" in answered.text


def test_it_is_never_shown_again(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the hash is stored, exactly as the command does it. A later view that could show it
    would make the sentence above a lie."""
    csrf = _signed_in(db, client)
    _the_forge_answers(monkeypatch)
    made = client.post(
        "/page/me/projects",
        data={"slug": "mine", "repo": "o/r", "forge": "forgejo", "csrf": csrf},
    )
    secret = made.text.split("/webhooks/")[1].split('"')[0].split("<")[0].strip()

    later = client.get("/page/me/projects")

    assert secret not in later.text
    assert secret not in client.get("/page/me/").text


# --- the guards every write route already has -----------------------------------------------------


def test_without_a_session_it_is_refused(db: Session, client: TestClient) -> None:
    """DR-0021 and item 166: no write route is reachable without the password."""
    answered = client.post(
        "/page/me/projects", data={"slug": "mine", "repo": "o/r", "forge": "forgejo"}
    )

    assert answered.status_code == 404
    assert db.query(Project).count() == 0


def test_a_wrong_csrf_is_refused(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _signed_in(db, client)
    _the_forge_answers(monkeypatch)

    answered = client.post(
        "/page/me/projects",
        data={"slug": "mine", "repo": "o/r", "forge": "forgejo", "csrf": "not-the-one"},
    )

    assert answered.status_code == 403
    assert db.query(Project).count() == 0


# --- the three things a person gets wrong ---------------------------------------------------------


def test_a_manifest_that_does_not_parse_says_which_line(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The command already writes a sentence per problem, naming the key. A generic failure here
    would send somebody to the shell to find out what the page already knew.

    **Asserted on the refusal, not on the page.** The first version looked for the word `repo`
    anywhere in the response — and the form on that same page has `name="repo"` in it, so it passed
    whatever the message said. Found by mutation: replacing the sentence with *something went wrong*
    changed nothing.
    """
    import re

    csrf = _signed_in(db, client)
    _the_forge_answers(monkeypatch, text="project: mine\ngit: {provider: forgejo}\n")

    answered = client.post(
        "/page/me/projects",
        data={"slug": "mine", "repo": "o/r", "forge": "forgejo", "csrf": csrf},
    )

    said = re.search(r'c-refused">([^<]*)', answered.text)
    assert said is not None, "the refusal is not on the page at all"
    assert "repo" in said.group(1).lower(), said.group(1)
    assert db.query(Project).count() == 0


def test_a_slug_already_taken_says_so(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    csrf = _signed_in(db, client)
    _the_forge_answers(monkeypatch)
    client.post(
        "/page/me/projects",
        data={"slug": "mine", "repo": "o/r", "forge": "forgejo", "csrf": csrf},
    )

    again = client.post(
        "/page/me/projects",
        data={"slug": "mine", "repo": "o/r", "forge": "forgejo", "csrf": csrf},
    )

    assert "mine" in again.text
    assert db.query(Project).filter(Project.slug == "mine").count() == 1


def test_a_reader_with_a_link_is_not_shown_a_form_they_cannot_submit(
    db: Session, client: TestClient
) -> None:
    """**DR-0021's split, on this page.** A token gives reading; the password gives the buttons. A
    form rendered to somebody who cannot submit it is worse than no form: it offers, and then it
    refuses.

    Found by mutation — nothing asserted the absence, so removing the check that hides it changed
    nothing.
    """
    from hullwork import page
    from hullwork.security import generate_token, hash_token

    minted = generate_token()
    page.issue(db, hash_token(minted))
    db.commit()

    shown = client.get(f"/page/{minted}/projects")

    assert shown.status_code == 200
    assert "<form" not in shown.text
