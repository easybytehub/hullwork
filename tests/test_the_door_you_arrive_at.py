"""Every URL on the operator's path offers the way in. Item 224.

The operator: *la web no es reactiva, es como que sólo se sirve `page/me/`, entro a cualquier otra
ruta, y me da error en el navegador.*

Reproduced exactly. With no session, `/page/me/` answered `200` with a login and **every other path
answered `{"detail":"Not Found"}`** — so a bookmark, a second browser, or a session twelve hours old
turned every view into a wall.

**The `404` is right where it is right, and it was in the wrong place.** DR-0021's reason is that
a distinct refusal tells somebody holding a *read link* which doors exist behind it. `me` is not a
read link: it is a literal anybody can type, and the front door already answers it with a login.
Refusing the rest protected nothing and cost everything.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from hullwork import operator, page
from hullwork.config import get_settings
from hullwork.db import make_engine
from hullwork.models import Base, Project
from hullwork.security import generate_token, hash_token

#: Every view on the operator's path. The point of the item is that none of them is a wall.
VIEWS = ("", "items", "instance", "projects", "doctor", "config", "projects/shop")


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path}/door.db"
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


@pytest.fixture
def client() -> TestClient:
    from hullwork.main import app

    return TestClient(app, follow_redirects=False)


# --- no view is a wall ---------------------------------------------------------------------------


@pytest.mark.parametrize("view", VIEWS)
def test_every_view_offers_the_way_in(db: Session, client: TestClient, view: str) -> None:
    """**The whole item.** A person arriving at any of these with no session gets the login, not a
    JSON `404` — which is what a browser shows as a bare error page."""
    operator.set_password(db, "correct horse")
    db.commit()

    shown = client.get(f"/page/me/{view}")

    assert shown.status_code == 200, view
    assert "current-password" in shown.text, f"/page/me/{view} is a wall"


def test_the_login_it_offers_still_says_nothing_about_the_instance(
    db: Session, client: TestClient
) -> None:
    """Item 204's rule, which this must not undo: the one page a prober can reach discloses that
    this host has a login and nothing else — not a name, not a version, not a count. A version tells
    somebody which advisories to go and read."""
    operator.set_password(db, "correct horse")
    db.commit()

    # **Without the stylesheet**, which is inlined and whose comments cite WCAG 2.5.8 and CSS
    # escapes — the first version of this failed on a rule number in a comment and called it a
    # version. What is being asserted is what a reader sees, not what the bytes contain.
    shown = re.sub(r"<style.*?</style>", "", client.get("/page/me/config").text, flags=re.S)

    assert "hullwork" not in shown.lower()
    assert not re.search(r"\d+\.\d+\.\d+", shown), "a version reached the door"


def test_an_instance_with_no_password_still_refuses(db: Session, client: TestClient) -> None:
    """**Offering a login where there is none would be a lie**, and a door that says *sign in* on an
    instance with no password sends somebody looking for a credential that does not exist. With
    nothing to sign in to, the refusal is the honest answer and stays a `404`."""
    for view in ("instance", "projects", "doctor"):
        assert client.get(f"/page/me/{view}").status_code == 404, view


def test_a_read_link_is_still_told_nothing(db: Session, client: TestClient) -> None:
    """DR-0021 intact. The `404` is right where it is right: a token is a secret, and a distinct
    refusal on one path and not another tells its holder which doors exist behind it."""
    operator.set_password(db, "correct horse")
    minted = generate_token()
    page.issue(db, hash_token(minted))
    db.commit()

    assert client.get(f"/page/{minted}/doctor").status_code == 404
    assert client.get(f"/page/{minted}/config").status_code == 404


def test_a_link_that_stopped_working_is_not_an_invitation(
    db: Session, client: TestClient
) -> None:
    """**A rotated link must not look like a door.** The colleague holding yesterday's URL is not
    somebody who should sign in — they have no password and never did — and answering them with a
    login sends them to ask for one. It stays a `404`, which is what a wrong path is.

    Written because a mutation escaped: the read-link test above uses a *valid* token, so it never
    reaches this decision at all."""
    operator.set_password(db, "correct horse")
    stale = generate_token()
    page.issue(db, hash_token(generate_token()))  # somebody rotated it
    db.commit()

    for view in ("", "instance", "doctor"):
        shown = client.get(f"/page/{stale}/{view}")

        assert shown.status_code == 404, view
        assert "current-password" not in shown.text, f"a stale link is offered a login at {view!r}"


# --- and it takes you where you were going -------------------------------------------------------


def test_signing_in_lands_where_you_were_going(db: Session, client: TestClient) -> None:
    """Twelve hours is the session, and an instance reached by bookmark is reached at a view. Being
    returned to the front door every time means finding it again by hand."""
    operator.set_password(db, "correct horse")
    db.commit()

    offered = client.get("/page/me/doctor").text
    field = re.search(r'name="going_to" value="([^"]*)"', offered)

    assert field is not None, "the login forgot where it was asked from"

    arrived = client.post(
        "/page/me/login", data={"password": "correct horse", "going_to": field.group(1)}
    )

    assert arrived.headers["location"] == "/page/me/doctor"


@pytest.mark.parametrize(
    "asked",
    [
        "https://evil.example/x",
        "//evil.example",
        "/page/me/../../etc/passwd",
        "/page/me/config/../../elsewhere",
        "instance;rm -rf /",
        "/page/OTHER-TOKEN/instance",
    ],
)
def test_it_will_not_be_pointed_anywhere_else(asked: str) -> None:
    """**An open redirect is how a sign-in form becomes somebody else's.** A literal list rather
    than a pattern, because `../`, `//host` and `%2e%2e` are each something a pattern written in a
    hurry lets through."""
    assert page.where_it_may_land(asked) == ""


def test_it_does_take_you_to_a_project_of_its_own(db: Session, client: TestClient) -> None:
    """The one shape beyond the flat list, because it is where half the work is."""
    assert page.where_it_may_land("/page/me/projects/shop") == "projects/shop"
    assert page.where_it_may_land("/page/me/projects/shop/../../x") == ""
