"""The one control that creates something, above the list rather than under it. Item 214, DR-0023.

The decision read four things off GlitchTip and item 212 built three. This is the fourth: *the
primary action is a button, top right, always* — where Hullwork's was a form at the bottom of the
second page, beneath every project the instance already had.

The hazard of putting a form behind a disclosure is that the answer to submitting it lands where the
reader cannot see, so most of what is asserted here is that refusals and one-time secrets arrive
with the drawer open.

Every test verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from hullwork import page
from hullwork.config import Settings, get_settings
from hullwork.db import make_engine
from hullwork.models import Base, Project
from hullwork.page import Acting
from hullwork.security import generate_token, hash_token

SIGNED_IN = Acting(csrf="c", offered=True)
A_READER = Acting(csrf=None, offered=False)


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path}/action.db"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    yield sessionmaker(bind=engine)()
    get_settings.cache_clear()


@pytest.fixture
def client() -> TestClient:
    from hullwork.main import app

    return TestClient(app)


def _a_project(db: Session) -> None:
    db.add(
        Project(
            slug="shop", forge="forgejo", repo="acme/shop",
            webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
        )
    )
    db.commit()


def _drawer(html: str) -> str:
    """The primary action's opening tag, and only it.

    **Not `<details[^>]*>` on the whole page**: the first version matched whichever disclosure came
    first in the document, and asserted `startswith("<details open")` on an attribute order nobody
    promised. A test that depends on the order attributes are written in is a test that fails on a
    change that means nothing.
    """
    found = re.search(r'<details class="primary"[^>]*>', html)
    assert found is not None, "the primary action is not a details element"
    return found.group(0)


def _where(html: str, needle: str) -> int:
    found = html.find(needle)
    assert found >= 0, f"{needle!r} is not on the page"
    return found


# --- where it is ----------------------------------------------------------------------------------


def test_the_action_comes_before_the_list(db: Session) -> None:
    """**Position in the document is the whole item.** The form was last: to register the second
    project you scrolled past the first one. Asserted as an order rather than as a class name,
    because a button that is markup-first and visually last would pass a shallower test."""
    _a_project(db)

    shown = page.projects(db, Settings(), acting=SIGNED_IN)

    assert _where(shown, "Connect a project") < _where(shown, 'class="name"')


def test_it_is_one_control_that_needs_no_script(db: Session) -> None:
    """No script on this page, ever — so the drawer is a `<details>`, the same mechanism the login
    uses. A control that needs JavaScript to open is a control that does not open."""
    _a_project(db)

    shown = page.projects(db, Settings(), acting=SIGNED_IN)

    assert "<script" not in shown
    assert "<summary>Connect a project</summary>" in shown
    assert shown.count('action="projects"') == 1, "one form, and therefore one route"


def test_a_read_link_is_offered_nothing(db: Session, client: TestClient) -> None:
    """DR-0021: the URL reads, the password acts. A create button that 404s on submit is worse than
    no button — it offers, and then refuses."""
    _a_project(db)
    minted = generate_token()
    page.issue(db, hash_token(minted))
    db.commit()

    shown = client.get(f"/page/{minted}/projects").text

    assert "Connect a project" not in shown
    assert "<form" not in shown


# --- what happens after you use it --------------------------------------------------------------


def test_a_refusal_arrives_with_the_drawer_open(db: Session) -> None:
    """**The hazard this item introduces, closed in the same item.** A form behind a disclosure
    submits, refuses, and re-renders closed — so the reader is returned to a button, with the reason
    they were refused hidden inside it. That reads as a page that ignored them."""
    _a_project(db)

    shown = page.projects(db, Settings(), acting=SIGNED_IN, refused="no manifest at hullwork.yml")

    assert "no manifest at hullwork.yml" in shown
    assert _drawer(shown) is not None, "no drawer at all"
    assert " open" in _drawer(shown), "the drawer closed over the refusal"


def test_the_one_time_secret_arrives_with_the_drawer_open(db: Session) -> None:
    """A webhook secret is shown once and never again. Rendering it behind a closed drawer would
    lose it for good, which is a data-loss bug wearing a layout bug's clothes."""
    made = SimpleNamespace(project=SimpleNamespace(slug="shop"), token="tok-shown-once")  # noqa: S106

    shown = page.projects(db, Settings(), acting=SIGNED_IN, just_made=made)

    assert "tok-shown-once" in shown
    assert " open" in _drawer(shown), "the drawer closed over a secret shown once"


# --- the empty instance -------------------------------------------------------------------------


def test_the_empty_front_door_offers_the_action(db: Session) -> None:
    """*No items yet. Nothing has arrived from the error tracker on this instance* is true and
    useless: the reason nothing arrived is that nothing is connected, and the thing to do about it
    was two clicks and a scroll away."""
    landing = page.items(
        db, acting=SIGNED_IN, here="./", settings=Settings(), front=True
    )

    assert 'href="projects"' in landing
    assert "Connect a project" in landing, "the empty state describes the emptiness and no more"


def test_the_empty_front_door_offers_a_reader_nothing_to_press(db: Session) -> None:
    """Same line as everywhere else. An empty instance is not a reason to hand a read link a
    control it cannot use."""
    landing = page.items(db, acting=A_READER, here="./", settings=Settings(), front=True)

    assert "Connect a project" not in landing
