"""Two buttons on a page whose URL is a credential. Item 166.

The page was read-only for two versions and the argument for keeping it that way is written into
`approve` itself: *"an approval endpoint would be a permanent attack surface for something done by
one person a handful of times."* That argument was answered rather than ignored — the ground it
stood on ("the operator already has the host") stopped being true — so what these tests assert is
the thing that makes the reversal safe: **the read token gains no authority at all.**

Every test below is one sentence of the threat model:

* the URL is a bearer credential, so it must not be able to spend money;
* an instance nobody has given a key to must be exactly what it was before this item;
* and nothing may answer differently depending on whether a key exists, because that answer is
  itself worth having.
"""

from __future__ import annotations

import io
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from hullwork import operator, page
from hullwork.config import get_settings
from hullwork.db import make_engine, make_session_factory
from hullwork.models import Item, ItemKind, ItemState, Lane, Project
from hullwork.security import generate_token, hash_token

ROOT = Path(__file__).resolve().parents[1]

#: The read credential. Long enough to be real, and fixed so the tests can name URLs.
TOKEN = "a-page-token-long-enough-to-be-real-x"  # noqa: S105


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    """A migrated database with one project and one amber item waiting for a decision."""
    url = f"sqlite:///{tmp_path / 'acted-on.db'}"
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.setenv("HULLWORK_BASE_URL", "https://hullwork.example")
    get_settings.cache_clear()

    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.cmd_opts = None
    command.upgrade(cfg, "head")

    with make_session_factory(make_engine(url))() as session:
        session.add(
            Project(
                slug="p",
                forge="forgejo",
                repo="easybyte/p",
                webhook_secret_hash="not-a-real-hash",  # noqa: S106 - fixture
                manifest={},
            )
        )
        session.commit()
        session.add(
            Item(
                project_id=1,
                fingerprint="fp-1",
                state=ItemState.WAITING_APPROVAL,
                lane=Lane.AMBER,
                kind=ItemKind.BUG,
                title="OperationalError: locked",
            )
        )
        session.commit()
        page.issue(session, hash_token(TOKEN))
        yield session
    get_settings.cache_clear()


@pytest.fixture
def client() -> TestClient:
    from hullwork.main import app

    # Redirects are the subject of two tests below, so they are never followed automatically.
    return TestClient(app, follow_redirects=False)


def _key(db: Session) -> str:
    """Give this instance an operator key, the way the operator does."""
    return operator.issue_key(db)


def _sign_in(db: Session, client: TestClient) -> str:
    """Log in and return the CSRF token the page would put in its forms."""
    key = _key(db)
    answered = client.post(f"/page/{TOKEN}/login", data={"key": key})
    assert answered.status_code == 303
    csrf = operator.acting(db, client.cookies.get(operator.COOKIE))
    assert csrf is not None
    return csrf


def _state(db: Session) -> ItemState:
    db.expire_all()
    found = db.get(Item, 1)
    assert found is not None
    return found.state


# --- an instance nobody gave a key to -----------------------------------------------------------


def test_with_no_operator_key_the_page_says_it_is_read_only(
    db: Session, client: TestClient
) -> None:
    """**The acceptance criterion that protects everybody who did not ask for this.** An upgrade
    that added buttons to a running instance would be this item changing somebody else's security
    posture on their behalf."""
    front = client.get(f"/page/{TOKEN}/").text
    item_page = client.get(f"/page/{TOKEN}/items/1").text

    assert "Nothing here changes anything" in front
    assert "read-only" in front
    assert "Sign in to decide" not in front
    assert "Sign in to decide" not in item_page
    assert "<button" not in item_page.replace('<button type="submit">Sign in', "")


def test_with_no_operator_key_the_deciding_routes_are_not_there(
    db: Session, client: TestClient
) -> None:
    """`404`, and the **same** `404` an unknown path gets — not `401` and not `403`.

    A `403` would say *this instance can be acted on and you are not allowed*, which is a fact worth
    withholding from somebody who has found a saved link.
    """
    unknown = client.get("/nope")
    approved = client.post(f"/page/{TOKEN}/items/1/approve", data={"csrf": "anything"})

    assert approved.status_code == unknown.status_code == 404
    assert approved.json() == unknown.json()
    assert _state(db) is ItemState.WAITING_APPROVAL


def test_the_item_page_offers_the_command_when_there_is_no_key(
    db: Session, client: TestClient
) -> None:
    """It says how to act rather than pretending nothing can be done — the complaint that started
    this item was *"¿y ahora qué?"*, and the answer without a key is a command."""
    rendered = client.get(f"/page/{TOKEN}/items/1").text

    assert "hullwork approve p 1" in rendered
    assert "hullwork operator-key" in rendered


# --- a key, but no session ----------------------------------------------------------------------


def test_a_key_offers_a_login_and_still_no_buttons(db: Session, client: TestClient) -> None:
    _key(db)

    front = client.get(f"/page/{TOKEN}/").text
    item_page = client.get(f"/page/{TOKEN}/items/1").text

    assert "Sign in to decide" in front
    assert "Sign in to decide" in item_page
    assert "Let the agent try it" not in item_page


def test_the_read_token_alone_cannot_decide_anything(db: Session, client: TestClient) -> None:
    """**The whole point of the two-credential split, stated as a test.** Somebody holding the URL —
    a saved page, a screenshot, a forwarded link — posts the form and nothing happens."""
    _key(db)

    approved = client.post(f"/page/{TOKEN}/items/1/approve", data={"csrf": "guessed"})

    assert approved.status_code == 404
    assert _state(db) is ItemState.WAITING_APPROVAL


def test_a_wrong_key_answers_exactly_like_the_right_one(db: Session, client: TestClient) -> None:
    """No error page, because an error page is an oracle: an attacker with the read link would
    otherwise have a place to guess keys and be told when one is wrong."""
    _key(db)

    wrong = client.post(f"/page/{TOKEN}/login", data={"key": "not-the-key"})

    assert wrong.status_code == 303
    assert operator.COOKIE not in wrong.cookies
    assert operator.acting(db, None) is None


# --- a session ----------------------------------------------------------------------------------


def test_signing_in_shows_the_two_buttons_and_nothing_else(db: Session, client: TestClient) -> None:
    csrf = _sign_in(db, client)

    rendered = client.get(f"/page/{TOKEN}/items/1").text

    assert "Let the agent try it" in rendered
    assert "I will take this one" in rendered
    assert csrf in rendered, "the form has to carry the token the server will check"
    assert "Nothing here changes anything" not in client.get(f"/page/{TOKEN}/").text


def test_approving_from_the_page_makes_the_item_ready(db: Session, client: TestClient) -> None:
    csrf = _sign_in(db, client)

    answered = client.post(f"/page/{TOKEN}/items/1/approve", data={"csrf": csrf})

    assert answered.status_code == 303
    assert answered.headers["location"].endswith("/items/1")
    assert _state(db) is ItemState.READY


def test_handing_it_to_a_human_is_human_only_and_not_rejected(
    db: Session, client: TestClient
) -> None:
    """**`rejected` would have corrupted a number.** That state means a reviewer closed a pull
    request and it feeds `counted.rejected` by reason; a decision about whether to *attempt* has no
    business in the tally that counts *review*."""
    csrf = _sign_in(db, client)

    answered = client.post(f"/page/{TOKEN}/items/1/human", data={"csrf": csrf})

    assert answered.status_code == 303
    assert _state(db) is ItemState.HUMAN_ONLY


def test_a_wrong_csrf_token_changes_nothing(db: Session, client: TestClient) -> None:
    """`403` here rather than `404`: this is reachable only by something already holding a valid
    session cookie, so there is nothing left to hide from it."""
    _sign_in(db, client)

    answered = client.post(f"/page/{TOKEN}/items/1/approve", data={"csrf": generate_token()})

    assert answered.status_code == 403
    assert _state(db) is ItemState.WAITING_APPROVAL


def test_a_missing_csrf_token_changes_nothing(db: Session, client: TestClient) -> None:
    _sign_in(db, client)

    answered = client.post(f"/page/{TOKEN}/items/1/approve", data={})

    assert answered.status_code == 403
    assert _state(db) is ItemState.WAITING_APPROVAL


def test_deciding_twice_refuses_the_second_time(db: Session, client: TestClient) -> None:
    """The state machine is the last guard, and it is the one that cannot be forgotten: a double
    submit — a refresh, an impatient click — must not buy two attempts."""
    csrf = _sign_in(db, client)

    first = client.post(f"/page/{TOKEN}/items/1/approve", data={"csrf": csrf})
    second = client.post(f"/page/{TOKEN}/items/1/approve", data={"csrf": csrf})

    assert first.status_code == 303
    assert second.status_code == 409
    assert _state(db) is ItemState.READY


def test_the_cookie_is_httponly_and_samesite_strict(db: Session, client: TestClient) -> None:
    """`SameSite=Strict` is the first half of the CSRF defence: a cross-site POST does not carry it.

    `Secure` is **not** asserted, and that is deliberate: it is read off the request scheme, so the
    test client's `http` correctly produces a cookie without it. Hardcoding it on would have made
    the login silently impossible on the plain-HTTP tailnet deployment this runs on.
    """
    key = _key(db)

    answered = client.post(f"/page/{TOKEN}/login", data={"key": key})

    header = answered.headers["set-cookie"].lower()
    assert "httponly" in header
    assert "samesite=strict" in header
    assert f"path={page.PREFIX}" in header


def test_rotating_the_key_ends_the_session_that_was_open(db: Session, client: TestClient) -> None:
    """Measured rather than asserted in prose: the reason to rotate is that the old key may be in
    somebody else's hands, and a live session issued by it would outlive the rotation."""
    csrf = _sign_in(db, client)
    assert client.post(f"/page/{TOKEN}/items/1/approve", data={"csrf": csrf}).status_code == 303

    operator.issue_key(db)

    # Asserted on the front page rather than on the item: the approval above moved it out of
    # `waiting-approval`, and the login only appears beside a decision that is still open.
    after = client.get(f"/page/{TOKEN}/").text
    assert "Sign in to decide" in after
    assert "Nothing here changes anything" in after, "no session, so it is read-only again"


def test_signing_out_ends_it_too(db: Session, client: TestClient) -> None:
    csrf = _sign_in(db, client)

    client.post(f"/page/{TOKEN}/logout", data={"csrf": csrf})

    assert "Sign in to decide" in client.get(f"/page/{TOKEN}/").text


# --- the three complaints that started the item -------------------------------------------------


def test_the_board_counts_lead_to_the_items_they_counted(db: Session, client: TestClient) -> None:
    """*"Waiting on you 2 → ¿y ahora qué?"* — a count with no name behind it was a dead end."""
    front = client.get(f"/page/{TOKEN}/").text

    assert 'href="items?in=waiting"' in front
    listed = client.get(f"/page/{TOKEN}/items?in=waiting").text
    assert "items/1" in listed
    assert "in=waiting" not in listed or "All items" in listed


def test_a_zero_count_is_not_a_link(db: Session, client: TestClient) -> None:
    """A link that lands on "nothing here" teaches a reader that the page is broken."""
    front = client.get(f"/page/{TOKEN}/").text

    assert 'href="items?in=working"' not in front


def test_the_item_says_what_it_is_waiting_for_without_hedging(
    db: Session, client: TestClient
) -> None:
    """The line this replaces was *"Either this item is waiting for the dispatcher, or its lane says
    a human takes it"* — on an item whose state answers that question exactly."""
    rendered = client.get(f"/page/{TOKEN}/items/1").text

    assert "Waiting for" in rendered
    assert "Either this item is waiting" not in rendered


def test_an_item_whose_project_is_disabled_says_it_will_never_run(
    db: Session, client: TestClient
) -> None:
    """**Measured on the live instance on 2026-08-07.** `simplecheck` was disabled, item 15 stayed
    `ready`, and the board went on counting it under *Queued* with a climbing age while `work.py`
    would never look at it again."""
    found = db.get(Item, 1)
    assert found is not None
    found.state = ItemState.READY
    project = db.get(Project, 1)
    assert project is not None
    project.active = False
    db.commit()

    rendered = client.get(f"/page/{TOKEN}/items/1").text
    listed = client.get(f"/page/{TOKEN}/items").text

    assert "is disabled, so the dispatcher will never pick this up" in rendered
    assert "never" in listed


def test_an_unknown_filter_shows_everything_rather_than_nothing(
    db: Session, client: TestClient
) -> None:
    """It arrives from a URL, and a typo in a hand-edited address should not read as an empty
    instance."""
    listed = client.get(f"/page/{TOKEN}/items?in=nonsense").text

    assert "items/1" in listed


# --- the CLI side -------------------------------------------------------------------------------


def test_the_command_refuses_to_replace_a_key_without_rotate(db: Session) -> None:
    """The failure it prevents: a second person running this to "get in" locks out the first, and it
    reads as the buttons being broken rather than as a key having changed."""
    from hullwork.cli import main as cli_main

    out = io.StringIO()
    assert cli_main(["operator-key"], out=out) == 0
    assert "shown once" in out.getvalue()

    # `main` turns a `CommandError` into an exit code and a line on stderr rather than a traceback,
    # so the refusal is asserted where an operator would see it.
    again = io.StringIO()
    assert cli_main(["operator-key"], out=again) != 0
    assert again.getvalue() == "", "the refusal belongs on stderr, not in the output"


def test_the_key_is_printed_once_and_only_its_hash_is_stored(db: Session) -> None:
    from hullwork.cli import main as cli_main
    from hullwork.models import OperatorKey

    out = io.StringIO()
    assert cli_main(["operator-key"], out=out) == 0

    printed = [line.strip() for line in out.getvalue().splitlines() if line.strip()]
    key = next(line for line in printed if len(line) > 40 and " " not in line)

    db.expire_all()
    stored = db.get(OperatorKey, 1)
    assert stored is not None
    assert stored.key_hash == hash_token(key)
    assert key not in stored.key_hash
