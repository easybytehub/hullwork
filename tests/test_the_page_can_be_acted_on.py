"""Two buttons on a page whose URL is a credential. Items 166, 167 and 168.

The page was read-only for two versions and the argument for keeping it that way is written into
`approve` itself: *"an approval endpoint would be a permanent attack surface for something done by
one person a handful of times."* That argument was answered rather than ignored — the ground it
stood on ("the operator already has the host") stopped being true — so what these tests assert is
the thing that makes the reversal safe: **the read token gains no authority at all.**

**The credential behind the buttons changed twice** and these assertions did not: a stored key to
paste (166), a one-time link from the CLI (167), and now a password a browser can fill (168). The
first two were secure and unusable; each rewrite of this file kept every property and changed only
how the session is obtained, which is the point of writing them as threat-model sentences rather
than as clicks:

* the URL is a bearer credential, so it must not be able to spend money;
* a request with no session sees and does exactly what it did before any of this;
* nothing answers differently depending on whether a credential exists — except a lockout, which is
  reported on purpose, because an operator who is locked out needs to know.
"""

from __future__ import annotations

import io
import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from hullwork import operator, page
from hullwork.config import get_settings
from hullwork.db import make_engine, make_session_factory
from hullwork.models import Item, ItemKind, ItemState, Lane, OperatorPassword, Project
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


PASSWORD = "a-password-long-enough-to-pass"  # noqa: S105


def _set_password(db: Session) -> str:
    """Give this instance a password, the way `hullwork password` does."""
    operator.set_password(db, PASSWORD)
    return PASSWORD


def _sign_in(db: Session, client: TestClient) -> str:
    """Sign in and return the CSRF token the page will put in its forms."""
    _set_password(db)
    answered = client.post(f"/page/{TOKEN}/login", data={"password": PASSWORD})
    assert answered.status_code == 303
    csrf = operator.acting(db, client.cookies.get(operator.COOKIE))
    assert csrf is not None, "the right password should have signed this browser in"
    return csrf


def _state(db: Session) -> ItemState:
    db.expire_all()
    found = db.get(Item, 1)
    assert found is not None
    return found.state


# --- an instance nobody gave a key to -----------------------------------------------------------


def test_without_a_session_the_page_is_read_only(db: Session, client: TestClient) -> None:
    """**No session, no buttons, and the footer says which of the two it is.**

    Asserted directly rather than through "has a credential been configured", which is a question
    that has meant three different things in three items. What matters is what a request carrying
    only the read token can see and do.
    """
    front = client.get(f"/page/{TOKEN}/").text
    item_page = client.get(f"/page/{TOKEN}/items/1").text

    assert "read-only" in front
    assert "Sign out" not in front
    assert "Let the agent try it" not in item_page
    assert "<button" not in item_page


def test_without_a_session_the_deciding_routes_are_not_there(
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


def test_with_no_password_the_item_page_says_how_to_get_one(
    db: Session, client: TestClient
) -> None:
    """It says how to act rather than pretending nothing can be done — and it does not offer a login
    form on an instance that could not accept one, which would be a dead end."""
    rendered = client.get(f"/page/{TOKEN}/items/1").text

    assert "hullwork password" in rendered
    assert "hullwork approve p 1" in rendered
    assert 'name="password"' not in rendered


def test_with_a_password_the_item_page_offers_the_login(
    db: Session, client: TestClient
) -> None:
    """**The two attributes that are the whole feature.** A browser offers to save a password it
    sees submitted in a form and fills it in next time, which is what turns item 167's eight steps
    into two."""
    _set_password(db)

    rendered = client.get(f"/page/{TOKEN}/items/1").text

    assert 'autocomplete="current-password"' in rendered
    assert 'action="../login"' in rendered, "relative, and from an item that means one level up"
    assert "Let the agent try it" not in rendered


# --- a key, but no session ----------------------------------------------------------------------


def test_setting_a_password_signs_nobody_in(db: Session, client: TestClient) -> None:
    """Setting it is not using it: the authority arrives in the browser that submits it, and nowhere
    else."""
    _set_password(db)

    item_page = client.get(f"/page/{TOKEN}/items/1").text

    assert "Let the agent try it" not in item_page
    assert operator.acting(db, client.cookies.get(operator.COOKIE)) is None


def test_the_read_token_alone_cannot_decide_anything(db: Session, client: TestClient) -> None:
    """**The whole point of the two-credential split, stated as a test.** Somebody holding the URL —
    a saved page, a screenshot, a forwarded link — posts the form and nothing happens."""
    _set_password(db)

    approved = client.post(f"/page/{TOKEN}/items/1/approve", data={"csrf": "guessed"})

    assert approved.status_code == 404
    assert _state(db) is ItemState.WAITING_APPROVAL


def test_a_wrong_password_answers_exactly_like_the_right_one(
    db: Session, client: TestClient
) -> None:
    """No error page, because an error page is an oracle: somebody with the read link would then
    have a place to guess and be told when a guess was wrong."""
    _set_password(db)

    wrong = client.post(f"/page/{TOKEN}/login", data={"password": "not-it-at-all"})

    assert wrong.status_code == 303
    assert operator.COOKIE not in wrong.cookies
    assert operator.acting(db, None) is None


def test_ten_wrong_passwords_close_the_door_for_fifteen_minutes(
    db: Session, client: TestClient
) -> None:
    """37 ms per attempt is most of the answer to online guessing; this is the rest. A lockout turns
    twenty-seven guesses a second into four an hour."""
    _set_password(db)

    for _ in range(operator.MAX_FAILURES):
        client.post(f"/page/{TOKEN}/login", data={"password": "wrong"})

    assert operator.locked_for(db) is not None
    refused = client.post(f"/page/{TOKEN}/login", data={"password": PASSWORD})
    assert operator.acting(db, client.cookies.get(operator.COOKIE)) is None, (
        "the right password does not open a locked instance"
    )
    assert refused.status_code == 303

    front = client.get(f"/page/{TOKEN}/").text
    assert "Too many wrong passwords" in front, "a lockout is reported; a wrong guess is not"


def test_the_lockout_lifts_on_its_own(db: Session, client: TestClient) -> None:
    """It is a lockout and not a lock: nothing has to be run on the host to recover from a bad
    morning."""
    _set_password(db)
    for _ in range(operator.MAX_FAILURES):
        client.post(f"/page/{TOKEN}/login", data={"password": "wrong"})

    row = db.scalars(select(OperatorPassword)).one()
    row.locked_until = datetime.now(UTC) - timedelta(seconds=1)
    db.commit()

    client.post(f"/page/{TOKEN}/login", data={"password": PASSWORD})

    assert operator.acting(db, client.cookies.get(operator.COOKIE)) is not None


def test_the_cost_parameters_travel_with_the_password(db: Session) -> None:
    """Stored per row so raising the default later keeps existing passwords verifiable, rather than
    locking their owners out of the instance the day somebody tunes a constant."""
    _set_password(db)

    row = db.scalars(select(OperatorPassword)).one()
    assert (row.n, row.r, row.p) == (operator.COST["n"], operator.COST["r"], operator.COST["p"])
    assert row.key != PASSWORD
    assert len(row.salt) == 32


# --- a session ----------------------------------------------------------------------------------


def test_signing_in_shows_the_two_buttons_and_nothing_else(db: Session, client: TestClient) -> None:
    csrf = _sign_in(db, client)

    rendered = client.get(f"/page/{TOKEN}/items/1").text

    assert "Let the agent try it" in rendered
    assert "I will take this one" in rendered
    assert csrf in rendered, "the form has to carry the token the server will check"
    assert "Sign out" in client.get(f"/page/{TOKEN}/").text


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
    _set_password(db)

    answered = client.post(f"/page/{TOKEN}/login", data={"password": PASSWORD})

    header = answered.headers["set-cookie"].lower()
    assert "httponly" in header
    assert "samesite=strict" in header
    assert f"path={page.PREFIX}" in header


def test_ending_every_session_ends_the_one_that_was_open(db: Session, client: TestClient) -> None:
    """The lever for the morning a laptop goes missing, and the reason sessions are rows rather than
    signatures: ending them all is a `DELETE` rather than a key rotation that happens to log
    everybody out."""
    csrf = _sign_in(db, client)
    assert client.post(f"/page/{TOKEN}/items/1/approve", data={"csrf": csrf}).status_code == 303

    ended = operator.end_every_session(db)

    assert ended == 1
    assert operator.acting(db, client.cookies.get(operator.COOKIE)) is None
    assert "read-only" in client.get(f"/page/{TOKEN}/").text


def test_signing_out_ends_it_too(db: Session, client: TestClient) -> None:
    csrf = _sign_in(db, client)

    client.post(f"/page/{TOKEN}/logout", data={"csrf": csrf})

    assert operator.acting(db, client.cookies.get(operator.COOKIE)) is None
    assert "read-only" in client.get(f"/page/{TOKEN}/").text


# --- the three complaints that started the item -------------------------------------------------


def test_the_front_page_names_the_item_rather_than_counting_it(
    db: Session, client: TestClient
) -> None:
    """*"Waiting on you 2 → ¿y ahora qué?"*

    Item 166 answered this by making the count a link — one click instead of a dead end. **Item 167
    removed the click**: the item is on the front page, by name, with how long it has waited. Three
    lines cost less than the card that counted them.
    """
    front = client.get(f"/page/{TOKEN}/").text

    assert 'href="items/1"' in front, "the item itself, not a tally"
    assert "OperationalError: locked" in front
    assert "1 item needs a decision from you" in front
    assert 'class="lede mine"' in front, "and it is the only amber thing on the page"


def test_the_machine_strip_links_what_it_counts_and_a_zero_is_not_a_link(
    db: Session, client: TestClient
) -> None:
    """The demoted figures still lead somewhere when there is something behind them. A link that
    lands on "nothing here" teaches a reader that the page is broken, so zero is plain text."""
    found = db.get(Item, 1)
    assert found is not None
    found.state = ItemState.READY
    db.commit()

    front = client.get(f"/page/{TOKEN}/").text

    assert 'href="items?in=queued"' in front
    assert 'href="items?in=working"' not in front
    assert 'class="fig zero"' in front

    listed = client.get(f"/page/{TOKEN}/items?in=queued").text
    assert "items/1" in listed
    assert "All items" in listed


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


def test_the_command_reads_from_stdin_and_refuses_a_short_one(db: Session) -> None:
    """Twelve characters, because this is the only thing between a stranger who found the page URL
    and somebody's budget — and the browser is going to remember it, so length is nearly free."""
    import sys

    from hullwork.cli import main as cli_main

    class _In:
        def __init__(self, text: str) -> None:
            self.text = text

        def readline(self) -> str:
            return self.text

    sys.stdin = _In("short\n")
    try:
        assert cli_main(["password", "--stdin"], out=io.StringIO()) != 0
        assert not operator.configured(db)

        sys.stdin = _In("a-password-long-enough\n")
        out = io.StringIO()
        assert cli_main(["password", "--stdin"], out=out) == 0
        assert "Password set" in out.getvalue()
    finally:
        sys.stdin = sys.__stdin__
    db.expire_all()
    assert operator.configured(db)


def test_changing_the_password_ends_every_session(db: Session, client: TestClient) -> None:
    """The reason to change it is usually that the old one may be in somebody else's hands, and a
    session issued under it would otherwise outlive the change by a month."""
    _sign_in(db, client)
    assert operator.acting(db, client.cookies.get(operator.COOKIE)) is not None

    operator.set_password(db, "a-different-password-entirely")

    assert operator.acting(db, client.cookies.get(operator.COOKIE)) is None


def test_ending_every_session_says_how_many(db: Session, client: TestClient) -> None:
    from hullwork.cli import main as cli_main

    _sign_in(db, client)

    out = io.StringIO()
    assert cli_main(["password", "--end-sessions"], out=out) == 0
    assert "Ended 1 session(s)" in out.getvalue()
    assert operator.configured(db), "the password is unchanged"


def test_with_nothing_waiting_the_lede_says_so(db: Session, client: TestClient) -> None:
    """*Nothing needs you* is a real answer and deserves saying, rather than being left to be
    inferred from six zeroes — which is what the board it replaces asked a reader to do."""
    found = db.get(Item, 1)
    assert found is not None
    found.state = ItemState.DONE
    db.commit()

    front = client.get(f"/page/{TOKEN}/").text

    assert "Nothing needs you." in front
    assert 'class="lede calm"' in front
    assert "needs a decision from you" not in front


def test_nothing_disagreeing_is_one_line_and_still_says_it_ran(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**The docstring of `_disagreements` was right and item 167 kept it.** An absent section
    cannot tell a reader whether the check ran or was skipped, so the assertion stays — as a line
    rather than a heading and a full-width card.

    A model has to be pinned for nothing to disagree: an instance that cannot tell drift from normal
    is one of the three things this check is *for*, and the fixture does not pin one.
    """
    monkeypatch.setenv("HULLWORK_MODEL_NAME", "anthropic/claude-sonnet-5")
    get_settings.cache_clear()

    front = client.get(f"/page/{TOKEN}/").text

    assert "Nothing disagrees: the three checks ran and found nothing." in front
    assert "<h2>What does not add up</h2>" not in front


def test_the_evaluator_material_is_folded_away(db: Session, client: TestClient) -> None:
    """the interface document promised the daily reader never pays for the
    evaluator's questions, and the configuration table was starting in the second half of the first
    screen anyway."""
    front = client.get(f"/page/{TOKEN}/").text

    assert "<details><summary>How this instance is configured</summary>" in front
    assert front.index("class=\"lede") < front.index("How this instance is configured")


def test_no_microsecond_timestamp_is_rendered_for_a_human(
    db: Session, client: TestClient
) -> None:
    """`seen` printed `2026-08-05 09:57:43.866473+00:00` twice, at the weight of the lane and its
    reason. Nobody parses that, so nobody read the line it was in."""
    rendered = client.get(f"/page/{TOKEN}/items/1").text

    visible = re.sub(r"<time[^>]*>", "", rendered)
    assert ".866473" not in visible
    assert "+00:00" not in re.sub(r'(datetime|title)="[^"]*"', "", rendered)
    assert "<time datetime=" in rendered, "the exact value is still there, as a tooltip"


def test_there_is_a_way_in_when_nothing_is_waiting(db: Session, client: TestClient) -> None:
    """**Found by opening the deployed page on a calm day.** The login lived inside the list of
    decisions, so an instance with nothing waiting offered no way to sign in — and a lockout had
    nowhere to be reported, which made a working lockout look like a broken login."""
    _set_password(db)
    found = db.get(Item, 1)
    assert found is not None
    found.state = ItemState.DONE
    db.commit()

    front = client.get(f"/page/{TOKEN}/").text

    assert "Nothing needs you." in front, "the calm page, which is the case that was broken"
    assert "<summary>Sign in</summary>" in front
    assert 'autocomplete="current-password"' in front


def test_a_lockout_is_reported_even_with_nothing_waiting(
    db: Session, client: TestClient
) -> None:
    _set_password(db)
    found = db.get(Item, 1)
    assert found is not None
    found.state = ItemState.DONE
    db.commit()
    for _ in range(operator.MAX_FAILURES):
        client.post(f"/page/{TOKEN}/login", data={"password": "wrong"})

    front = client.get(f"/page/{TOKEN}/").text

    assert "Too many wrong passwords" in front
