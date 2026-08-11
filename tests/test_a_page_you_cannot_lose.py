"""Reading your own instance without a credential you can lose. Item 204, DR-0021.

The operator, handed the page's URL and told it could not be shown again: *the token thing is
ridiculous. It is one more piece of friction for users.*

The person who runs `page-token` reached it through `docker exec` on the host — they can already
read the database, the environment file and the Docker socket. Withholding their own page's URL
from them protects nothing they do not have. So the password reads, and the token keeps the job it
is good at: handing reading to somebody with no account.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from hullwork import page
from hullwork.page import Acting
from hullwork.security import generate_token, hash_token

A_SESSION = Acting(csrf="c", offered=True)
NO_SESSION = Acting(csrf=None, offered=True)
NO_PASSWORD = Acting(csrf=None, offered=False)


def _a_token(session: Session) -> str:
    minted = generate_token()
    page.issue(session, hash_token(minted))
    session.commit()
    return minted


# --- the door that needs no token -----------------------------------------------------------------


def test_a_session_reads_without_a_token(session: Session) -> None:
    """The whole item. Nothing to lose, nothing to rotate, nothing to hand back to a colleague."""
    assert page.opens(session, page.MINE, acting=A_SESSION)


def test_no_session_does_not_read(session: Session) -> None:
    """The password has to buy something, or this is a page with no door at all."""
    assert not page.opens(session, page.MINE, acting=NO_SESSION)


def test_with_no_password_configured_it_is_a_stranger_like_any_other(session: Session) -> None:
    """**The property this must not spend.** Everything without a valid token answers `404`,
    including a wrong one, so the page cannot be found by probing. A login form at a fixed path
    would end that — so the door exists only where somebody deliberately set a password.
    """
    assert not page.opens(session, page.MINE, acting=NO_PASSWORD)


def test_the_reserved_word_cannot_be_a_real_token(session: Session) -> None:
    """A minted token that happened to equal the reserved word would open the page for anybody with
    a session, and close it for the person holding the link. Asserted against how tokens are made,
    not against a list of things somebody thought of."""
    minted = {generate_token() for _ in range(200)}

    assert page.MINE not in minted
    assert len(page.MINE) < min(len(one) for one in minted)


def test_no_password_configured_offers_no_login(session: Session) -> None:
    """**The property DR-0021 promised not to spend, and the one defect the mutation caught me on.**

    Everything without a valid token answers `404`, including a wrong one, so the page cannot be
    found by probing. A login form at a fixed path ends that — so it exists only where somebody
    deliberately set a password, and `offered` is that opt-in. Removing it from this function failed
    nothing: every other test here asks `opens`, and this is the other question.
    """
    del session

    assert not page.offers_a_login(page.MINE, NO_PASSWORD)


def test_a_password_and_no_session_is_offered_the_login(session: Session) -> None:
    """Or the door that replaces the token has no handle: there would be no way to acquire the
    session that reads."""
    del session

    assert page.offers_a_login(page.MINE, NO_SESSION)


def test_a_login_is_never_offered_on_a_token_path(session: Session) -> None:
    """A wrong token stays a `404`. Offering a login there would tell a prober that this path is
    real, which is the whole thing the `404` withholds."""
    del session

    assert not page.offers_a_login("not-the-one", NO_SESSION)


# --- everything the token did, it still does ------------------------------------------------------


def test_a_real_token_still_opens_it(session: Session) -> None:
    """Somebody holding a link handed to them keeps it. That is what the token is for."""
    minted = _a_token(session)

    assert page.opens(session, minted, acting=NO_SESSION)


def test_a_wrong_token_is_still_refused(session: Session) -> None:
    _a_token(session)

    assert not page.opens(session, "not-the-one", acting=NO_SESSION)


def test_a_wrong_token_is_refused_even_with_a_session(session: Session) -> None:
    """A session is authority for `MINE` and for nothing else. Otherwise the reserved word would be
    decoration and any path would open with a cookie."""
    _a_token(session)

    assert not page.opens(session, "not-the-one", acting=A_SESSION)


def test_reading_with_a_session_is_not_permission_to_act(session: Session) -> None:
    """Item 166's split, unchanged: what may read and what may act are two questions, and this item
    only answers the first. The renderer receives `Acting` and decides the second itself."""
    assert page.opens(session, page.MINE, acting=A_SESSION)
    assert A_SESSION.csrf is not None, "acting is decided by the renderer, from this, not by opens"


def test_the_login_page_says_nothing_about_the_instance() -> None:
    """The one path that is not a `404`, so it is the one that must disclose least. A version, a
    name or a count beside the password would answer questions for somebody who has not signed in —
    and the whole reason this door may exist is that it discloses exactly one thing.
    **Measured on the visible text, not on the document.** The first version of this searched the
    whole HTML and tripped on a word inside a CSS comment — and while fixing that it found the real
    leak, which the wrong method had buried: the shared chrome put `▚ hullwork` and
    `Hullwork 0.1.0a8` on the page. A version tells a prober which advisories to go and read.
    """
    from re import DOTALL, sub

    said = page.just_the_login(NO_SESSION)
    without_style = sub(r"<style.*?</style>", "", said, flags=DOTALL)
    visible = " ".join(sub(r"<[^>]+>", " ", without_style).split())

    assert "password" in said and "<form" in said
    for leak in ("hullwork", "0.1.0", "item", "project"):
        assert leak not in visible.lower(), f"{leak} in: {visible}"


def test_a_locked_out_login_offers_no_form() -> None:
    """`_login` already refuses after too many wrong passwords, and this door must not be a way
    around that."""
    said = page.just_the_login(Acting(csrf=None, offered=True, locked_minutes=3))

    assert "<form" not in said


# --- one gate
# --------------------------------------------------------------------------------------


def test_there_is_one_gate_and_not_ten() -> None:
    """**Asserted per route, not by counting.** Ten routes each deciding this would be ten
    implementations of one question, which is what items 193, 194, 200 and 203 each cost a day to.

    The first version of this compared two call-shape counts, which was a proxy for the property and
    stopped being one the moment a second legitimate gate existed — the login needs a different
    question from every other route, and a third helper answers *may this be told there is a login*.
    What matters is that a **route** never asks: the helpers do, and a fourth route cannot bring a
    fourth opinion with it.
    """
    from pathlib import Path

    source = Path(page.__file__).parent.joinpath("main.py").read_text(encoding="utf-8")
    routes = [block for block in source.split("\ndef ") if block.startswith("page_")]

    assert len(routes) >= 6, "this test is watching routes that no longer exist"
    for route in routes:
        assert "page.opens(" not in route, route.split("(")[0]
    assert "MINE" not in source, "the reserved word is the gate's business, not each route's"
