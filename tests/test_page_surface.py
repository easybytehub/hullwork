"""The read-only page: the surface, not the content. Item 122.

The page lives on the **receiver**, and that is forced: the dispatcher listens on nothing, which is
what lets it hold a credential that can push (DR-0009). So this is a new inbound route on the half
of Hullwork an error tracker has to be able to reach — a public address on a hosted tracker — and
the constitution asks for a threat model before such a surface ships (principle 7). The item carries
it; these tests are the parts of it that can be measured.

**What is not asserted here**: hostile *content* rendered through a view. The instance view shows
numbers and states, none of which a third party writes. The views that render an error's title and
its captured output arrive with item 123, and the assertion belongs there rather than being faked
here — what is asserted now is the escaping primitive itself, with the strings that motivate it.
"""

from __future__ import annotations

import io
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from hullwork import page
from hullwork.cli import CommandError
from hullwork.cli import main as cli_main
from hullwork.config import get_settings
from hullwork.db import make_engine
from hullwork.models import Base
from hullwork.security import generate_token, hash_token

TOKEN = "a-token-that-is-not-real-but-is-long-enough"  # noqa: S105


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path / 'page.db'}"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.setenv("HULLWORK_BASE_URL", "https://hullwork.example")
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    # **A value no prose could contain.** It used to be the word `ingest`, which made this test
    # fail the day the page explained the credential split in English — a false positive, and a
    # secret that is a dictionary word also makes the scrubber redact ordinary sentences.
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "tok-forge-must-never-render")
    get_settings.cache_clear()
    yield sessionmaker(bind=engine)()
    get_settings.cache_clear()


@pytest.fixture
def client() -> TestClient:
    from hullwork.main import app

    return TestClient(app)


def test_with_no_token_there_is_no_page(db: Session, client: TestClient) -> None:
    """**The default, and the reason this table starts empty.** An upgrade must not add a page to
    an instance that is reachable from the internet because its tracker has to reach it.
    """
    assert page.configured(db) is False

    unknown = client.get("/nope")
    asked = client.get(f"/page/{TOKEN}")

    assert asked.status_code == unknown.status_code == 404
    assert asked.json() == unknown.json(), "a different body would confirm the route exists"


def test_a_wrong_token_is_indistinguishable_from_an_unknown_path(
    db: Session, client: TestClient
) -> None:
    """`403` would be a yes. So would a friendlier message, which is how the first version of this
    gave itself away: `{"detail": "not found"}` next to Starlette's `{"detail": "Not Found"}`."""
    page.issue(db, hash_token(generate_token()))

    unknown = client.get("/also-nope")
    wrong = client.get(f"/page/{TOKEN}")

    assert wrong.status_code == unknown.status_code == 404
    assert wrong.json() == unknown.json()
    assert wrong.headers["content-type"] == unknown.headers["content-type"]


def test_the_right_token_opens_it(db: Session, client: TestClient) -> None:
    token = generate_token()
    page.issue(db, hash_token(token))

    answered = client.get(f"/page/{token}")

    assert answered.status_code == 200
    assert answered.headers["content-type"].startswith("text/html")
    # A structural landmark, not prose. This test is about the token opening the door, and asserting
    # on title text made it fail when item 143 renamed the page and again when item 167 restructured
    # it — a rename breaking a test about authentication. `class="lede"` is what only the instance
    # view renders, and it is the one element that survives a rewording.
    assert 'class="lede' in answered.text


def test_an_item_that_predates_the_clock_reads_as_not_recorded() -> None:
    """**Item 141's third criterion, which had the behaviour and not the assertion.**

    `state_since` is nullable and deliberately not backfilled: an item older than the column has no
    age, and inventing one from `updated_at` is precisely what the column exists to avoid —
    `updated_at` moves on an occurrence bump, so it answers "when was this touched" and never "how
    long has it been waiting".

    So `None` renders as *not recorded*. Never `0`, never *just now*, never an empty cell — each of
    which a reader would take as a measurement.
    """
    assert page._ago(None) == "not recorded"

    recent = datetime.now(UTC) - timedelta(seconds=5)
    assert page._ago(recent) == "just now", "and a real instant is still rendered"
    assert page._ago(datetime.now(UTC) - timedelta(hours=3)) != "not recorded"


def test_the_page_serves_no_markup_language_of_its_own(db: Session, client: TestClient) -> None:
    """A stranger evaluating the product on 2026-08-04 read four literal `**` on the served page.

    The credential-split paragraph is written in the same emphasised prose as every document in this
    repository; the page escaped it and served the markers. The one artefact designed to be shown to
    somebody who is **not** an operator was showing asterisks at them.

    Asserted on the whole body rather than on that paragraph, because the defect is a *class* — any
    constant added here is written in the same prose by the same hands — and on `<strong>` too:
    a fix that deleted the emphasis instead of rendering it would pass the first assertion alone.
    """
    token = generate_token()
    page.issue(db, hash_token(token))

    served = client.get(f"/page/{token}/instance").text

    assert "**" not in served, "the page is HTML; markdown emphasis in it is a literal asterisk"
    assert "<strong>listens</strong>" in served


def test_the_emphasis_helper_cannot_be_talked_into_markup() -> None:
    """The safety property of `_own_prose`, not its behaviour: escaping runs *before* substitution.

    `**` survives `html.escape` untouched, which is the whole reason the substitution is safe — by
    the time it runs every `<` is already `&lt;`, so no input can assemble a tag. Asserted directly
    because that ordering is invisible at the call site and a later edit could swap it without any
    other test noticing.
    """
    assert page._own_prose("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert page._own_prose("**<b>x</b>**") == "<strong>&lt;b&gt;x&lt;/b&gt;</strong>"


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        # The token is a path segment, so a browser following a link out would hand the credential
        # to whatever it links to. This one is the fix for a hole this design creates.
        ("referrer-policy", "no-referrer"),
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
    ],
)
def test_every_response_carries_its_headers(
    db: Session, client: TestClient, header: str, expected: str
) -> None:
    """One test per header, because a header nobody asserts is a header that disappears in a
    refactor and takes its reason with it."""
    token = generate_token()
    page.issue(db, hash_token(token))

    answered = client.get(f"/page/{token}")

    assert answered.headers[header] == expected


def test_the_policy_forbids_script_because_there_is_none(db: Session, client: TestClient) -> None:
    """`default-src 'none'` with no `script-src` at all: the page has no JavaScript, so the policy
    can be the strict one rather than the one that allows what we happen to ship."""
    token = generate_token()
    page.issue(db, hash_token(token))

    answered = client.get(f"/page/{token}")
    policy = answered.headers["content-security-policy"]

    assert "default-src 'none'" in policy
    assert "script-src" not in policy
    assert "frame-ancestors 'none'" in policy
    assert "<script" not in answered.text.lower()


#: The only routes under the page prefix that may change anything. Item 166 added them and this
#: tuple is the whole of the exception: everything else stays `GET`-only.
_MAY_POST = (
    # Three items, three shapes of this tuple, and it noticed each time: item 167 removed `/login`
    # for a one-time link outside the prefix, and item 168 put it back as a password form.
    f"{page.PREFIX}/{{token}}/login",
    f"{page.PREFIX}/{{token}}/logout",
    f"{page.PREFIX}/{{token}}/items/{{item_id}}/approve",
    f"{page.PREFIX}/{{token}}/items/{{item_id}}/human",
    # **Item 206, DR-0022**, and this list failing on the day it was written is the guard working.
    # Administration moves to the page deliberately: the receiver already holds every credential
    # registering a project needs — `forge_token` is *issue write and content read* — and it still
    # holds none that can push, which is the law this does not touch.
    f"{page.PREFIX}/{{token}}/projects",
    # Item 207: the rest of a project's life, on one route with an action rather than four names.
    #
    # **Item 250 moved it one segment deeper rather than adding four more.** A `POST` answers at the
    # URL its form posted to, so the document it answers with has to be the one that URL serves;
    # `feature` names that document and nothing else. At `projects/{slug}` three of its four
    # branches answered with a document written for somewhere else, and every relative link in
    # those answers — which is all of them — resolved from the wrong depth.
    f"{page.PREFIX}/{{token}}/projects/{{slug}}/{{feature}}",
    # **Item 219**, and this list failing again on the day it was written is the guard working a
    # third time. The instance's own upkeep — the lease, stranded verdicts, and forgetting old
    # delivery bodies — is database work and one forge call the receiver already makes. `prune` is
    # the only destructive control on this page and it takes two submissions.
    f"{page.PREFIX}/{{token}}/instance",
    # Item 219: what an operator does to one item that is not a decision about it. The two
    # decisions keep their own routes above, because they are the product's gate and are pressed by
    # somebody who may be reading nothing else.
    f"{page.PREFIX}/{{token}}/items/{{item_id}}",
)


def test_only_the_named_routes_under_the_prefix_accept_a_post(client: TestClient) -> None:
    """**This test used to say `GET`-only, and item 166 is why it does not any more.**

    The invariant it was protecting was never "no POST" — it was *no accidental mutation surface*,
    asserted by walking the application's own routes rather than by trusting a decorator to stay a
    `get` through the next refactor. That still holds, and it is now specific: the routes that may
    take a POST are named here, and one more appearing fails this test on the day it is written —
    which is exactly what item 206 did, and why the fifth name below carries its reason.

    A view acquiring a POST by accident is what this catches, and it is worth catching: the token is
    a bearer credential in a URL, so a mutating route that only checks the token would let anybody
    holding a saved link spend money.
    """
    from hullwork.main import app

    for route in app.routes:
        path = getattr(route, "path", "")
        if not path.startswith(page.PREFIX):
            continue
        methods: set[str] = getattr(route, "methods", set())
        allowed = {"GET", "HEAD", "POST"} if path in _MAY_POST else {"GET", "HEAD"}
        assert methods <= allowed, path
    # And every route named above exists: a typo here would silently stop asserting anything.
    paths = {getattr(route, "path", "") for route in app.routes}
    assert set(_MAY_POST) <= paths


def test_no_credential_of_any_kind_is_in_the_page(db: Session, client: TestClient) -> None:
    """The receiver holds the ingest token and every project's webhook hash. None of it is on a
    page whose whole audience is people who are not the operator."""
    from hullwork.models import Project

    db.add(
        Project(
            slug="demo", forge="forgejo", repo="acme/demo",
            webhook_secret_hash=hash_token("the-webhook-token"),
        )
    )
    db.commit()
    token = generate_token()
    page.issue(db, hash_token(token))

    body = client.get(f"/page/{token}").text

    assert hash_token("the-webhook-token") not in body
    assert "the-webhook-token" not in body
    assert "tok-forge-must-never-render" not in body, (
        "the forge token's value, which the receiver holds in memory"
    )


def test_the_numbers_are_the_ones_status_prints(db: Session, client: TestClient) -> None:
    """Read from the same functions, never re-queried for the page. A second implementation drifts,
    and the first anybody knows is a reader and an operator disagreeing about one instance."""
    from hullwork import outcomes

    token = generate_token()
    page.issue(db, hash_token(token))

    body = client.get(f"/page/{token}/instance").text
    printed = io.StringIO()
    cli_main(["status"], out=printed)

    assert outcomes.lines(outcomes.funnel(db)) == [], "an empty instance, so both say nothing"
    said = printed.getvalue().lower()
    for fact in ("ready", "every 60s", "0 item(s) owed an issue"):
        assert fact in body.lower() and fact in said, fact


def test_a_url_becomes_a_link_only_when_its_scheme_allows(db: Session) -> None:
    """**The stored cross-site script.** A permalink comes from somebody else's tracker; a
    `javascript:` one is an attack with a human clicking it. It renders as text instead."""
    assert '<a href="https://tracker/issues/1"' in page._link("https://tracker/issues/1")
    assert "<a" not in page._link("javascript:alert(1)")
    assert "javascript:alert(1)" in page._link("javascript:alert(1)"), "shown, just not clickable"
    assert "<a" not in page._link("data:text/html;base64,PHNjcmlwdD4=")
    assert page._link(None, "no link") == "no link"


def test_everything_interpolated_is_escaped(db: Session) -> None:
    """The primitive, with the strings that motivate it. Item 123 asserts it through the views that
    actually render a third party's text."""
    assert page._h("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert page._h('a slug with a " in it') == "a slug with a &quot; in it"
    # Numbers and `None` reach it too, and a template that crashed on one would be a page that
    # disappears exactly when something is wrong.
    assert page._h(None) == "None"
    assert page._h(4) == "4"


def test_the_page_says_the_url_is_the_credential(db: Session, client: TestClient) -> None:
    """It is a shared key, not a login. A reader who does not know that will paste it somewhere."""
    token = generate_token()
    page.issue(db, hash_token(token))

    body = client.get(f"/page/{token}").text

    assert "This URL is the credential" in body
    assert "hullwork page-token --rotate" in body


# --- the command that mints it ----------------------------------------------------------------


def _printed_token(printed: str) -> str:
    """The token out of the URL `page-token` printed, whose last character is a slash."""
    return next(w for w in printed.split() if w.startswith("https")).rstrip("/").rsplit("/", 1)[1]


def test_page_token_prints_the_url_once_and_stores_only_a_hash(db: Session) -> None:
    out = io.StringIO()
    assert cli_main(["page-token"], out=out) == 0
    printed = out.getvalue()

    urls = [w for w in printed.split() if w.startswith("https://hullwork.example/page/")]
    assert len(urls) == 1
    # **The printed URL ends in a slash**, deliberately: without it the request is answered by
    # a 308 to the same path with one, which a stranger checking the link with `curl` on
    # 2026-08-04 read as a mangled credential that by design cannot be reissued.
    assert urls[0].endswith("/")
    token = urls[0].rstrip("/").rsplit("/", 1)[1]
    assert printed.count(token) == 1

    db.expire_all()
    assert page.opens(db, token) is True
    from hullwork.models import PageAccess

    assert db.get(PageAccess, 1).token_hash == hash_token(token)  # type: ignore[union-attr]
    assert token not in db.get(PageAccess, 1).token_hash  # type: ignore[union-attr]


def test_it_refuses_to_replace_a_token_without_being_asked(db: Session) -> None:
    """A second person running it to "get the link" would lock out everybody holding the first, and
    the failure would look like the page being broken rather than like a key having changed."""
    cli_main(["page-token"], out=io.StringIO())

    import argparse

    from hullwork.cli import _cmd_page_token

    with pytest.raises(CommandError, match="already has a page token"):
        _cmd_page_token(argparse.Namespace(rotate=False), db, get_settings(), io.StringIO())


def test_rotating_invalidates_the_previous_url(db: Session) -> None:
    first = io.StringIO()
    cli_main(["page-token"], out=first)
    old = _printed_token(first.getvalue())

    second = io.StringIO()
    assert cli_main(["page-token", "--rotate"], out=second) == 0
    new = _printed_token(second.getvalue())

    db.expire_all()
    assert new != old
    assert page.opens(db, new) is True
    assert page.opens(db, old) is False


def test_status_says_whether_the_page_is_on(db: Session) -> None:
    """The page is invisible by design — it answers 404 to anybody without the token, including to
    the operator looking for it. So the one place that can say whether it exists has to."""
    off = io.StringIO()
    cli_main(["status"], out=off)
    assert "page: off" in off.getvalue()

    cli_main(["page-token"], out=io.StringIO())

    on = io.StringIO()
    cli_main(["status"], out=on)
    assert "page: on" in on.getvalue()


def test_the_attempt_header_is_above_the_fold(db: Session, client: TestClient) -> None:
    """**A test that passes with its own subject deleted is not a test** (item 116 found the same
    shape, and a reintroduction found this one). `test_the_reviewers_first_screen` proves
    `_above_the_fold` renders the seal; this proves the item view calls it, and that what it renders
    comes before the `<details>` a reader would otherwise have to open. Item 136.
    """
    from datetime import UTC, datetime, timedelta

    from hullwork.models import (
        Attempt,
        AttemptOutcome,
        AttemptPhase,
        Item,
        ItemKind,
        ItemState,
        Lane,
        Project,
    )

    project = Project(
        slug="demo", forge="forgejo", repo="acme/demo",
        webhook_secret_hash=hash_token("w"),
    )
    db.add(project)
    db.flush()
    item = Item(
        project_id=project.id, fingerprint="f", title="KeyError", state=ItemState.PR_OPEN,
        lane=Lane.GREEN, kind=ItemKind.BUG,
    )
    db.add(item)
    db.flush()
    started = datetime(2026, 8, 3, 9, tzinfo=UTC)
    db.add(
        Attempt(
            item_id=item.id,
            started_at=started,
            finished_at=started + timedelta(seconds=775),
            phase_reached=AttemptPhase.PUBLISH,
            outcome=AttemptOutcome.PR_OPEN,
            consumed=True,
            seal={
                "endpoint": "https://api.anthropic.com",
                "models_served": ["claude-opus-5"],
                "input_tokens": 1_807,
                "output_tokens": 9_364,
            },
        )
    )
    db.commit()
    token = generate_token()
    page.issue(db, hash_token(token))

    body = client.get(f"/page/{token}/items/{item.id}").text

    assert "claude-opus-5" in body
    assert "api.anthropic.com" in body
    assert "12m 55s" in body


def test_the_page_shows_money_when_the_operator_has_priced_it(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**The defect item 136 was written for**: `page.artefact()` did not pass `prices`, so a reader
    of the page saw tokens and a reader of the same artefact in a pull request saw a figure. Two
    surfaces rendering one function and disagreeing, because of an argument nobody threaded through.
    """
    from datetime import UTC, datetime, timedelta

    from hullwork.models import (
        Attempt,
        AttemptOutcome,
        AttemptPhase,
        Item,
        ItemKind,
        ItemState,
        Lane,
        Project,
    )

    monkeypatch.setenv("HULLWORK_MODEL_PRICE_INPUT", "3")
    monkeypatch.setenv("HULLWORK_MODEL_PRICE_OUTPUT", "15")
    get_settings.cache_clear()

    project = Project(
        slug="demo", forge="forgejo", repo="acme/demo",
        webhook_secret_hash=hash_token("w"),
    )
    db.add(project)
    db.flush()
    item = Item(
        project_id=project.id, fingerprint="f2", title="KeyError", state=ItemState.PR_OPEN,
        lane=Lane.GREEN, kind=ItemKind.BUG,
    )
    db.add(item)
    db.flush()
    started = datetime(2026, 8, 3, 9, tzinfo=UTC)
    db.add(
        Attempt(
            item_id=item.id,
            started_at=started,
            finished_at=started + timedelta(seconds=600),
            phase_reached=AttemptPhase.PUBLISH,
            outcome=AttemptOutcome.PR_OPEN,
            consumed=True,
            seal={"models_served": ["opus"], "input_tokens": 1_000_000,
                  "output_tokens": 1_000_000},
        )
    )
    db.commit()
    token = generate_token()
    page.issue(db, hash_token(token))

    body = client.get(f"/page/{token}/items/{item.id}").text

    assert "18.0000 USD" in body, "3 + 15 per million, on a million of each"


def test_the_page_serves_the_mark_the_design_document_specifies() -> None:
    """`▚`, inline, and no external asset. The glyph was decided and never served.

    Two properties, and the second is why this is not a cosmetic test. The mark has to be
    **there** — a browser tab showing a generic document icon is where somebody with fifteen tabs
    open loses the page. And it has to be **inline**, because `_document`'s own docstring promises
    "no external asset": a favicon file would make the page fetch something, which is a claim this
    project makes about itself in `SECURITY.md` as well as in that docstring.
    """
    html = page._document("anything", "<p>body</p>")

    assert 'rel="icon"' in html, "the interface document specifies a favicon glyph"
    assert "data:image/svg+xml," in html, "inline, or the page fetches an asset it promises not to"
    assert "%E2%96%9A" in html, "the glyph is ▚, not a letter or a picture"
    # Not "no `http://` anywhere in the head": the SVG namespace is a URI and is not a fetch, which
    # this assertion learned the hard way. What matters is that nothing is *requested*.
    head = html.split("<body>")[0]
    assert 'href="http' not in head and 'src="http' not in head, "the head must fetch nothing"


# --- the door that replaces the token (item 204, DR-0021) ----------------------------------------


def test_signing_in_at_the_session_door_is_not_a_404(db: Session, client: TestClient) -> None:
    """**Found in use, on the first attempt, by the operator** (2026-08-10). Item 204 put the login
    behind the same gate as everything else — and that gate requires a session at `/page/me/`, so
    signing in required already being signed in. The form posted, and Hullwork answered
    `{"detail":"Not Found"}`.

    A door with a handle you can only reach from inside is a door nobody opens.
    """
    from hullwork import operator

    operator.set_password(db, "correct horse")
    db.commit()

    answered = client.post(
        "/page/me/login", data={"password": "correct horse"}, follow_redirects=False
    )

    assert answered.status_code != 404
    assert operator.COOKIE in answered.cookies, "and it signed them in"


def test_the_session_door_still_refuses_without_a_password_configured(
    db: Session, client: TestClient
) -> None:
    """The property DR-0021 spends nothing of: an instance that never opted in has no login to post
    to, and says so with the same `404` an unknown path gets."""
    answered = client.post("/page/me/login", data={"password": "anything"})

    assert answered.status_code == 404


def test_a_wrong_password_at_the_session_door_still_says_nothing(
    db: Session, client: TestClient
) -> None:
    """Item 168's rule survives the new door: a wrong password answers exactly as a right one does,
    because an error page is an oracle. What differs is the cookie."""
    from hullwork import operator

    operator.set_password(db, "correct horse")
    db.commit()

    answered = client.post("/page/me/login", data={"password": "wrong"}, follow_redirects=False)

    assert answered.status_code != 404
    assert operator.COOKIE not in answered.cookies


def test_the_whole_way_in(db: Session, client: TestClient) -> None:
    """**The flow, end to end, because the parts passing separately is what let this ship broken.**

    Open the door, sign in, read the page. Item 204 had a test for the gate and a test for the login
    page and none for the sequence, so the one step between them — the form's own POST — was never
    exercised by anything until a person tried it.
    """
    from hullwork import operator

    operator.set_password(db, "correct horse")
    db.commit()

    shut = client.get("/page/me/")
    assert shut.status_code == 200
    assert "<form" in shut.text and 'class="lede' not in shut.text, "the login, not the page"

    client.post("/page/me/login", data={"password": "correct horse"})

    opened = client.get("/page/me/")
    assert opened.status_code == 200
    assert 'class="lede' in opened.text, "and now the instance view"
