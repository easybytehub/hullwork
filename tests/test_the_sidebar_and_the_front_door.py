"""Navigation as furniture, and a front door that is the work. Item 212, DR-0023.

Measured on the live instance before any of this: the landing view held **357 words, 11 numbers and
14 sentences**, and its navigation was five text links below a wall of arithmetic. GlitchTip's, open
in the next tab held about forty words, a sidebar of nouns, and the things you have.

What is copied is the information architecture. What is not copied is the voice: `Nothing needs
you.` and *a reasoned refusal and the runs behind it* are the product's thesis, and a page reduced
to
labels would look like GlitchTip's and stop saying the one thing that distinguishes it.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from hullwork import operator, page
from hullwork.config import Settings, get_settings
from hullwork.models import Project
from hullwork.page import Acting

SIGNED_IN = Acting(csrf="c", offered=True)
A_READER = Acting(csrf=None, offered=False)


@pytest.fixture
def db(tmp_path: object, monkeypatch: pytest.MonkeyPatch) -> Session:
    """A real instance behind the routes, because the defect below was in the wiring and not in
    `page`: every function here was already able to draw the whole rail."""
    from hullwork.config import get_settings
    from hullwork.db import make_engine
    from hullwork.models import Base

    url = f"sqlite:///{tmp_path}/rail.db"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    return sessionmaker(bind=engine)()


@pytest.fixture
def client() -> TestClient:
    from hullwork.main import app

    return TestClient(app)


def _words(html: str) -> int:
    """What a person meets on the first screen, counted the way the 357 was."""
    body = re.sub(r"<style.*?</style>", "", html, flags=re.S)
    return len(re.sub(r"<[^>]+>", " ", body).split())


# --- navigation is furniture ---------------------------------------------------------------------


def test_every_page_carries_the_same_sidebar(session: Session) -> None:
    """**From one function**, or four pages grow four opinions about what this product contains —
    which is the drift items 193, 194, 200, 203 and 211 each cost a day to."""
    settings = Settings()
    pages = (
        page.items(session, acting=SIGNED_IN),
        page.projects(session, settings, acting=SIGNED_IN),
        page.instance(session, settings, error_reporting=False, acting=SIGNED_IN),
    )

    for one in pages:
        assert '<nav class="rail"' in one


def test_the_sidebar_shows_a_reader_only_what_a_reader_may_open(session: Session) -> None:
    """DR-0021's line survives the new layout. A control that leads to a `404` is worse than one
    that is not there: it offers, and then refuses."""
    rail = re.search(r'<nav class="rail".*?</nav>', page.items(session, acting=A_READER), re.S)

    assert rail is not None
    assert 'href="doctor"' not in rail.group(0)
    assert 'href="config"' not in rail.group(0)


def test_the_operator_is_shown_all_four(session: Session) -> None:
    """**The `or` in the first version made this pass before anything was built.** `href="./"` is on
    every page, so `A or B` was satisfied by B for all four nouns — a test that asserted nothing and
    would have let me build against it."""
    rail = re.search(r'<nav class="rail".*?</nav>', page.items(session, acting=SIGNED_IN), re.S)

    assert rail is not None
    for noun in ("projects", "doctor", "config", "instance"):
        assert f'href="{noun}"' in rail.group(0), noun


def test_the_operators_own_views_do_not_take_the_rail_away(
    db: Session, client: TestClient
) -> None:
    """**Found by clicking, not by reading.** `doctor` and `config` rendered with the default
    `Acting`, so a signed-in operator opening *why it will not work* was shown the reader's three
    nouns — and the way to *what it received*, the other view they came for, was gone from the page
    they were standing on.

    A rail that changes what it offers depending on which page you are on is not furniture; it is
    five pages with five opinions, which is the thing this item exists to end.
    """
    operator.set_password(db, "correct horse")
    db.commit()
    client.post("/page/me/login", data={"password": "correct horse"})

    for where in ("doctor", "config", "instance", "projects"):
        shown = client.get(f"/page/me/{where}")

        assert shown.status_code == 200, where
        rail = re.search(r'<nav class="rail".*?</nav>', shown.text, re.S)
        assert rail is not None, where
        for noun in ("projects", "instance", "doctor", "config"):
            assert f'href="{noun}"' in rail.group(0), f"{noun} missing from the rail on {where}"
        assert 'aria-current="page"' in rail.group(0), f"{where} does not say where you are"


def test_no_view_serves_a_literal_asterisk(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**Seen on the deployed `doctor`, in the `deliveries` finding.** These sentences were written
    for a terminal and carry this project's own emphasis; `_as_code` turned their backticks into
    code and left the `**` alone, so the page said *a tracker is configured and \\*\\*no delivery
    has
    ever arrived\\*\\**.

    The existing assertion of this covered one view, which is why four others could grow it. It is
    every view now — a rendering rule that holds on the page you happened to test is not a rule.
    """
    # **The state that produces the sentence.** A tracker configured and a project that has never
    # received a delivery is what `deliveries` needs to say it — and is exactly the instance this
    # was seen on. Without it every view is asterisk-free for want of anything to emphasise, which
    # is how the first version of this test passed against the defect.
    monkeypatch.setenv("HULLWORK_TRACKER_URL", "https://tracker.example")
    monkeypatch.setenv("HULLWORK_TRACKER_TOKEN", "t")
    get_settings.cache_clear()
    db.add(
        Project(
            slug="shop", forge="forgejo", repo="acme/shop",
            webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
        )
    )
    operator.set_password(db, "correct horse")
    db.commit()
    client.post("/page/me/login", data={"password": "correct horse"})

    for where in ("", "instance", "projects", "doctor", "config"):
        shown = client.get(f"/page/me/{where}")

        assert shown.status_code == 200, where
        served = re.sub(r"<style.*?</style>", "", shown.text, flags=re.S)
        assert "**" not in served, f"markdown emphasis served as asterisks on {where or 'the door'}"


# --- the front door ------------------------------------------------------------------------------


#: **The setting that makes the two branches differ at all.** Without a DSN, `error_reporting=True`
#: and `False` produce identical readiness, so the first version of the comparison below passed
#: against the very defect it was written for — the third time this week a test of mine agreed with
#: a broken product because its fixture could not tell the two apart.
REPORTING_ITS_OWN_ERRORS = Settings(error_dsn="https://key@errors.example/1")  # type: ignore[arg-type]


def _front_door(
    session: Session, *, settings: Settings | None = None, error_reporting: bool = False
) -> str:
    """What the route at `/page/<token>/` renders — not `items` with its arguments defaulted.

    **The first version of the two tests below measured `page.items(session, acting=…)`**, which
    without `front=True` renders no headline at all. So the word count was counting a view no
    person is served, and it would have kept passing however long the real front door grew.
    """
    return page.items(
        session,
        acting=SIGNED_IN,
        here="./",
        settings=settings or Settings(),
        front=True,
        error_reporting=error_reporting,
    )


def test_the_front_door_and_the_report_give_the_same_answer(session: Session) -> None:
    """**Found on the deployed page, in red.** The front door computes its own readiness, and the
    first version hardcoded `error_reporting=False` — so an instance that was reporting its errors
    opened on *HULLWORK_ERROR_DSN is set but error reporting is not running*, a fault it did not
    have, while the report one click away said it was fine.

    **Asserted against `readiness.check`, not against the other view.** The first version compared
    the door's headline to the report's, which both views build from the same function — so the
    defect moved them together and the comparison passed. Agreement between two callers of one
    broken function is not evidence; the ground truth is what the check itself says.
    """
    from hullwork import readiness

    for reporting in (True, False):
        door = _front_door(
            session, settings=REPORTING_ITS_OWN_ERRORS, error_reporting=reporting
        )
        truth = readiness.check(
            session, REPORTING_ITS_OWN_ERRORS, error_reporting=reporting
        ).problems
        headline = re.search(r'<p class="lede[^"]*">(.*?)</p>', door, re.S)

        assert headline is not None
        if truth:
            assert truth[0] in headline.group(1), f"error_reporting={reporting}"
        else:
            assert "not running" not in door, (
                "an instance reporting its errors is told it is not, on the first screen"
            )


def test_the_first_screen_is_the_work_and_not_the_arithmetic(session: Session) -> None:
    """You land among the things that arrived, which is what a person comes to look at. The
    instance's own numbers are a noun in the sidebar, one click away, with nothing dropped."""
    landing = _front_door(session)

    assert "Errors" in landing or "Nothing has arrived" in landing
    assert 'href="instance"' in landing


def test_the_first_screen_is_short(session: Session) -> None:
    """**357 words is the measurement this item exists to move.** An empty instance should be a
    sentence and a sidebar, not a report about having nothing."""
    assert _words(_front_door(session)) < 120


def test_the_instance_report_keeps_every_number(session: Session) -> None:
    """Moving is not dropping. An instance that cannot show its own numbers is asking to be
    believed, which is the one thing this product refuses to ask."""
    said = page.instance(session, Settings(), error_reporting=False, acting=SIGNED_IN)

    for label in ("found", "tried", "merged", "held", "came back"):
        assert label in said.lower(), label


# --- the voice, which is not decoration ----------------------------------------------------------


def test_the_lede_survives_the_move(session: Session) -> None:
    """`Nothing needs you.` is the product's thesis in three words: it measures what left a person's
    desk, not what a machine did. GlitchTip has nothing to say there because it verifies nothing.

    **It has to be on the new front door, not merely somewhere.** The headline was the top of the
    instance report; moving the door without it would have left a person meeting a table of rows
    and having to read them to learn whether any of it wanted them — which is the question item 167
    built this sentence to answer without reading."""
    assert "Nothing needs you." in _front_door(session)
    assert "Nothing needs you." in page.instance(
        session, Settings(), error_reporting=False, acting=SIGNED_IN
    ), "and still where an operator who opened the report on a bad morning would look"
