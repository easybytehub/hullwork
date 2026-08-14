"""What a press answers with, followed the way a browser follows it. Item 250.

Item 249's crawl walks every view a `GET` serves. A `POST` answers with a document too — served at
the URL the form posted to, with every relative link in it resolved against **that** URL — and
nothing had ever looked at one. Pressing all thirty-five buttons and following what came back:
eight answered with navigation that 404'd.

All of it is one mistake, **a document built for one URL served at another**: the list of projects
returned from a project's URL on every refusal and on `rotate-secret`, and the dependency view —
which carries `../../` — returned from one level above it.

The fourth thing pressing found is not a link at all. `rotate-secret` passed `rotated[1]` into a
`tuple[str, str | None]`, and `rotated` is the token: **the one answer in this product that can
never be repeated printed a single character of it**, and type-checked.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urljoin

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from hullwork import operator
from hullwork.config import get_settings
from hullwork.db import make_engine
from hullwork.models import (
    Attempt,
    AttemptOutcome,
    Base,
    DependencyReport,
    Item,
    ItemState,
    Lane,
    Project,
    UpgradeVerdict,
)
from hullwork.security import hash_token

PASSWORD = "correct horse"  # noqa: S105 - a fixture, not a credential


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    """Enough in it that every control renders: an attempt, a tracker name, a report, a verdict."""
    url = f"sqlite:///{tmp_path}/press.db"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.setenv("HULLWORK_BASE_URL", "http://testserver")
    get_settings.cache_clear()
    session = sessionmaker(bind=engine)()
    project = Project(
        slug="shop", forge="forgejo", repo="acme/shop",
        webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
        manifest={"version": 1, "autofix": {"open_upgrades": True}},
    )
    project.tracker_project = "shop"
    session.add(project)
    session.flush()
    now = dt.datetime.now(dt.UTC)
    session.add(Item(
        project_id=project.id, fingerprint="f", title="KeyError",
        state=ItemState.WAITING_APPROVAL, lane=Lane.GREEN, last_seen=now,
    ))
    session.flush()
    session.add(Attempt(
        item_id=1, outcome=AttemptOutcome.PR_OPEN, pull_request_ref="#4",
        started_at=now, finished_at=now,
    ))
    session.merge(DependencyReport(
        project_id=project.id, taken_at=now, asked=True, pinned=9,
        findings=[{
            "package": "thing", "version": "1.0", "source": "uv.lock",
            "advisories": [{"id": "GHSA-x", "summary": "s", "fixed": ["2.0"]}],
        }],
    ))
    session.add(UpgradeVerdict(
        project_id=project.id, package="thing", was="1.0", to="2.0", outcome="clean",
        tried_at=now, artefact={"files": {"uv.lock": "x"}, "runs": None}, base_sha="b" * 40,
    ))
    operator.set_password(session, PASSWORD)
    session.commit()
    yield session
    get_settings.cache_clear()


@pytest.fixture
def client(db: Session) -> TestClient:
    del db
    from hullwork.main import app

    made = TestClient(app)
    made.post("/page/me/login", data={"password": PASSWORD})
    return made


FORM = re.compile(r"<form[^>]*>.*?</form>", re.S)


def _presses(html: str) -> list[tuple[str, dict[str, str], str]]:
    """Every button on a rendered view, as the request pressing it makes."""
    found = []
    for form in FORM.findall(html):
        action = re.search(r'action="([^"]+)"', form)
        if action is None:
            raise AssertionError("a form with no action posts to the current URL by accident")
        fields = {
            name: (value.group(1) if (value := re.search(r'value="([^"]*)"', tag)) else "")
            for tag in re.findall(r"<input[^>]*>", form)
            if (name := (found_name.group(1)
                         if (found_name := re.search(r'name="([^"]+)"', tag)) else ""))
        }
        for tag in re.findall(r"<button[^>]*>[^<]*</button>", form):
            label = re.search(r">([^<]*)</button>", tag)
            named = re.search(r'name="([^"]+)"', tag)
            value = re.search(r'value="([^"]*)"', tag)
            body = dict(fields)
            if named:
                body[named.group(1)] = value.group(1) if value else ""
            found.append((action.group(1), body, (label.group(1) if label else "?").strip()))
    return found


def _dead_links(client: TestClient, at: str, html: str) -> list[str]:
    """Every link in `html`, resolved against the URL it was served at, that does not answer 200."""
    dead = []
    for href in re.findall(r'<a href="([^"]+)"', html):
        if href.startswith(("http://", "https://", "mailto:", "#", "data:")):
            continue
        went = urljoin(f"http://testserver{at}", href)
        if client.get(went).status_code != 200:
            dead.append(f"{href} → {went.removeprefix('http://testserver')}")
    return dead


class TestWhatComesBackCanBeNavigated:
    def test_every_button_answers_with_a_page_whose_links_land(self, client: TestClient) -> None:
        """**The whole item, and the guard that would have caught all of it.**

        `test_every_form_posts_somewhere_that_exists` resolves a form's action and asserts the
        route is there. It never submits, so a form that reaches a real route and comes back with a
        document nobody can navigate passed it — and passed it for as long as the route existed.
        """
        from test_every_link_lands import WHERE_YOU_CAN_BE

        pressed: set[str] = set()
        for here in WHERE_YOU_CAN_BE:
            for action, body, label in _presses(client.get(here).text):
                if label in ("Sign out", "Issue a new read link"):
                    # Sign out ends the session; the read link is the one press whose answer is
                    # *meant* to be a page you cannot use, and it has its own test below.
                    continue
                fresh = _presses(client.get(here).text)
                body = next((one for one, _, name in
                             ((b, a, n) for a, b, n in fresh) if name == label), body)
                landed = urljoin(f"http://testserver{here}", action)
                answer = client.post(landed, data=body, follow_redirects=False)
                pressed.add(label)
                if answer.status_code in (302, 303, 307):
                    continue
                if answer.status_code == 409:
                    # The state machine refusing a decision about an item that has already moved,
                    # which is item 166's choice and not this item's business. What it answers with
                    # is a bare `{"detail": …}` rather than a page — recorded in item 251.
                    continue
                at = landed.removeprefix("http://testserver")

                assert answer.status_code == 200, f"{here} [{label}] → {answer.status_code}"
                assert not _dead_links(client, at, answer.text), (
                    f"{here} [{label}] posted to {action} and came back with dead links: "
                    f"{_dead_links(client, at, answer.text)}"
                )

        # **Named rather than counted** (the lesson of item 249's empty fixture). A count passes
        # while the fixture quietly stops rendering the controls this item is about; these eight
        # are the ones whose answers were broken, so this walk proves nothing without them.
        assert {
            "Open a draft PR", "Re-read its manifest", "Issue a new secret", "Name it",
            "What the tracker still has", "File them", "Which files keep a human on",
            "Read a manifest from its CI",
        } <= pressed, f"not pressed: {sorted({'Open a draft PR'} - pressed)} of {sorted(pressed)}"

    def test_a_refusal_answers_with_the_view_you_were_on(self, client: TestClient) -> None:
        """**The common path, not the exotic one.** A forge that will not answer is what this
        product is for, and it reported that on the list of every project — rendered at this
        project's URL, so its six rail links resolved to `projects/projects`, `projects/instance`
        and the rest."""
        csrf = _csrf(client, "/page/me/projects/shop/settings")

        answer = client.post(
            "/page/me/projects/shop/settings", data={"action": "refresh", "csrf": csrf}
        )

        assert "<title>Hullwork — shop settings</title>" in answer.text
        assert "c-refused" in answer.text, "the reason has to survive the move"
        assert not _dead_links(client, "/page/me/projects/shop/settings", answer.text)

    def test_open_upgrade_answers_at_the_dependency_views_own_url(
        self, client: TestClient
    ) -> None:
        """**Item 245's button, which I built and the operator pressed.** It posted to
        `../<slug>` and was answered with the dependency view — a document carrying `../../`,
        returned two levels up — so every link on it resolved to `/page/projects/…`, outside the
        token's prefix entirely."""
        csrf = _csrf(client, "/page/me/projects/shop/dependencies")

        answer = client.post(
            "/page/me/projects/shop/dependencies",
            data={"action": "open-upgrade", "verdict": "1", "csrf": csrf},
        )

        assert "<title>Hullwork — shop dependencies</title>" in answer.text
        assert "Asked for thing 1.0 → 2.0" in answer.text
        assert not _dead_links(client, "/page/me/projects/shop/dependencies", answer.text)


class TestTheSecretThatWasShownOnce:
    def test_the_secret_shown_is_the_secret_stored(self, client: TestClient, db: Session) -> None:
        """**`rotated[1]` is the second character of the token.**

        It was passed into a parameter typed `tuple[str, str | None]`, so it type-checked, and the
        existing test asserted the shape of the answer — that `/webhooks/` appeared, that it said
        *only time*, that it said *stopped working* — and never that the value shown was the value
        minted. Pressing the button stopped the tracker's working URL and printed `0`, and only the
        hash is kept, so there was no way back.
        """
        csrf = _csrf(client, "/page/me/projects/shop/settings")

        answer = client.post(
            "/page/me/projects/shop/settings", data={"action": "rotate-secret", "csrf": csrf}
        )

        shown = re.search(r"/webhooks/glitchtip/shop/([^<\s]+)", answer.text)
        assert shown is not None, "the new URL is the whole point of the answer"
        db.expire_all()
        assert hash_token(shown.group(1)) == db.query(Project).one().webhook_secret_hash, (
            "the secret on the page is not the one this instance now expects"
        )

    def test_it_is_shown_where_the_button_is(self, client: TestClient) -> None:
        """It was shown on the list of every project, rendered at this project's URL: the one
        answer that can never be repeated, on a page whose every link was dead."""
        csrf = _csrf(client, "/page/me/projects/shop/settings")

        answer = client.post(
            "/page/me/projects/shop/settings", data={"action": "rotate-secret", "csrf": csrf}
        )

        assert "<title>Hullwork — shop settings</title>" in answer.text
        assert "stopped working" in answer.text.lower()
        assert not _dead_links(client, "/page/me/projects/shop/settings", answer.text)


class TestTheReadLinkSaysWhatItJustDid:
    def test_at_a_minted_url_it_says_this_page_stopped_working_too(
        self, client: TestClient, db: Session
    ) -> None:
        """**The one answer that is meant to be a page you cannot use.** Every link on it is
        correctly written and every one of them 404s, because the URL they resolve under was
        revoked by the press. Saying *every URL handed out before this moment has stopped working*
        and not saying that this is one of them leaves the reader clicking."""
        from hullwork import page
        from hullwork.security import generate_token

        minted = generate_token()
        page.issue(db, hash_token(minted))
        db.commit()
        where = f"/page/{minted}/instance"
        csrf = _csrf(client, where)

        answer = client.post(where, data={"action": "page-token", "csrf": csrf})

        assert "answers 404 now" in answer.text
        assert _dead_links(client, where, answer.text), (
            "if the links still land, this sentence has become false"
        )

    def test_at_me_it_does_not_say_it(self, client: TestClient) -> None:
        """**Because it would be false.** `MINE` is opened by the session, not by the token that
        was just revoked, so nothing on this page stops working."""
        csrf = _csrf(client, "/page/me/instance")

        answer = client.post("/page/me/instance", data={"action": "page-token", "csrf": csrf})

        assert "answers 404 now" not in answer.text
        assert not _dead_links(client, "/page/me/instance", answer.text)


def _csrf(client: TestClient, where: str) -> str:
    found = re.search(r'name="csrf" value="([^"]+)"', client.get(where).text)
    assert found is not None, f"{where} renders no form to press"
    return found.group(1)
