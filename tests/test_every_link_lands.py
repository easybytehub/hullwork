"""Every link on every view, followed. Item 227.

The operator, one URL: `/page/me/projects/projects` → `{"detail":"Not Found"}`.

They had clicked **Projects** in the rail, from a project's own view. Every URL on this page is
relative on purpose — that is what keeps the token out of the HTML, so a saved page or a screenshot
of the source carries no key — and `_document` takes `up` for exactly that reason. Item 223 gave the
project view a rail and did not tell it how deep it sits, so all five nouns resolved one level too
far — `projects/projects`, `projects/instance`, `projects/doctor`, `projects/config`, `projects/`.

**Five broken links, and every existing test passed**, because a test that renders a view by
calling a function never resolves an `href`. `test_the_evidence_a_reviewer_came_for` walks links
from the front door for this reason, and had no reason to walk them from anywhere else.

So this file walks them from **everywhere**: for each view, at the URL it is really served from,
every link is resolved the way a browser resolves it and followed. A rail that 404s is a page whose
navigation moves under the reader, and it is invisible to anything short of clicking.

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
)


def _where_you_can_be() -> tuple[str, ...]:
    """Every GET the page serves, derived from the application rather than listed by hand.

    **Item 249, and the reason it exists.** This was seven URLs written out, and DR-0027 then gave a
    project five views of its own — `errors`, `fixes`, `dependencies`, `deliveries`, `settings` —
    none of which was ever added here. The operator found the gap by clicking: an item on a
    project's *fixes* view had a relative `items/27`, which resolves three levels deep to
    `projects/shop/items/27` and answers `{"detail":"Not Found"}`.

    A hand-written list of *where you can be* is a list that goes stale on the next route, silently,
    and its silence reads as coverage. Derived, a new page is crawled the day it exists.

    The trailing shape matters and is preserved: a browser resolves `projects` differently from
    `/page/me/projects` and from `projects/shop`.
    """
    from hullwork import page as page_module
    from hullwork.main import app

    prefix = f"{page_module.PREFIX}/{{token}}"
    found = []
    for route in app.routes:
        path = getattr(route, "path", "")
        if not path.startswith(prefix) or "GET" not in getattr(route, "methods", set()):
            continue
        here = path.replace(prefix, "/page/me")
        if "{" in here.replace("{token}", ""):
            here = here.replace("{slug}", "shop").replace("{item_id}", "1")
        if "{" in here:
            continue
        # **The slashless variant redirects and serves nothing**, so resolving a relative href
        # against it measures a URL no reader is ever on: `/page/me` + `projects` is
        # `/page/projects`, which is the redirect's job to prevent rather than a broken link.
        if here == "/page/me":
            continue
        found.append(here or "/page/me/")
    return tuple(sorted(set(found)))


#: Every view a person can reach, at the path it is served from.
WHERE_YOU_CAN_BE = _where_you_can_be()


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path}/links.db"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    session = sessionmaker(bind=engine)()
    project = Project(
        slug="shop", forge="forgejo", repo="acme/shop",
        webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
    )
    project.tracker_project = "shop"
    session.add(project)
    session.flush()
    session.add(
        Item(
            project_id=project.id, fingerprint="f", title="KeyError",
            state=ItemState.NEW, lane=Lane.GREEN, last_seen=dt.datetime.now(dt.UTC),
        )
    )
    session.flush()
    # **Enough in it that every view emits its links** (item 249). Three of that item's four
    # reintroductions escaped a crawl that visited the right pages and found them empty: `fixes`
    # renders no row without an attempt, the sweep form does not exist without a tracker name, and
    # the dependency view has nothing to link to without a report. A crawl over empty pages reports
    # coverage it does not have, which is the same failure as the hand-written list it replaced.
    now = dt.datetime.now(dt.UTC)
    session.add(Attempt(
        item_id=1, outcome=AttemptOutcome.PR_OPEN, pull_request_ref="#4",
        started_at=now, finished_at=now,
    ))
    session.merge(DependencyReport(
        project_id=project.id, taken_at=now, asked=True, pinned=9,
        findings=[{
            "package": "thing", "version": "1.0", "source": "uv.lock",
            "advisories": [{"id": "GHSA-x", "summary": "something", "fixed": ["2.0"]}],
        }],
    ))
    operator.set_password(session, "correct horse")
    session.commit()
    yield session
    get_settings.cache_clear()


@pytest.fixture
def client(db: Session) -> TestClient:
    from hullwork.main import app

    made = TestClient(app)
    made.post("/page/me/login", data={"password": "correct horse"})
    return made


def _links(html: str, *, only: str | None = None) -> list[str]:
    within = html
    if only:
        found = re.search(rf"<{only}[^>]*>.*?</{only.split()[0]}>", html, re.S)
        within = found.group(0) if found else ""
    return re.findall(r'<a href="([^"]+)"', within)


@pytest.mark.parametrize("here", WHERE_YOU_CAN_BE)
def test_the_rail_lands_from_everywhere(client: TestClient, here: str) -> None:
    """**The whole item.** From a project's own view every noun in the rail resolved one level too
    deep and answered `404`, which is what the operator opened and what nothing here could see."""
    shown = client.get(here)

    assert shown.status_code == 200, here
    rail = _links(shown.text, only='nav class="rail"')

    assert rail, f"{here} has no rail"
    for href in rail:
        landed = urljoin(f"http://testserver{here}", href)
        assert client.get(landed).status_code == 200, f"{here} → {href} → {landed}"


@pytest.mark.parametrize("here", WHERE_YOU_CAN_BE)
def test_every_link_on_every_view_lands(client: TestClient, here: str) -> None:
    """Not only the rail. A view's own links — *All projects*, *This instance*, an item's id — are
    written by hand in nine functions, and each of them can be one `../` out."""
    shown = client.get(here)

    for href in _links(shown.text):
        if href.startswith(("http://", "https://", "mailto:", "#", "data:")):
            continue
        landed = urljoin(f"http://testserver{here}", href)
        assert client.get(landed).status_code == 200, f"{here} → {href} → {landed}"


@pytest.mark.parametrize("here", WHERE_YOU_CAN_BE)
def test_every_form_posts_somewhere_that_exists(client: TestClient, here: str) -> None:
    """**A form is a URL like any other**, and `_document`'s own docstring says so: from `items/28`
    the sign-out has to post to `../logout`, and hardcoding `logout` would have posted to
    `items/logout`. Asserted by resolving, not by reading.

    **Asked of the router rather than shaped by hand** (item 250). This used to turn a resolved URL
    back into a route template with a ladder of `re.sub` — `/projects/<slug>` to
    `/projects/{slug}`, and so on — which is the hand-written list of item 249 wearing a different
    hat: it went stale the moment a route had a shape the ladder did not know, and said *not a
    route* about a route that was there. The router already answers this question.
    """
    from starlette.routing import Match

    from hullwork.main import app

    shown = client.get(here)

    for action in re.findall(r'<form[^>]*action="([^"]+)"', shown.text):
        landed = urljoin(f"http://testserver{here}", action)
        path = landed.removeprefix("http://testserver")
        scope = {"type": "http", "method": "POST", "path": path, "root_path": "", "headers": []}
        matched = any(one.matches(scope)[0] is Match.FULL for one in app.routes)

        assert matched, f"{here} posts to {action} → {path}, which is not a route"


#: What each label promises, as the path it has to reach. A link that lands is not a link that is
#: honest: `This instance` pointed at the front door for as long as the front door was the instance
#: report, and item 212 moved that without moving the label.
LABELS_PROMISE = {
    "This instance": "/page/me/instance",
    "All projects": "/page/me/projects",
    "All items": "/page/me/items",
    "Projects": "/page/me/projects",
    "Items": "/page/me/",
    "Why it will not work": "/page/me/doctor",
    "What it received": "/page/me/config",
}


@pytest.mark.parametrize("here", WHERE_YOU_CAN_BE)
def test_a_label_goes_where_it_says(client: TestClient, here: str) -> None:
    """**Landing is not the same as being honest.** Every test in this file follows links and checks
    they answer `200`; a label pointing at the wrong working page passes all of them, and is worse
    than a broken one — a `404` tells you something is wrong, and this quietly does not."""
    shown = client.get(here).text

    for href, label in re.findall(r'<a href="([^"]+)"[^>]*>([^<]+)</a>', shown):
        promised = LABELS_PROMISE.get(label.strip())
        if promised is None:
            continue
        landed = urljoin(f"http://testserver{here}", href).removeprefix("http://testserver")

        assert landed == promised, f"{here}: {label.strip()!r} goes to {landed}, not {promised}"


def test_the_crawl_covers_every_page_the_application_serves() -> None:
    """**The guard's own scope, asserted** (item 249).

    Reintroducing the hand-written list of seven changes nothing while the code is correct, so the
    property has to be measured directly: what this file walks is what the application serves, and
    a route added tomorrow is walked without anybody editing this file.

    That is the defect item 249 is about. DR-0027 gave a project five views and none of them was
    added here; the crawl kept passing over the seven it knew, and its silence read as coverage.
    """
    from hullwork import page as page_module
    from hullwork.main import app

    prefix = f"{page_module.PREFIX}/{{token}}"
    served = {
        getattr(one, "path", "")
        for one in app.routes
        if getattr(one, "path", "").startswith(prefix)
        and "GET" in getattr(one, "methods", set())
    }
    walked = {
        one.replace("/page/me", prefix).replace("/shop", "/{slug}").replace("/1", "/{item_id}")
        for one in WHERE_YOU_CAN_BE
    }
    # The slashless variant redirects and is excluded above, with its reason.
    missing = served - walked - {prefix}

    assert not missing, f"the crawl does not visit: {sorted(missing)}"
    for feature in ("errors", "fixes", "dependencies", "deliveries", "settings"):
        assert f"/page/me/projects/shop/{feature}" in WHERE_YOU_CAN_BE
