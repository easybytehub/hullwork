"""Every command is on the page, or says in writing why it is not. Item 218.

The operator, told the dependency half worked: *pero no hay ninguna ejecución del informe de
dependencias y verificación. Al menos en la página web.* There was not, and there is no view, no
route and no table for it — `_cmd_deps` opens no session and cannot run inside the container at all.

So this file is the guard that makes *every feature has a place* a fact rather than an intention:
a command added tomorrow fails here until somebody has decided where it lives, or written down why
it does not. **A reason is as good as a route** — `work` will never be on a page served by the
receiver, and saying so is the answer rather than an omission.

Three lists and not two, because *never* and *not yet* are different claims and collapsing them is
how a to-do becomes a design. `NOT_YET` is the work remaining, and it is meant to empty.

Read off the parser rather than the published surface on purpose: the surface records the last
release, so a command added today would not appear in it until after it shipped undocumented, which
is the failure item 209 is about arriving through a second door.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import argparse
from collections.abc import Iterator

import pytest
from sqlalchemy.orm import Session

from hullwork import page
from hullwork.cli import build_parser
from hullwork.models import Item as _Item
from hullwork.page import Acting

#: Where each command lives, as the path under `/page/{token}/` **and what is rendered there**.
#:
#: **The second half is item 223.** Until then this named a path and checked the application's route
#: table, and five commands passed that check with no button anywhere: `refresh`, `disable`,
#: `rotate-secret`, `set-tracker` and `requeue` were reachable by `curl` and by nothing a person
#: could press. Their tests posted straight at the route, which is a fair test of a route and no
#: test at all of a page.
#:
#: So a placement now names a string that has to appear in the rendered view — `value="disable"` for
#: an action, a heading or a link for a reading. A route is not a control.
#:
#: **Item 235 moved half of these** (DR-0027). Dependencies, deliveries and fixes each stopped being
#: a fold inside one project and became a page across every project, and this table is what proves
#: the move lost nothing: a command whose page vanished fails here, before anybody looks at a
#: screen. Three placements changed and every other one had to keep working, which is the whole
#: reason this file was written before the redesign rather than after it.
ON_THE_PAGE: dict[str, tuple[str, str]] = {
    "status": ("instance", "<h1>This instance</h1>"),
    "doctor": ("doctor", "<h1>Diagnostics</h1>"),
    "config": ("config", "<h1>What it received</h1>"),
    "approve": ("items/{item_id}", 'items/{id}/approve"'),
    "requeue": ("items/{item_id}", 'value="requeue"'),
    "republish": ("instance", 'value="republish"'),
    "lease": ("instance", "Releasing it means the next dispatcher"),
    "lease release": ("instance", 'value="lease-release"'),
    "prune": ("instance", 'value="prune-preview"'),
    "page-token": ("instance", 'value="page-token"'),
    "deps": ("projects/{slug}/dependencies", "Dependencies</span></h1>"),
    "sweep": ("projects/{slug}/settings", 'value="sweep"'),
    "features": ("projects/{slug}/settings", "What Hullwork can do for"),
    "propose": ("projects/{slug}/settings", 'value="propose"'),
    "projects lanes": ("projects/{slug}/settings", 'value="lanes"'),
    "projects": ("projects", "<h1>Projects</h1>"),
    "projects add": ("projects", "Connect a project"),
    "projects list": ("projects", "<h1>Projects</h1>"),
    "projects refresh": ("projects/{slug}/settings", 'value="refresh"'),
    "projects disable": ("projects/{slug}/settings", 'value="disable-preview"'),
    "projects enable": ("projects/{slug}/settings", 'value="enable"'),
    "projects rotate-secret": ("projects/{slug}/settings", 'value="rotate-secret"'),
    "projects set-tracker": ("projects/{slug}/settings", 'value="set-tracker"'),
}

#: Never, and each with the reason it is never. **Prose here is the point**: a command missing from
#: all three lists is one nobody decided about, and that is what this file catches.
NEVER_ON_THE_PAGE: dict[str, str] = {
    "work": (
        "the receiver holds no Docker socket and no credential that can push, and refuses to start "
        "if it finds one (DR-0005). A page served by it that could attempt a fix would undo the "
        "split this product is sold on."
    ),
    "try": "needs the Docker socket, which the receiver does not have (DR-0005).",
    "gateway": "needs the Docker socket, which the receiver does not have (DR-0005).",
    "init": (
        "writes the two files a deployment needs, before an instance exists. There is no page to "
        "put it on, because there is nothing running yet."
    ),
    "password": (
        "sets the credential that decides who may hold the session in future. DR-0025, accepted "
        "2026-08-11: a session obtained once — a borrowed laptop, an unlocked screen — would "
        "become permanent, silently, and unlike every other control here it could not be undone "
        "from the page. Rotating a read link revokes; setting a password grants."
    ),
}

#: Not yet, and the item that will place it. This list is the work remaining and it is meant to
#: empty; an entry here is a promise with a number on it rather than a decision.
#: **Empty, and it is meant to stay that way.** DR-0024 was the last thing in it: the receiver may
#: ask OSV now, so `deps` has a place rather than a promise. An entry here is a promise with a
#: number on it; the list existing is what stops one becoming a design.
NOT_YET: dict[str, str] = {}


@pytest.fixture
def an_operator() -> Acting:
    return Acting(csrf="c", offered=True)


@pytest.fixture
def an_instance(tmp_path: object, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    """One project and two items, because half these controls appear only when there is something
    for them to act on — which is why a route-table check could not see them."""
    import datetime as dt

    from sqlalchemy.orm import sessionmaker

    from hullwork.config import get_settings
    from hullwork.db import make_engine
    from hullwork.models import (
        Attempt,
        AttemptOutcome,
        AttemptPhase,
        Base,
        ItemState,
        Lane,
        Project,
    )

    url = f"sqlite:///{tmp_path}/place.db"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    session = sessionmaker(bind=engine)()
    project = Project(
        slug="shop", forge="forgejo", repo="acme/shop",
        webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
        tracker_project="shop",
    )
    # **And one that is not watched**, because stopping and starting are each offered only in the
    # state the other one leaves you in — the same reason there are two items below.
    session.add(
        Project(
            slug="stopped", forge="forgejo", repo="acme/stopped",
            webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
            active=False,
        )
    )
    session.add(project)
    session.flush()
    # **Two items, because the two item controls live in different states** and neither is wrong to
    # hide in the other: `requeue` is for one a red baseline left with a human, `approve` for one
    # waiting on a decision. A fixture with one of them measures whichever it happens to be.
    stopped = _Item(
        project_id=project.id, fingerprint="a", title="KeyError", state=ItemState.HUMAN_ONLY,
        lane=Lane.GREEN, last_seen=dt.datetime.now(dt.UTC),
    )
    waiting = _Item(
        project_id=project.id, fingerprint="b", title="ValueError",
        state=ItemState.WAITING_APPROVAL, lane=Lane.AMBER, last_seen=dt.datetime.now(dt.UTC),
        state_since=dt.datetime.now(dt.UTC),
    )
    session.add_all([stopped, waiting])
    session.flush()
    session.add(
        Attempt(
            item_id=stopped.id, phase_reached=AttemptPhase.BASELINE,
            outcome=AttemptOutcome.BASELINE_RED, consumed=False,
        )
    )
    session.commit()
    yield session
    get_settings.cache_clear()


def _every_command() -> Iterator[str]:
    """Every command this build offers, from the parser that offers them."""

    def walk(parser: argparse.ArgumentParser, prefix: tuple[str, ...] = ()) -> Iterator[str]:
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, sub in action.choices.items():
                    yield " ".join((*prefix, name))
                    yield from walk(sub, (*prefix, name))

    yield from walk(build_parser())


def test_no_command_is_undecided() -> None:
    """**The whole item.** A command in neither dictionary is one nobody has placed, and the way
    that reaches a release is exactly how the dependency half ended up invisible: nothing was ever
    wrong, so nothing ever failed."""
    placed = set(ON_THE_PAGE) | set(NEVER_ON_THE_PAGE) | set(NOT_YET)
    commands = set(_every_command())

    assert commands - placed == set(), f"no place and no reason: {sorted(commands - placed)}"
    gone = sorted(placed - commands)
    assert gone == [], f"placed, but no longer a command: {gone}"


def test_every_reason_is_a_sentence() -> None:
    """A reason of `""` or `"n/a"` would satisfy the test above and answer nobody. This is the
    cheapest way to keep the second dictionary from becoming a list of names."""
    for command, why in NEVER_ON_THE_PAGE.items():
        assert len(why) > 25, f"{command} has no real reason: {why!r}"
        assert why.endswith("."), f"{command}'s reason is not a sentence: {why!r}"


def test_nothing_is_both_placed_and_pending() -> None:
    """A command in two lists is a command whose status nobody can read off this file — and the one
    that would go unnoticed is `NOT_YET` left behind after the work landed."""
    assert set(ON_THE_PAGE) & set(NOT_YET) == set()
    assert set(ON_THE_PAGE) & set(NEVER_ON_THE_PAGE) == set()
    assert set(NEVER_ON_THE_PAGE) & set(NOT_YET) == set()


def test_every_promise_names_an_item() -> None:
    """`NOT_YET` is the work remaining, and a promise with no work item behind it is a wish. The
    file it names has to exist, which is what stops this list from outliving its plan."""
    from pathlib import Path

    work = Path(__file__).resolve().parent.parent / "work"
    if not work.is_dir():
        pytest.skip("the work items are withheld from the published tree, and this reads them")

    for command, item in NOT_YET.items():
        assert list(work.glob(f"{item}-*.md")), f"{command} promises item {item}, which is not one"


def test_every_placement_names_a_route_that_exists() -> None:
    """**Asserted against the app's own route table**, because a placement is a claim about where a
    person goes, and a claim naming a path that 404s is worse than no claim: it closes the question
    without answering it."""
    from hullwork.main import app

    routes = {getattr(one, "path", "") for one in app.routes}

    for command, (where, _) in ON_THE_PAGE.items():
        full = f"{page.PREFIX}/{{token}}/{where}" if where else f"{page.PREFIX}/{{token}}/"
        assert full in routes, f"{command} is placed at {where}, which is not a route"


def test_every_placement_is_something_a_person_can_press(
    an_instance: Session, an_operator: Acting
) -> None:
    """**The check that would have caught five of these** (item 223). A route in the table is not a
    place on a page: `refresh`, `disable`, `rotate-secret`, `set-tracker` and `requeue` all passed
    the test above with no button rendered anywhere, and on an item stuck `human-only` — the one
    state `requeue` is for — the only button on the page was *Sign out*.

    Rendered with an operator and with data in it, because half of these appear only for a session
    and half only for a project or an item that exists.
    """
    from hullwork.config import Settings

    settings = Settings()
    items = an_instance.query(_Item).order_by(_Item.id).all()
    views = {
        "instance": page.instance(
            an_instance, settings, error_reporting=False, acting=an_operator
        ),
        "doctor": page.why_it_will_not_work(an_instance, settings, acting=an_operator),
        "config": page.what_it_received(settings, acting=an_operator),
        "projects": page.projects(an_instance, settings, acting=an_operator),
        # Item 237: a feature lives inside the project it is about.
        "projects/{slug}/dependencies": "".join(
            page.dependencies(an_instance, settings, slug, acting=an_operator) or ""
            for slug in ("shop", "stopped")
        ),
        "projects/{slug}/settings": "".join(
            page.settings_for(an_instance, settings, slug, acting=an_operator) or ""
            for slug in ("shop", "stopped")
        ),
        # Both states, joined: a control offered only when it applies is not a control missing.
        "projects/{slug}": "".join(
            page.project(an_instance, settings, slug, acting=an_operator) or ""
            for slug in ("shop", "stopped")
        ),
        # Both states, joined: what is asserted is that the control exists in the state it is for.
        "items/{item_id}": "".join(
            page.item(an_instance, settings, one.id, acting=an_operator) or "" for one in items
        ),
    }

    for command, (where, rendered) in ON_THE_PAGE.items():
        shown = views.get(where)
        assert shown is not None, f"{command} names {where}, which this test does not render"
        wanted = rendered.replace("{id}", str(items[1].id)) if items else rendered
        assert wanted in shown, (
            f"{command} claims {where} and nothing there renders {wanted!r}"
        )
