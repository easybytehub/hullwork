"""What this instance has switched on. Item 203.

`hullwork features` answers for a **checkout** and hands four names back as somebody else's
question:

    INSTANCE_SHAPED = ("filing a production error as an issue", "the daily page",
                       "notifications", "the recurrence watch")

with the comment *`doctor` owns these*. It does not — `doctor` answers resources, and a resource is
not a feature. So four capabilities were declared by name as nobody's question, and the hole was
written down in the code before the operator asked for the dashboard that fills it.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import socket
import urllib.request

import pytest
from pydantic import SecretStr
from sqlalchemy.orm import Session

from hullwork import features
from hullwork.config import Settings
from hullwork.models import Project

FORGE = Settings(forge_url="https://forge.example.com", forge_token=SecretStr("t"))


def _project(session: Session, *, notify: str | None = None, active: bool = True) -> Project:
    manifest: dict[str, object] = {"project": "p"}
    if notify is not None:
        manifest["notify"] = {"channel": notify}
    project = Project(
        slug="p", forge="forgejo", repo="o/r", active=active,
        webhook_secret_hash="x",  # noqa: S106
        manifest=manifest,
    )
    session.add(project)
    session.commit()
    return project


def _named(standing: list[features.Standing], name: str) -> features.Standing:
    return next(one for one in standing if one.name == name)


# --- the hole item 186 named --------------------------------------------------------------------


def test_every_instance_shaped_feature_has_an_answer(session: Session) -> None:
    """The whole item. `features` names four and takes none of them; this takes all four, so the
    list stops being a question nobody has."""
    answered = {one.name for one in features.on_this_instance(session, Settings())}

    assert set(features.INSTANCE_SHAPED) <= answered


def test_nothing_is_still_handed_to_nobody() -> None:
    """**Asserted by construction.** A fifth name added to `INSTANCE_SHAPED` tomorrow has to be
    answered here without anybody remembering, or the hole reopens exactly as it was."""
    from inspect import getsource

    source = getsource(features.on_this_instance)

    assert "INSTANCE_SHAPED" in source, "the answers are derived from the list, not kept beside it"


# --- the three states ---------------------------------------------------------------------------


def test_a_configured_forge_with_a_project_can_file(session: Session) -> None:
    _project(session)

    filing = _named(
        features.on_this_instance(session, FORGE), "filing a production error as an issue"
    )

    assert filing.state is features.ON


def test_no_forge_is_a_cannot_that_says_what_to_do(session: Session) -> None:
    """A missing thing, with the remedy in words somebody can type."""
    _project(session)

    filing = _named(
        features.on_this_instance(session, Settings()), "filing a production error as an issue"
    )

    assert filing.state is features.CANNOT
    assert "HULLWORK_FORGE_URL" in filing.detail


def test_a_channel_nobody_chose_is_off_and_not_a_fault(session: Session) -> None:
    """**DR-0019's rule, on the instance side.** `notify: none` is the default and a decision, and
    showing a decision as a defect is the one way this dashboard could insult its reader."""
    _project(session, notify="none")

    notifications = _named(features.on_this_instance(session, Settings()), "notifications")

    assert notifications.state is features.OFF
    assert "cannot" not in notifications.detail.lower()


def test_a_channel_that_parses_and_does_not_deliver_is_a_cannot(session: Session) -> None:
    """`telegram` and `email` parse in the manifest and are refused at delivery, which `docs/status`
    says in prose and nothing said where somebody would look."""
    _project(session, notify="telegram")

    notifications = _named(features.on_this_instance(session, Settings()), "notifications")

    assert notifications.state is features.CANNOT
    assert "telegram" in notifications.detail


def test_the_page_is_off_until_somebody_mints_a_token(session: Session) -> None:
    """It is off until `page-token` is run, deliberately — and that is a decision, not a fault."""
    page = _named(features.on_this_instance(session, Settings()), "the daily page")

    assert page.state is features.OFF
    assert "page-token" in page.detail


# --- the bounds ---------------------------------------------------------------------------------


def test_it_asks_nothing_of_the_network(session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    """**This renders on a request.** A page that opened a socket per view would make somebody's
    dashboard a load test of their forge, and a reachability answer that costs a page load is one
    nobody refreshes."""

    def forbidden(*_a: object, **_k: object) -> None:
        raise AssertionError("the dashboard reached the network while rendering")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    _project(session)

    assert features.on_this_instance(session, FORGE)


def test_what_is_off_or_broken_comes_before_what_works(session: Session) -> None:
    """*On* is the least interesting state. A reader opens this looking for what is not working, and
    a wall of green with one red line in the middle is a wall of green."""
    _project(session, notify="telegram")

    standing = features.on_this_instance(session, FORGE)

    states = [one.state for one in standing]
    assert states == sorted(states, key=lambda one: one is features.ON)


def test_a_state_it_did_not_establish_is_not_claimed(session: Session) -> None:
    """Whether the forge *answers* costs a network call, and this makes none. Saying `on` about a
    configured-but-unreachable forge is items 193, 194 and 199 arriving in the dashboard."""
    _project(session)

    filing = _named(
        features.on_this_instance(session, FORGE), "filing a production error as an issue"
    )

    assert "configured" in filing.detail.lower()
    assert "answers" not in filing.detail.lower() or "not asked" in filing.detail.lower()
