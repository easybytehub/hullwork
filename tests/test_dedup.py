"""Deduplication and triage, against a real migrated database.

The behaviour under test is mostly about what must *not* happen: no second item, no notification, no
issue. Silence is the feature.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import Session

from hullwork.config import get_settings
from hullwork.db import make_engine, make_session_factory
from hullwork.dedup import Outcome, resolve
from hullwork.manifest import Manifest, parse_manifest
from hullwork.models import Item, ItemState, Lane, Project
from hullwork.normalise import ErrorFact, derive_fingerprint
from hullwork.states import transition
from hullwork.triage import choose_lane

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)

MANIFEST = """
project: demo
git: {provider: forgejo, repo: acme/demo}
autofix:
  lanes:
    green: [checkout]
    amber: [migrations]
    red: [payment, auth]
"""


@pytest.fixture
def session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path / 'dedup-test.db'}"
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.cmd_opts = None
    command.upgrade(cfg, "head")

    factory = make_session_factory(make_engine(url))
    with factory() as db:
        db.add(
            Project(
                slug="demo",
                forge="forgejo",
                repo="acme/demo",
                webhook_secret_hash="not-a-real-hash",  # noqa: S106 - fixture
            )
        )
        db.commit()
        yield db
    get_settings.cache_clear()


@pytest.fixture
def manifest() -> Manifest:
    return parse_manifest(MANIFEST)


def _fact(title: str = "TypeError in cart", culprit: str | None = "app.cart in total") -> ErrorFact:
    return ErrorFact(
        provider="glitchtip",
        project_ref="demo",
        title=title,
        culprit=culprit,
        external_id="4821",
        fingerprint=derive_fingerprint("glitchtip", title),
        fingerprint_derived=True,
        level="error",
        permalink="https://glitchtip.example.com/easybyte/issues/4821",
        timestamps_are_receipt_time=True,
        first_seen=NOW,
        last_seen=NOW,
        raw={},
    )


def test_a_new_error_creates_a_triaged_item(session: Session, manifest: Manifest) -> None:
    result = resolve(session, 1, _fact(), manifest)

    assert result.outcome is Outcome.CREATED
    assert result.item.state is ItemState.TRIAGED
    assert result.item.occurrences == 1
    assert result.needs_attention


def test_the_same_error_again_is_silent(session: Session, manifest: Manifest) -> None:
    # The 80% case. No new item, no notification, nothing but a counter.
    resolve(session, 1, _fact(), manifest)
    result = resolve(session, 1, _fact(), manifest)

    assert result.outcome is Outcome.DEDUPLICATED
    assert result.item.occurrences == 2
    assert not result.needs_attention
    assert session.query(Item).count() == 1


def test_an_error_returning_after_being_closed_is_a_regression(
    session: Session, manifest: Manifest
) -> None:
    # A green-lane fact, because only those travel the agent path to `done`. The green pattern
    # has to match the CULPRIT: a match in the title alone is text the reporter controls, and
    # since item 017 that buys no leniency.
    green = {"title": "TypeError in cart", "culprit": "app.checkout in submit"}
    first = resolve(session, 1, _fact(**green), manifest).item
    assert first.lane is Lane.GREEN
    for step in (ItemState.READY, ItemState.IN_PROGRESS, ItemState.PR_OPEN, ItemState.DONE):
        transition(first, step)
    session.commit()

    result = resolve(session, 1, _fact(**green), manifest)

    assert result.outcome is Outcome.REOPENED
    assert result.item.regression is True
    assert result.needs_attention  # a regression must reach a human

    # It passes THROUGH `reopened` and lands in `triaged`. This assertion used to read
    # `is ItemState.REOPENED`, which encoded the defect: nothing ever performed the only transition
    # out of that state, so the item was stuck, and the next human to close its issue crashed the
    # sweep on an illegal `reopened → done` — permanently, for every project (item 016).
    assert result.item.state is ItemState.TRIAGED


def test_an_error_arriving_while_still_open_is_not_a_regression(
    session: Session, manifest: Manifest
) -> None:
    # Only a *closed* item can regress. An open one is just happening again.
    green = {"title": "TypeError in cart", "culprit": "app.checkout in submit"}
    item = resolve(session, 1, _fact(**green), manifest).item
    transition(item, ItemState.READY)
    session.commit()

    result = resolve(session, 1, _fact(**green), manifest)

    assert result.outcome is Outcome.DEDUPLICATED
    assert result.item.regression is False


def test_two_different_errors_are_two_items(session: Session, manifest: Manifest) -> None:
    resolve(session, 1, _fact(title="TypeError in cart"), manifest)
    resolve(session, 1, _fact(title="OperationalError in db"), manifest)

    assert session.query(Item).count() == 2


def test_the_lane_comes_from_the_manifest_and_says_why(
    session: Session, manifest: Manifest
) -> None:
    result = resolve(session, 1, _fact(title="Error in payment adapter"), manifest)

    assert result.item.lane is Lane.RED
    assert result.item.lane_reason is not None
    assert "payment" in result.item.lane_reason


def test_an_unmatched_error_defaults_to_red(session: Session, manifest: Manifest) -> None:
    # The safe default is a human looking at it.
    result = resolve(session, 1, _fact(title="Something nobody predicted", culprit=None), manifest)

    assert result.item.lane is Lane.RED
    assert result.item.lane_reason is not None
    assert "defaulting to red" in result.item.lane_reason


def test_red_wins_over_green_when_both_match(manifest: Manifest) -> None:
    # "checkout" is green and "payment" is red; overlapping rules must resolve towards caution.
    decision = choose_lane(manifest, _fact(title="checkout failed", culprit="payment gateway"))

    assert decision.lane is Lane.RED


def test_a_regression_is_retriaged_rather_than_inheriting_its_old_lane(
    session: Session, manifest: Manifest
) -> None:
    green = {"title": "TypeError in cart", "culprit": "app.checkout in submit"}
    item = resolve(session, 1, _fact(**green), manifest).item
    assert item.lane is Lane.GREEN
    for step in (ItemState.READY, ItemState.IN_PROGRESS, ItemState.PR_OPEN, ItemState.DONE):
        transition(item, step)
    session.commit()

    # Same fingerprint, but the manifest now classifies this text as red.
    stricter = parse_manifest(MANIFEST.replace("red: [payment, auth]", "red: [payment, checkout]"))
    result = resolve(session, 1, _fact(**green), stricter)

    assert result.item.lane is Lane.RED
