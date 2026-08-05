"""The sweep asking the tracker for the full error (item 036, second half).

On a clock rather than on delivery, and that is the whole design. The tracker notifies once per
issue for the issue's entire life, so a fetch attempted only while a webhook was being handled
would never be prompted again — the same fact that already forced this system to keep its own
retry clock (item 013).
"""

from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from hullwork.ingest import fetch_context
from hullwork.models import Base, Event, FetchedEvent, Item, ItemState, Lane, Project
from hullwork.tracker import (
    FetchedEvent as FetchedEventData,
)
from hullwork.tracker import (
    Frame,
    PermanentTrackerError,
    RetryableTrackerError,
)

PERMALINK = "http://tracker.invalid/org/issues/6"



def _project(session: Session) -> Project:
    project = Project(
        slug="p", forge="forgejo", repo="o/r",
        webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
    )
    session.add(project)
    session.flush()
    return project


def _item(
    session: Session,
    *,
    permalink: str | None = PERMALINK,
    state: ItemState = ItemState.TRIAGED,
) -> Item:
    project = _project(session)
    item = Item(
        project_id=project.id, fingerprint="fp", title="ValueError: boom",
        lane=Lane.GREEN, state=state,
    )
    session.add(item)
    session.flush()
    if permalink is not None:
        delivery_free_event = Event(
            project_id=project.id, delivery_id=1, fingerprint="fp",
            title="ValueError: boom", permalink=permalink, raw={},
        )
        session.add(delivery_free_event)
    session.flush()
    return item


def _event(**overrides: object) -> FetchedEventData:
    defaults: dict[str, object] = {
        "provider_event_id": "evt-1",
        "exception_type": "ValueError",
        "message": "boom",
        "frames": (Frame(abs_path="/app/x.py", lineno=3, function="f", context_line="raise"),),
        "packages": {"fastapi": "0.140.1"},
        "release": "b292599",
    }
    defaults.update(overrides)
    return FetchedEventData(**defaults)  # type: ignore[arg-type]


class _Tracker:
    def __init__(self, result: object = None) -> None:
        self.result = result
        self.calls: list[str] = []

    def fetch_latest(self, permalink: str) -> FetchedEventData | None:
        self.calls.append(permalink)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result  # type: ignore[return-value]

    def fetch_samples(self, permalink: str, limit: int = 2) -> list[FetchedEventData]:
        return []


def test_no_tracker_configured_changes_nothing() -> None:
    """The default, under DR-0002. Everything M1 does works without this credential."""
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as session:
        _item(session)

        assert fetch_context(session, None) == 0
        assert session.query(FetchedEvent).count() == 0


def test_the_full_error_is_stored_against_the_item(session: Session) -> None:
    item = _item(session)
    tracker = _Tracker(_event())

    assert fetch_context(session, tracker) == 1

    stored = session.query(FetchedEvent).one()
    assert stored.item_id == item.id
    assert stored.exception_type == "ValueError"
    assert stored.frames[0]["lineno"] == 3
    assert stored.frames[0]["abs_path"] == "/app/x.py"
    assert stored.packages == {"fastapi": "0.140.1"}
    assert stored.release == "b292599"
    assert tracker.calls == [PERMALINK]


def test_the_permalink_comes_from_the_item_s_event(session: Session) -> None:
    """`Item` carries no permalink; the join on (project, fingerprint) is the only route."""
    _item(session, permalink="http://tracker.invalid/org/issues/99")
    tracker = _Tracker(_event())

    fetch_context(session, tracker)

    assert tracker.calls == ["http://tracker.invalid/org/issues/99"]


def test_an_item_with_no_permalink_says_so_instead_of_failing(session: Session) -> None:
    item = _item(session, permalink=None)

    assert fetch_context(session, _Tracker(_event())) == 0
    assert item.context_error is not None
    assert "permalink" in item.context_error


def test_a_retryable_failure_leaves_the_item_fetchable(session: Session) -> None:
    """"The tracker was briefly down" must never become "this item has no context, forever"."""
    item = _item(session)

    assert fetch_context(session, _Tracker(RetryableTrackerError("502"))) == 0

    assert session.query(FetchedEvent).count() == 0
    assert item.context_error is not None
    assert item.context_error.startswith("retryable")
    # Checked, so the next pass backs off rather than hammering — but nothing is sealed.
    assert item.context_checked_at is not None


def test_a_permanent_failure_is_recorded_as_such(session: Session) -> None:
    item = _item(session)

    fetch_context(session, _Tracker(PermanentTrackerError("bad credentials")))

    assert item.context_error is not None
    assert item.context_error.startswith("permanent")


def test_a_deleted_issue_is_ordinary_news(session: Session) -> None:
    item = _item(session)

    assert fetch_context(session, _Tracker(None)) == 0
    assert item.context_error is not None
    assert "no longer has" in item.context_error


def test_an_item_that_already_has_a_sample_is_not_refetched(session: Session) -> None:
    """Otherwise every item is asked about on every pass for the rest of its life."""
    _item(session)
    tracker = _Tracker(_event())
    fetch_context(session, tracker)

    assert fetch_context(session, tracker) == 0
    assert len(tracker.calls) == 1


def test_a_done_item_is_left_alone(session: Session) -> None:
    """More context changes nothing once the work is over.

    **`human-only` was a second parameter here and it encoded a defect.** DR-0008 part 1 names it:
    a red lane is frequently red *because* the frames had not arrived — the tracker's webhook
    carries none — so excluding red items from enrichment made the decision taken on the poorest
    evidence the one decision this system never revisited. Item 070 took `human-only` out of
    `_SETTLED`, and `tests/test_relane.py` asserts the stronger claim that replaces this one: such
    an item is enriched *and* its lane is decided again on the culprit that arrives.

    `done` stays, and stays asserted. An item that is finished is finished.
    """
    _item(session, state=ItemState.DONE)
    tracker = _Tracker(_event())

    assert fetch_context(session, tracker) == 0
    assert tracker.calls == []


def test_a_recently_checked_item_is_not_asked_again(session: Session) -> None:
    item = _item(session)
    item.context_checked_at = datetime.now(UTC) - timedelta(seconds=10)
    session.flush()
    tracker = _Tracker(_event())

    assert fetch_context(session, tracker, recheck_after=600) == 0
    assert tracker.calls == []


def test_a_stale_check_is_asked_again(session: Session) -> None:
    item = _item(session)
    item.context_checked_at = datetime.now(UTC) - timedelta(seconds=3600)
    session.flush()

    assert fetch_context(session, _Tracker(_event()), recheck_after=600) == 1


def test_the_limit_is_respected(session: Session) -> None:
    project = _project(session)
    for n in range(5):
        item = Item(project_id=project.id, fingerprint=f"fp{n}", title="t", lane=Lane.GREEN)
        session.add(item)
        session.flush()
        session.add(Event(project_id=project.id, delivery_id=1, fingerprint=f"fp{n}",
                          title="t", permalink=PERMALINK, raw={}))
    session.flush()
    tracker = _Tracker(_event())

    assert fetch_context(session, tracker, limit=2) == 2
