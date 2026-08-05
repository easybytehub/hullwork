"""`fetch_context` keeps the timestamp that says it asked. Item 083.

The defect behind issue 15 on the live instance, and its message pointed at the wrong line:

```
OperationalError: ['raised as a result of Query-invoked autoflush; …']
  ingest.py:348  if session.query(FetchedEvent)…count():
     → flush() → _emit_update_statements → database is locked
```

The `UPDATE` that failed belonged to a **previous iteration**. The loop wrote
`item.context_checked_at` and moved on without committing, so the write sat pending until the next
item's `SELECT` forced it out through autoflush — reporting the failure inside a query on
`fetched_events` when the statement that failed was an update on `items`, one item earlier.

Underneath that was something quieter and worse: `if fetched: commit() else: flush()`. A flush
commits
nothing, `_sweep_once` closes the session immediately afterwards, and SQLAlchemy rolls it back — so
a
pass that fetched nothing lost every timestamp it wrote, and the same items were asked about again
sixty seconds later, for ever.

**Every assertion here reads the rows back from a new session.** That is the whole point: a flush is
invisible to the test that keeps using the session that made it.
"""

from collections.abc import Iterator, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import Session, sessionmaker

from hullwork.config import get_settings
from hullwork.db import make_engine, make_session_factory
from hullwork.forge import PermanentForgeError
from hullwork.ingest import fetch_context
from hullwork.models import Delivery, Event, Item, ItemState, Project
from hullwork.tracker import FetchedEvent as FetchedEventData
from hullwork.tracker import RetryableTrackerError

ROOT = Path(__file__).resolve().parent.parent


class _Silent:
    """A tracker that has nothing to give. The commonest pass on a healthy instance."""

    def __init__(self) -> None:
        self.asked: list[str] = []

    def fetch_latest(self, permalink: str) -> FetchedEventData | None:
        self.asked.append(permalink)
        return None

    def fetch_samples(self, permalink: str, limit: int = 2) -> Sequence[FetchedEventData]:
        return []


class _Refusing(_Silent):
    def fetch_latest(self, permalink: str) -> FetchedEventData | None:
        self.asked.append(permalink)
        raise RetryableTrackerError("the tracker timed out")


class _RaisesHalfway(_Silent):
    """Answers for the first item and explodes on the second, uncaught by `fetch_context`."""

    def fetch_latest(self, permalink: str) -> FetchedEventData | None:
        self.asked.append(permalink)
        if len(self.asked) > 1:
            msg = "something nobody anticipated"
            raise RuntimeError(msg)
        return None


@pytest.fixture
def factory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[sessionmaker[Session]]:
    url = f"sqlite:///{tmp_path / 'backoff.db'}"
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.cmd_opts = None
    command.upgrade(cfg, "head")
    yield make_session_factory(make_engine(url))
    get_settings.cache_clear()


def _items(factory: sessionmaker[Session], count: int = 3) -> list[int]:
    """Items with a permalink, so the loop reaches the tracker for each of them."""
    with factory() as session:
        project = Project(
            slug="p", forge="forgejo", repo="o/r",
            webhook_secret_hash="x",  # noqa: S106
            manifest={"project": "p", "autofix": {"agent": "none"}},
        )
        session.add(project)
        session.flush()
        # `events.delivery_id` is NOT NULL, so a delivery has to exist for the event to hang off.
        delivery = Delivery(
            project_id=project.id,
            provider="glitchtip",
            provider_delivery_id="d1",
            payload_hash="h",
            payload_json="{}",
        )
        session.add(delivery)
        session.flush()
        ids = []
        for index in range(count):
            item = Item(
                project_id=project.id,
                fingerprint=f"fp{index}",
                title="ValueError: boom",
                state=ItemState.TRIAGED,
            )
            session.add(item)
            session.flush()
            # The permalink lives on the event, joined by `(project_id, fingerprint)` — `Item` does
            # not carry one. See `ingest._permalink_for`.
            session.add(
                Event(
                    project_id=project.id,
                    delivery_id=delivery.id,
                    fingerprint=f"fp{index}",
                    fingerprint_derived=True,
                    title="ValueError: boom",
                    permalink=f"http://tracker/x/issues/{index + 1}",
                    timestamps_are_receipt_time=True,
                    raw={},
                )
            )
            ids.append(item.id)
        session.commit()
        return ids


def _checked(factory: sessionmaker[Session], ids: list[int]) -> dict[int, datetime | None]:
    """Read the timestamps back **from a new session**, which is what a flush does not survive."""
    with factory() as session:
        return {
            item_id: session.get(Item, item_id).context_checked_at  # type: ignore[union-attr]
            for item_id in ids
        }


# --- the timestamp survives ----------------------------------------------------------------------


def test_a_pass_that_fetches_nothing_still_records_that_it_asked(
    factory: sessionmaker[Session],
) -> None:
    """**The defect, and the commonest pass on a healthy instance.**

    `if fetched: commit() else: flush()` — so with the tracker having nothing to give, every
    `context_checked_at` written by the pass was rolled back when the session closed.
    """
    ids = _items(factory)
    tracker = _Silent()

    with factory() as session:
        assert fetch_context(session, tracker) == 0, "nothing was fetched, which is the case"

    assert len(tracker.asked) == 3
    stamps = _checked(factory, ids)
    assert all(stamp is not None for stamp in stamps.values()), (
        "every item the pass looked at must be recorded as checked, or the backoff does not exist"
    )


def test_the_same_items_are_not_asked_about_again_within_the_window(
    factory: sessionmaker[Session],
) -> None:
    """What the timestamp is *for*. Both halves, or this only proves the pass can go quiet."""
    ids = _items(factory)

    first = _Silent()
    with factory() as session:
        fetch_context(session, first, recheck_after=600)
    assert len(first.asked) == 3

    second = _Silent()
    with factory() as session:
        fetch_context(session, second, recheck_after=600)
    assert second.asked == [], "asked again inside the window: up to 20 requests a minute, for ever"

    # …and once the window has passed, they are asked about again.
    with factory() as session:
        for item_id in ids:
            item = session.get(Item, item_id)
            assert item is not None
            item.context_checked_at = datetime.now(UTC) - timedelta(hours=1)
        session.commit()

    third = _Silent()
    with factory() as session:
        fetch_context(session, third, recheck_after=600)
    assert len(third.asked) == 3


def test_a_retryable_failure_still_backs_off(factory: sessionmaker[Session]) -> None:
    """A failure nobody records is a failure that repeats every minute."""
    ids = _items(factory)

    with factory() as session:
        fetch_context(session, _Refusing(), recheck_after=600)

    with factory() as session:
        errors = [session.get(Item, i).context_error for i in ids]  # type: ignore[union-attr]
    assert all(error is not None and "retryable" in error for error in errors)
    assert all(stamp is not None for stamp in _checked(factory, ids).values())


def test_an_unexpected_failure_does_not_cost_the_earlier_items_their_backoff(
    factory: sessionmaker[Session],
) -> None:
    """One bad item must not undo the pass that came before it — the `finally`'s reason."""
    ids = _items(factory)

    with factory() as session, pytest.raises(RuntimeError):
        fetch_context(session, _RaisesHalfway())

    stamps = _checked(factory, ids)
    assert stamps[ids[0]] is not None, "the first item was handled and must stay handled"


# --- no write is left pending for the next iteration's SELECT ------------------------------------


def test_nothing_is_pending_when_the_loop_queries_again(
    factory: sessionmaker[Session],
) -> None:
    """**The mechanism that reported the failure one item away from its cause.**

    The loop's `SELECT` on `fetched_events` triggered autoflush, which emitted the previous item's
    `UPDATE` — so a write failure surfaced inside an unrelated query. Asserted on the connection at
    the moment of each `SELECT`, because that is the only place the difference is visible.
    """
    ids = _items(factory)
    pending_at_query: list[bool] = []

    class _Watching(_Silent):
        def __init__(self, session: Session) -> None:
            super().__init__()
            self.session = session

        def fetch_latest(self, permalink: str) -> FetchedEventData | None:
            # Called after this item's `SELECT` and before the next one's: if the previous
            # iteration's write were still pending, it would be pending here too.
            raw = self.session.connection().connection.dbapi_connection
            assert raw is not None
            pending_at_query.append(bool(raw.in_transaction))
            return super().fetch_latest(permalink)

    with factory() as session:
        fetch_context(session, _Watching(session))

    assert len(pending_at_query) == len(ids)
    assert not any(pending_at_query[1:]), (
        "a write from the previous iteration was still open, so the next query would emit it"
    )


# --- a closed item is not owed an issue. Item 084 ------------------------------------------------


def test_a_closed_item_is_not_filed(factory: sessionmaker[Session]) -> None:
    """**Measured on the live instance: four `PATCH … 404` a minute, `forge_attempts` at 38.**

    `forge_sync_pending` is the intent to file, and an item can be closed while still carrying it.
    Filing for a bug already settled is work with no reader, and when the issue it points at is gone
    the attempt can never succeed — so it repeats for the life of the instance.

    The per-pass cap bounds one pass; it does not retire an item that can never be filed.
    """
    from hullwork.ingest import drain_unmaterialised

    ids = _items(factory, count=2)
    with factory() as session:
        settled = session.get(Item, ids[0])
        assert settled is not None
        settled.state = ItemState.DONE
        settled.forge_sync_pending = True
        settled.forge_issue_ref = "#404"
        live = session.get(Item, ids[1])
        assert live is not None
        live.forge_sync_pending = True
        session.commit()

    asked: list[int] = []

    class _Forge:
        def get_issue(self, repo: str, number: int) -> object | None:
            return None

        def set_issue_state(self, repo: str, number: int, state: str) -> object:
            asked.append(number)
            msg = "no such issue"
            raise PermanentForgeError(msg, 404)

        def find_issue_by_marker(self, repo: str, fingerprint: str) -> object | None:
            return None

        def ensure_labels(self, repo: str, names: dict[str, str]) -> dict[str, int]:
            return dict.fromkeys(names, 1)

        def create_issue(
            self, repo: str, title: str, body: str, label_ids: list[int] | None = None
        ) -> object:
            asked.append(-1)
            return SimpleNamespace(
                number=9, title=title, state="open", html_url="http://forge/9", ref="#9"
            )

        def comment(self, repo: str, number: int, body: str) -> None:
            pass

    with factory() as session:
        drain_unmaterialised(session, _Forge())  # type: ignore[arg-type]

    assert 404 not in asked, "the closed item must not be touched at all"
    assert asked == [-1], "and the open one still gets its issue created"


def test_a_closed_item_is_not_counted_as_backlog_either(
    factory: sessionmaker[Session],
) -> None:
    """The other two places that ask, kept in step with the drain. Item 084.

    Excluding the closed item from the selection and not from the count left `status` reporting
    "4 item(s) owed an issue" for ever — a backlog that can never reach zero, over an exit code of
    zero. Measured on the live instance immediately after the drain fix deployed.
    """
    from hullwork import readiness
    from hullwork.config import get_settings as settings_fn

    ids = _items(factory, count=2)
    with factory() as session:
        settled = session.get(Item, ids[0])
        assert settled is not None
        settled.state = ItemState.DONE
        settled.forge_sync_pending = True
        live = session.get(Item, ids[1])
        assert live is not None
        live.forge_sync_pending = True
        session.commit()

    with factory() as session:
        report = readiness.check(session, settings_fn(), error_reporting=False)

    assert report.backlog == 1, "the open item counts; the settled one is owed nothing"
