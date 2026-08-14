"""What the page may say about a dispatcher that is working. Item 242.

The operator, watching a verification queue he could only see through `docker logs`: *sería
interesante ver en la página web qué está pasando. Ahora mismo no tenemos trazabilidad ninguna.*

It was worse than missing. The instance report has a band for *the attempt in flight* and it read
**nothing running** while the dispatcher spent five minutes building an image and running somebody
else's suite twice — because it looked at `Item.state == IN_PROGRESS`, and a verification is not an
item. A page that reports calm during four minutes of work is not missing a feature; it is answering
wrongly.

So the dispatcher says what it is doing and the page reads that. Two claims are worth guarding: that
it is **the dispatcher's own word**, and that a **stale heartbeat is not busy** — a process killed
mid-sentence leaves its last one behind, and rendering that as *now* is this page's own version of
the defect it fixes.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from hullwork import lease, page
from hullwork.config import Settings, get_settings
from hullwork.db import make_engine
from hullwork.models import Base, DependencyReport, DispatcherLease, Project, UpgradeVerdict

SIGNED_IN = page.Acting(csrf="c", offered=True)


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path}/doing.db"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    session = sessionmaker(bind=engine)()
    session.add(
        Project(
            slug="shop", forge="forgejo", repo="acme/shop",
            webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
        )
    )
    session.commit()
    yield session
    get_settings.cache_clear()


def _holding(db: Session) -> str:
    holder = lease.new_holder()
    assert lease.acquire(db, holder)
    return holder


def _door(db: Session) -> str:
    return page.front_door(db, Settings(), acting=SIGNED_IN)


# --- what it is doing ---------------------------------------------------------------------------


def test_the_page_says_what_the_dispatcher_said(db: Session) -> None:
    """**The whole item.** Not deduced: everything a page could infer has the same hole in the
    middle, and that hole is the four minutes somebody is trying to watch."""
    holder = _holding(db)
    lease.doing(db, holder, "shop: verifying cryptography 48.0.1 → 49.0.0")

    shown = _door(db)

    assert "shop: verifying cryptography 48.0.1 → 49.0.0" in shown
    assert "working" in shown


def test_it_says_how_long_that_has_been_going_on(db: Session) -> None:
    """A step that has taken nine minutes is the interesting one, and *what* alone cannot say so."""
    holder = _holding(db)
    lease.doing(db, holder, "shop: building the image")
    row = db.get(DispatcherLease, 1)
    assert row is not None
    row.doing_since = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=9)
    db.commit()

    assert "for 9m" in _door(db)


def test_the_clock_does_not_restart_while_the_step_is_the_same(db: Session) -> None:
    """The loop writes this every turn. If each write moved the timestamp, a nine-minute step would
    read as *just now* for ever — the permanently-reset version of item 073's rule."""
    holder = _holding(db)
    lease.doing(db, holder, "shop: verifying x")
    row = db.get(DispatcherLease, 1)
    assert row is not None
    row.doing_since = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=6)
    db.commit()

    lease.doing(db, holder, "shop: verifying x")

    db.refresh(row)
    assert row.doing_since is not None
    assert (dt.datetime.now(dt.UTC) - row.doing_since).total_seconds() > 300


def test_an_idle_dispatcher_says_so_and_says_it_is_there(db: Session) -> None:
    """**Idle and unreachable are different facts**, and a door that renders nothing in both cases
    answers *is it running?* with silence — which is the question that was opened to ask."""
    holder = _holding(db)
    lease.doing(db, holder, "shop: verifying x")
    lease.doing(db, holder, None)

    shown = _door(db)

    assert "nothing running" in shown
    assert "The dispatcher answered" in shown
    assert "verifying x" not in shown


def test_an_instance_with_no_dispatcher_at_all_says_what_that_costs(db: Session) -> None:
    """The state an evaluator meets first, and the one where every queue silently stops."""
    shown = _door(db)

    assert "no dispatcher" in shown
    assert "Nothing will be attempted or verified until one does" in shown


# --- and what it must never claim ----------------------------------------------------------------


def test_a_stale_heartbeat_is_not_busy(db: Session) -> None:
    """**The defect this page would otherwise inherit.** A dispatcher killed mid-sentence leaves its
    last one behind, and rendering it as *now* claims work that stopped — which is the same shape as
    the band that read *nothing running* through five minutes of it."""
    holder = _holding(db)
    lease.doing(db, holder, "shop: verifying cryptography 48.0.1 → 49.0.0")
    row = db.get(DispatcherLease, 1)
    assert row is not None
    row.renewed_at = dt.datetime.now(dt.UTC) - dt.timedelta(hours=4)
    db.commit()

    shown = _door(db)

    assert "not answering" in shown
    assert "what it was doing rather than what it is doing" in shown
    assert "working</span>" not in shown


def test_a_dispatcher_that_was_released_leaves_nothing_behind(db: Session) -> None:
    """A stopped dispatcher is not still doing the last thing it was doing."""
    holder = _holding(db)
    lease.doing(db, holder, "shop: verifying x")
    lease.release(db, holder)

    assert "verifying x" not in _door(db)


def test_only_the_dispatcher_that_holds_the_lease_may_say_what_it_is_doing(db: Session) -> None:
    """**A second process must not narrate over the one that is working.** Losing a lease mid-run is
    the state `renew` exists to catch; a stale process still writing here would put its sentence on
    the page under the live one's name, which is worse than saying nothing.

    The fixture holds the lease first, because a write that finds no lease at all returns either
    way — and a test that measured that would pass over the defect.
    """
    holder = _holding(db)
    lease.doing(db, holder, "shop: verifying the real one")

    lease.doing(db, "somebody-else", "shop: verifying x")

    shown = _door(db)
    assert "verifying the real one" in shown
    assert "verifying x" not in shown


# --- and what it has been doing -------------------------------------------------------------------


def test_the_recent_history_merges_what_is_already_stored(db: Session) -> None:
    """**No log table.** A second record of the same events could disagree with the first, and then
    a reader has to decide which to believe."""
    project = db.query(Project).one()
    db.merge(
        UpgradeVerdict(
            project_id=project.id, package="cryptography", was="48.0.1", to="49.0.0",
            outcome="clean", detail="", tried_at=dt.datetime.now(dt.UTC) - dt.timedelta(minutes=2),
        )
    )
    db.merge(
        DependencyReport(
            project_id=project.id, taken_at=dt.datetime.now(dt.UTC) - dt.timedelta(hours=1),
            asked=True, pinned=50, findings=[],
        )
    )
    db.commit()

    shown = _door(db)

    assert "What it has been doing" in shown
    assert "tried cryptography 48.0.1 → 49.0.0" in shown
    assert "asked OSV about 50 pinned version(s)" in shown
    # Newest first: a history in the other order buries what just happened under what happened
    # yesterday, which is the reading nobody wants.
    assert shown.index("tried cryptography") < shown.index("asked OSV")


def test_a_report_that_could_not_be_taken_is_not_dressed_as_one_that_was(db: Session) -> None:
    """DR-0024's condition, carried into the history: *could not ask* is not a report."""
    project = db.query(Project).one()
    db.merge(
        DependencyReport(
            project_id=project.id, taken_at=dt.datetime.now(dt.UTC), asked=False, pinned=0,
            note="OSV timed out", findings=[],
        )
    )
    db.commit()

    shown = _door(db)

    assert "could not ask OSV" in shown
    assert "with something published" not in shown


def test_an_instance_that_has_done_nothing_shows_no_history(db: Session) -> None:
    """An empty list titled *what it has been doing* is furniture claiming to be information."""
    assert "What it has been doing" not in _door(db)


def test_the_history_is_set_as_sentences_and_not_as_labels(db: Session) -> None:
    """**Seen in a browser.** `.standing .name` is small caps because it holds a thing's name —
    `CRYPTOGRAPHY 48.0.1` — and the history holds whole sentences, which small caps makes slower to
    read and louder than the thing they describe."""
    project = db.query(Project).one()
    db.merge(
        UpgradeVerdict(
            project_id=project.id, package="x", was="1", to="2", outcome="clean", detail="",
            tried_at=dt.datetime.now(dt.UTC),
        )
    )
    db.commit()

    shown = _door(db)
    history = shown[shown.index("What it has been doing") :]

    assert '<span class="said">' in history
    assert '<span class="name">' not in history, "the history is set as labels"
    assert ".standing .said" in page._STYLE
