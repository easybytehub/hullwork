"""The full error, on the item's own view. Item 232.

`FetchedEvent` is the largest object in the system — the untruncated message, the frames with their
source context, the locals, and the 33 to 71 dependency versions pinned at the moment it failed. It
is what item 036 built the tracker reader for, it is what an attempt is constructed from, and it
appeared on the page zero times.

**The webhook cuts the title at 100 characters**, and the model says why that is not a detail: for a
`KeyError` or a `ValueError` the half it cuts is often the input that reproduces the bug. The item's
title is the cut version; the whole one lives here and nowhere else on this page.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from hullwork import page
from hullwork.config import Settings, get_settings
from hullwork.db import make_engine
from hullwork.models import Base, FetchedEvent, Item, ItemState, Lane, Project

SIGNED_IN = page.Acting(csrf="c", offered=True)

#: The half a webhook cuts. The item's title stops at *checkout*; the input is after it.
WHOLE = "KeyError: 'total' in checkout — the input that reproduces it: {'lines': []}"


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path}/error.db"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    session = sessionmaker(bind=engine)()
    project = Project(
        slug="shop", forge="forgejo", repo="acme/shop",
        webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
    )
    session.add(project)
    session.flush()
    session.add(
        Item(
            project_id=project.id, fingerprint="f", title="KeyError: 'total' in checkout",
            state=ItemState.NEW, lane=Lane.GREEN, last_seen=dt.datetime.now(dt.UTC),
        )
    )
    session.commit()
    yield session
    get_settings.cache_clear()


def _recorded(db: Session, **fields: object) -> FetchedEvent:
    item = db.query(Item).one()
    seen = db.query(FetchedEvent).count()
    fetched = FetchedEvent(
        item_id=item.id,
        provider_event_id=f"ev-{seen}",
        exception_type="KeyError",
        message=WHOLE,
        culprit="app/checkout.py in total",
        level="error",
        handled=False,
        occurred_at=dt.datetime.now(dt.UTC) - dt.timedelta(hours=3),
        frames=[
            {
                "filename": "app/checkout.py",
                "function": "total",
                "lineno": 42,
                "context_line": "return sum(line['total'] for line in lines)",
                "variables": {"lines": "[]", "user_id": "9"},
            }
        ],
        packages={"requests": "2.31.0", "fastapi": "0.115.0"},
    )
    for name, value in fields.items():
        setattr(fetched, name, value)
    db.add(fetched)
    db.commit()
    return fetched


def _view(db: Session) -> str:
    item = db.query(Item).one()
    return page.item(db, Settings(), item.id, acting=SIGNED_IN) or ""


# --- what it shows -------------------------------------------------------------------------------


def test_the_untruncated_message_is_there_and_says_it_is(db: Session) -> None:
    """**The item's title is the cut one.** A page that showed only it would be showing the half
    the provider kept rather than the half that reproduces the bug."""
    _recorded(db)

    shown = _view(db)

    assert "the input that reproduces it" in shown
    assert "untruncated" in shown
    assert "cuts it at 100" in shown


def test_the_frames_carry_the_line_they_stopped_on(db: Session) -> None:
    _recorded(db)

    shown = _view(db)

    assert "app/checkout.py" in shown
    assert "line 42" in shown
    assert "sum(line[" in shown, "the source line itself is not there"


def test_the_locals_are_behind_their_own_disclosure(db: Session) -> None:
    """**The sharpest thing on this page.** Scrubbed on the way in, and still what a reader is
    least often looking for and most likely to be surprised to find rendered."""
    _recorded(db)

    shown = _view(db)
    fold = re.search(r"<details[^>]*>\s*<summary>What the code was holding here", shown)

    assert fold is not None, "the locals are not folded"
    assert " open" not in fold.group(0), "they are open, so they are read whether or not you asked"
    assert "user_id" in shown


def test_the_pinned_versions_are_counted_not_poured_out(db: Session) -> None:
    """33 to 71 of them. A wall of versions above the stack would bury the stack."""
    _recorded(db)

    shown = _view(db)

    assert "2 version(s)" in shown
    fold = re.search(r"<details[^>]*>\s*<summary>What was installed when it failed", shown)
    assert fold is not None and " open" not in fold.group(0)


def test_more_than_one_occurrence_says_why_that_is_worth_having(db: Session) -> None:
    """Several rows per item are allowed on purpose: what differs between two samples is usually
    the input that triggers it, and it is the only route to occurrences 2..N."""
    _recorded(db)
    _recorded(db)

    shown = _view(db)

    assert "2 occurrences" in shown
    assert "once per issue and never again" in shown


# --- and what it must not claim -------------------------------------------------------------------


def test_a_pruned_event_says_it_was_forgotten(db: Session) -> None:
    """**`prune` empties the row and keeps it.** Rendering *no frames* would report an error with no
    stack rather than one whose stack this instance chose to forget — different sentences, and the
    second is the true one."""
    _recorded(db, frames=[], packages={})

    shown = _view(db)

    assert "forgotten by" in shown
    assert "stopped keeping them" in shown
    assert "No frames were recorded" not in shown, "it reports absence as if it were the error's"


def test_an_item_nothing_was_fetched_for_shows_nothing_at_all(db: Session) -> None:
    """No fold, not an empty one: an item whose tracker was never read has nothing to say here, and
    a disclosure promising an error and holding none is worse than no disclosure."""
    shown = _view(db)

    assert "The error, as the tracker recorded it" not in shown
