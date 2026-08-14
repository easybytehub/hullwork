"""What arrived from the tracker, and what the page may claim about it. Item 231.

The page kept opening empty and answering with a guess: *No items yet. Nothing has arrived from the
error tracker on this instance* — a sentence written before anything checked whether it was true.

An empty item list is consistent with three states that have different causes and different fixes:
nothing arrived, things arrived carrying no error, things arrived and could not be understood. And
with a fourth the database cannot answer at all — **a delivery with a wrong secret is refused before
a row is written**, so an empty list means nobody knocked *with a working secret*, which is a
strictly weaker claim than the one the page was making.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from hullwork import page
from hullwork.config import Settings, get_settings
from hullwork.db import make_engine
from hullwork.models import Base, Delivery, Event, Project

SIGNED_IN = page.Acting(csrf="c", offered=True)


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path}/arrived.db"
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


def _arrived(
    db: Session, *, when: dt.datetime | None = None, error: str | None = None, facts: int = 0
) -> Delivery:
    project = db.query(Project).one()
    # **A unique constraint on `(project_id, provider_delivery_id)` is the deduplication** — the
    # table is the queue and that pair is what makes a retried webhook idempotent. A fixture that
    # left it at its default could only ever insert one row.
    seen = db.query(Delivery).count()
    one = Delivery(
        project_id=project.id,
        provider_delivery_id=f"call-{seen}",
        payload_hash="h",
        payload_json='{"secret": "this must never be rendered"}',
        received_at=when or dt.datetime.now(dt.UTC),
        processed_at=None if error else dt.datetime.now(dt.UTC),
        error=error,
        attempts=1,
    )
    db.add(one)
    db.flush()
    for n in range(facts):
        db.add(
            Event(
                project_id=project.id,
                delivery_id=one.id,
                fingerprint=f"f{one.id}-{n}",
                title="KeyError: 'total'",
                raw={},
            )
        )
    db.commit()
    return one


def _project_view(db: Session) -> str:
    """**Its own page since item 235.** What arrived is a feature across projects, not a corner of
    one: it was a closed fold on the project's view, which is where a reader could not find it."""
    return page.deliveries(db, Settings(), "shop", acting=SIGNED_IN) or ""


def _front_door(db: Session) -> str:
    return page.items(db, acting=SIGNED_IN, here="./", settings=Settings(), front=True)


# --- what the project's view says ---------------------------------------------------------------


def test_nothing_accepted_says_what_that_does_not_mean(db: Session) -> None:
    """**The claim the page could not support.** A refused secret leaves no row, so the strongest
    thing this list can say is that none arrived with a working one — and saying more would be the
    same lie as an advisory list rendered empty after a failed request."""
    shown = _project_view(db)

    assert "no delivery has ever been accepted" in shown.lower()
    assert "with a working" in shown
    assert "in this instance's log" in shown


def test_what_arrived_is_listed_with_when_and_whether_it_was_understood(db: Session) -> None:
    _arrived(db, facts=2)

    shown = _project_view(db)

    assert "carrying 2 fact(s)" in shown
    assert "understood" in shown


def test_a_delivery_that_could_not_be_understood_carries_its_reason(db: Session) -> None:
    """*Arrived* and *understood* are different facts, and a page that showed only the first would
    report a working pipeline over a payload nothing could read."""
    _arrived(db, error="no event in payload")

    shown = _project_view(db)

    assert "no event in payload" in shown


def test_no_payload_reaches_the_page(db: Session) -> None:
    """**This table keeps bodies verbatim.** A page whose whole audience is people who are not the
    operator has no business rendering somebody else's error payload, or its hash."""
    _arrived(db, facts=1)

    shown = _project_view(db)

    assert "this must never be rendered" not in shown
    assert "payload_hash" not in shown


# --- and what the front door says ---------------------------------------------------------------


def test_an_instance_nothing_reached_says_so_precisely(db: Session) -> None:
    shown = _front_door(db)

    assert "no delivery has ever been accepted" in shown
    assert "rather than that nobody knocked" in shown


def test_deliveries_that_carried_nothing_are_not_silence(db: Session) -> None:
    """**The state the old sentence denied.** A tracker sending something that is not an error is
    ordinary, and telling that operator *nothing has arrived* sends them to check a webhook that is
    working."""
    _arrived(db, facts=0)
    _arrived(db, facts=0)

    shown = _front_door(db)

    assert "2 delivery(s) arrived and none of them carried an error" in shown
    assert "Nothing has arrived" not in shown


def test_deliveries_that_could_not_be_read_are_a_third_answer(db: Session) -> None:
    _arrived(db, facts=1)
    _arrived(db, error="unparseable")

    shown = _front_door(db)

    assert "2 delivery(s) arrived and 1 could not be understood" in shown
