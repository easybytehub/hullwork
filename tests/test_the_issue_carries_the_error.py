"""What a person opens when Hullwork files an issue. Item 196.

Found on the live instance: issue `#24` on this repository's own forge, filed from a real production
error, containing a lane, an occurrence count, a first-seen timestamp and a fingerprint marker — and
**no exception message, no location, and no link to the error**. Hullwork had all of it: the frames,
the culprit and the release were sitting in `fetched_events` for that exact item.

The asymmetry is the point. `brief.py` renders frames for the **agent**, and item 165 made it say
which kind of run you are looking at because a brief with no frames was worthless. The person was
never given the same courtesy, and the two items that crashed the page sat untouched for four days.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from hullwork import ingest
from hullwork.models import FetchedEvent, Item, Lane, Project

FRAMES = [
    {"module": "hullwork.main", "function": "page_items", "lineno": 328, "context_line": "  x = 1"},
    {"module": "hullwork.page", "function": "items", "lineno": 986, "vars": {"token": "s3cret"}},
]


def _project(session: Session) -> Project:
    project = Project(
        slug="p", forge="forgejo", repo="o/r", active=True,
        webhook_secret_hash="x",  # noqa: S106
        manifest={},
    )
    session.add(project)
    session.flush()
    return project


def _item(session: Session, project: Project, *, lane: Lane = Lane.AMBER) -> Item:
    item = Item(
        project_id=project.id, fingerprint="fp", title="OperationalError: in hullwork.page.items",
        lane=lane, occurrences=1,
        permalink="http://tracker.example/easybyte-hub/issues/37",
    )
    session.add(item)
    session.flush()
    return item


def _evidence(session: Session, item: Item) -> FetchedEvent:
    event = FetchedEvent(
        item_id=item.id, provider_event_id="80ab0de2",
        exception_type="OperationalError",
        message="database is locked, while reading the page",
        culprit="hullwork.page in items",
        frames=FRAMES, release="0.1.0a3", environment="production",
        occurred_at=datetime(2026, 8, 6, 10, 17, 58, tzinfo=UTC),
    )
    session.add(event)
    session.flush()
    return event


# --- what the issue has to carry ----------------------------------------------------------------


def test_the_body_carries_the_exception_message_and_the_link(session: Session) -> None:
    """The two the gate calls a minimum. Without the link a reader cannot reach the error at all;
    without the message they are deciding from a title the provider truncated at 100 characters."""
    project = _project(session)
    item = _item(session, project)
    event = _evidence(session, item)

    body = ingest._issue_body(item, event)

    assert "database is locked, while reading the page" in body
    assert "http://tracker.example/easybyte-hub/issues/37" in body


def test_the_body_carries_where_it_happened(session: Session) -> None:
    """A location is what turns *something broke* into somewhere to look, and it is the whole
    difference between the agent's brief and the person's issue."""
    project = _project(session)
    item = _item(session, project)
    event = _evidence(session, item)

    body = ingest._issue_body(item, event)

    assert "hullwork.page" in body and "items" in body and "986" in body
    assert "0.1.0a3" in body, "the release is what says whether this is still true"


def test_it_never_carries_a_local_variable(session: Session) -> None:
    """**The bound, and the reason frames are rendered rather than dumped.** A frame's captured
    variables can hold a token; this body is written into a repository whose readers are not
    necessarily the people who may see secrets. Locations are the project's own code and are safe;
    variables are not ours to republish.
    """
    project = _project(session)
    item = _item(session, project)
    event = _evidence(session, item)

    body = ingest._issue_body(item, event)

    assert "s3cret" not in body
    assert "x = 1" not in body, "source lines go stale and the link above has them"


def test_it_states_what_it_leaves_out(session: Session) -> None:
    """*A decision the instance makes and can state, not a default nobody chose.* Said in the
    artefact every time rather than in a document somebody would have to find."""
    project = _project(session)
    item = _item(session, project)
    event = _evidence(session, item)

    body = ingest._issue_body(item, event)

    assert "no variables" in body.lower()


def test_an_item_with_no_evidence_yet_says_so(session: Session) -> None:
    """The commonest case at filing time, and it is why this defect existed: the issue is written
    once, at creation, and the enrichment arrives later. Silence there reads as *there was nothing*,
    which is a different fact from *it has not arrived*."""
    project = _project(session)
    item = _item(session, project)

    body = ingest._issue_body(item, None)

    assert "not arrived" in body or "not yet" in body
    assert "| Lane | amber |" in body, "everything it had before is still there"


def test_a_red_lane_item_carries_the_evidence_too(session: Session) -> None:
    """Red means no agent will touch it, so a person is the **only** one who will — which makes the
    evidence more load-bearing there, not less."""
    project = _project(session)
    item = _item(session, project, lane=Lane.RED)
    event = _evidence(session, item)

    body = ingest._issue_body(item, event)

    assert "database is locked" in body
    assert "Red lane" in body, "the existing reclassification sentence survives"
