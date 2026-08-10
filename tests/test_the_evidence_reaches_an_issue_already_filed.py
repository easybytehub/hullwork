"""The half that fixes the case that was actually measured. Item 196.

An issue's body is written **once**, when it is created. On the live instance the two page crashes
were filed on 2026-08-06 and 2026-08-07 and their enrichment arrived on 2026-08-09 — so putting the
evidence in the body fixes every issue filed from now on and **not one that already exists**, which
was every issue on the instance that produced the finding.

The forge protocol has no `edit_issue` and adding one means three adapters, so the evidence arrives
as a comment. Posted when the **first** sample lands and never again: that is idempotence without a
migration and without a second API call to ask what was already said.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session
from test_recurrence import FakeForge

from hullwork import ingest
from hullwork.models import Item, Lane, Project
from hullwork.tracker import FetchedEvent as FetchedEventData
from hullwork.tracker import Frame


#: **The real type, not a double.** Three hand-written versions of this drifted from
#: `tracker.FetchedEvent` in a row — missing `grouping_hashes`, missing
#: `is_useful_for_reproduction` — and a double that has to be repaired to match is a double that
#: proves nothing about the code it stands in for. Item 186 measured the same lesson on hand-written
#: manifests.
def _fetched() -> FetchedEventData:
    return FetchedEventData(
        provider_event_id="e1",
        exception_type="OperationalError",
        message="database is locked",
        culprit="hullwork.page in items",
        frames=(
            Frame(module="hullwork.page", function="items", lineno=986, abs_path="/a/page.py"),
        ),
        release="0.1.0a3",
        environment="production",
        occurred_at=datetime(2026, 8, 6, 10, 17, 58, tzinfo=UTC),
    )


class _Tracker:
    """Both halves of the protocol, because a partial one is not the thing it stands in for."""

    def fetch_latest(self, permalink: str) -> FetchedEventData:
        return _fetched()

    def fetch_samples(
        self, permalink: str, limit: int = 2
    ) -> Sequence[FetchedEventData]:
        return [_fetched()]


#: The repository's own forge double, extended rather than rewritten — `test_undecidable_fix` sets
#: the precedent. A second partial fake would fail the `Forge` protocol and, worse, would be a
#: second thing to keep in step with it.
class _Forge(FakeForge):
    def __init__(self) -> None:
        super().__init__()
        self.comments: list[tuple[str, int, str]] = []

    def comment(self, repo: str, number: int, body: str) -> None:
        self.comments.append((repo, number, body))


def _item(session: Session, *, issue: str | None) -> Item:
    project = Project(
        slug="p", forge="forgejo", repo="o/r", active=True,
        webhook_secret_hash="x",  # noqa: S106
        manifest={},
    )
    session.add(project)
    session.flush()
    item = Item(
        project_id=project.id, fingerprint="fp", title="OperationalError",
        lane=Lane.AMBER, occurrences=1, forge_issue_ref=issue,
        permalink="http://tracker.example/o/issues/37",
    )
    session.add(item)
    session.commit()
    return item


def test_evidence_that_arrives_after_the_issue_is_posted_to_it(session: Session) -> None:
    """The measured case: filed 2026-08-07, enriched 2026-08-09, body unchanged for ever."""
    _item(session, issue="#24")
    forge = _Forge()

    ingest.fetch_context(session, _Tracker(), forge=forge)

    assert len(forge.comments) == 1
    repo, number, body = forge.comments[0]
    assert (repo, number) == ("o/r", 24)
    assert "database is locked" in body
    assert "hullwork.page.items:986" in body


def test_it_is_posted_once_and_not_on_every_pass(session: Session) -> None:
    """**Idempotence without a migration.** `_fetch_one` runs again to re-decide a lane from a
    stored sample, so a comment guarded only by *the issue exists* would arrive on every pass until
    somebody muted the repository.

    `recheck_after=0` is load-bearing and was found by mutation: with the default 600 seconds the
    second and third passes do not re-select the item at all, so this test was measuring the recheck
    window and calling it idempotence.

    **And the guard it looks like it is testing is not what makes this pass.** Removing
    `first_sample` from the condition leaves this green, because once a sample is stored both of
    `_fetch_one`'s early branches return before the storing line is reached — so the property is
    real, the mechanism is the short-circuit, and the extra term is defence. Said here rather than
    left for the next person to discover by deleting it and seeing nothing happen.
    """
    _item(session, issue="#24")
    forge = _Forge()

    for _ in range(3):
        ingest.fetch_context(session, _Tracker(), forge=forge, recheck_after=0)

    assert len(forge.comments) == 1


def test_an_item_with_no_issue_yet_is_not_even_attempted(
    session: Session, caplog: pytest.LogCaptureFixture
) -> None:
    """Its body will carry the evidence when it is filed, so a comment would say it twice — and
    this product's cardinal sin is the duplicate.

    **Asserting the absence of a comment is not enough**, found by mutation: with the guard removed,
    `_post_the_evidence` calls `int("None")`, raises, is caught and logged — so no comment appears
    and the weaker version of this test passed while the code was doing the wrong thing badly. What
    separates the two is whether anything was *tried*.
    """
    _item(session, issue=None)
    forge = _Forge()

    with caplog.at_level(logging.WARNING, logger="hullwork.ingest"):
        ingest.fetch_context(session, _Tracker(), forge=forge)

    assert forge.comments == []
    assert not [r for r in caplog.records if "evidence" in r.message], (
        "it tried to post and failed, rather than correctly not trying"
    )


def test_enrichment_still_works_with_no_forge_at_all(session: Session) -> None:
    """`fetch_context` is called from places that hold no forge credential, and enrichment is worth
    having on its own. A missing forge must cost the fetch nothing."""
    item = _item(session, issue="#24")

    fetched = ingest.fetch_context(session, _Tracker())

    assert fetched == 1
    session.refresh(item)
    assert item.context_checked_at is not None
