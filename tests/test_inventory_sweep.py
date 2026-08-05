"""Folding the tracker's inventory through the pipeline. DR-0011, item 080.

The two properties that make this safe, and each is a test below:

* **an issue already known comes back deduplicated**, because identity is shared with the webhook
  route — so a sweep over ground the webhook already covered creates nothing;
* **the first pass of a project writes nothing** until an operator says go. Three hundred forge
  issues on somebody's first afternoon is DR-0006's adoption failure arriving from the other side.
"""

import io
import json
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import Session

from hullwork.cli import main as cli_main
from hullwork.config import get_settings
from hullwork.db import make_engine, make_session_factory
from hullwork.ingest import sweep_inventory
from hullwork.models import Item, ItemState, Project
from hullwork.normalise import glitchtip as adapter
from hullwork.tracker import PermanentTrackerError, TrackerIssue

ROOT = Path(__file__).resolve().parent.parent
ROWS: list[dict[str, Any]] = json.loads(
    (Path(__file__).parent / "fixtures" / "glitchtip-issues-unresolved.json").read_text(
        encoding="utf-8"
    )
)

MANIFEST: dict[str, Any] = {
    "version": 1,
    "project": "hullwork",
    "git": {"provider": "forgejo", "repo": "easybyte/hullwork"},
    "errors": {"provider": "glitchtip"},
    "autofix": {
        "agent": "none",
        "lanes": {"green": ["valueerror"], "amber": ["operationalerror"]},
    },
}


def _issue(
    external_id: str,
    *,
    title: str = "OperationalError: (sqlite3.OperationalError) database is locked",
    culprit: str | None = "hullwork/ingest.py:reconcile_closed",
    last_seen: datetime | None = None,
) -> TrackerIssue:
    return TrackerIssue(
        external_id=external_id,
        title=title,
        permalink=f"http://tracker/hullwork/issues/{external_id}",
        status="unresolved",
        level="error",
        culprit=culprit,
        occurrences=58,
        first_seen=datetime(2026, 7, 29, 7, 28, tzinfo=UTC),
        last_seen=last_seen or datetime(2026, 7, 29, 18, 9, tzinfo=UTC),
    )


class _Inventory:
    """Answers with whatever it was given, and records what it was asked."""

    def __init__(self, issues: Sequence[TrackerIssue]) -> None:
        self.issues = list(issues)
        self.asked: list[tuple[str, datetime | None, int]] = []

    def list_unresolved(
        self, project: str, *, since: datetime | None = None, limit: int = 25
    ) -> Sequence[TrackerIssue]:
        self.asked.append((project, since, limit))
        fresh = [
            issue
            for issue in self.issues
            if since is None or issue.last_seen is None or issue.last_seen > since
        ]
        return fresh[:limit]


class _Refusing:
    def list_unresolved(
        self, project: str, *, since: datetime | None = None, limit: int = 25
    ) -> Sequence[TrackerIssue]:
        raise PermanentTrackerError("the tracker has no project 'typo'")


@pytest.fixture
def session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path / 'sweep.db'}"
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.cmd_opts = None
    command.upgrade(cfg, "head")
    with make_session_factory(make_engine(url))() as db:
        yield db
    get_settings.cache_clear()


def _project(
    session: Session,
    *,
    tracker_project: str | None = "hullwork",
    swept_until: datetime | None = datetime(2026, 7, 1, tzinfo=UTC),
) -> Project:
    project = Project(
        slug="hullwork",
        forge="forgejo",
        repo="easybyte/hullwork",
        webhook_secret_hash="x",  # noqa: S106
        manifest=MANIFEST,
        tracker_project=tracker_project,
        tracker_swept_until=swept_until,
    )
    session.add(project)
    session.commit()
    return project


# --- the additive half ---------------------------------------------------------------------------


def test_a_project_with_no_tracker_project_is_never_swept(session: Session) -> None:
    """The whole feature is opt-in per project. An instance that sets nothing behaves as before."""
    _project(session, tracker_project=None)
    inventory = _Inventory([_issue("12")])

    assert sweep_inventory(session, inventory) == []
    assert inventory.asked == []
    assert session.query(Item).count() == 0


def test_no_inventory_configured_does_nothing(session: Session) -> None:
    _project(session)
    assert sweep_inventory(session, None) == []


# --- what it files -------------------------------------------------------------------------------


def test_an_unknown_issue_becomes_an_item_owed_a_forge_issue(session: Session) -> None:
    """The 58-event `OperationalError` that had never entered Hullwork, as an item."""
    project = _project(session)

    results = sweep_inventory(session, _Inventory([_issue("12")]))

    assert [(r.project, r.created, r.deduplicated) for r in results] == [("hullwork", 1, 0)]
    item = session.query(Item).one()
    assert item.project_id == project.id
    assert item.forge_sync_pending is True, "or a forge that is down loses the item silently"
    assert item.title.startswith("OperationalError")


def test_the_lane_comes_from_the_manifest_as_it_would_from_a_webhook(session: Session) -> None:
    """Nothing downstream changes: `resolve` does the dedup and the triage either way.

    `operationalerror` is amber in this manifest, so the real defect this found waits for a human's
    approval rather than being attempted quietly. That is the correct answer for a bug in the tool's
    own write path, and it falls out of the manifest rather than out of the sweep.
    """
    _project(session)

    sweep_inventory(session, _Inventory([_issue("12")]))

    assert session.query(Item).one().lane.value == "amber"


def test_an_issue_the_webhook_already_filed_comes_back_deduplicated(session: Session) -> None:
    """**The property the whole design rests on, end to end.**

    The item is created here the way a webhook creates it — with the webhook mapper's own
    fingerprint — and then swept. One item, not two. If identity ever diverges between the two
    routes, this is what fails.
    """
    project = _project(session)
    row = next(r for r in ROWS if r["id"] == "12")
    from_webhook = adapter.parse(
        {
            "attachments": [
                {
                    "title": row["title"],
                    "title_link": row["permalink"],
                    "fields": [{"title": "Project", "value": "hullwork"}],
                }
            ]
        },
        datetime(2026, 7, 30, tzinfo=UTC),
    )[0]
    session.add(
        Item(project_id=project.id, fingerprint=from_webhook.fingerprint, title=row["title"])
    )
    session.commit()

    swept = TrackerIssue(
        external_id=row["id"],
        title=row["title"],
        permalink=row["permalink"],
        status="unresolved",
        culprit="whatever the list route says",
    )
    results = sweep_inventory(session, _Inventory([swept]))

    assert [(r.created, r.deduplicated) for r in results] == [(0, 1)]
    assert session.query(Item).count() == 1, "one bug, one item, whichever route reported it"


def test_a_second_pass_immediately_after_creates_nothing(session: Session) -> None:
    """Negatively, and it is the other half of the falsifiable gate."""
    _project(session)
    inventory = _Inventory(
        [_issue("12"), _issue("13", last_seen=datetime(2026, 7, 29, 7, 29, tzinfo=UTC))]
    )

    first = sweep_inventory(session, inventory)
    second = sweep_inventory(session, inventory)

    assert sum(r.created for r in first) == 2
    assert sum(r.created for r in second) == 0
    assert sum(r.deduplicated for r in second) == 0, "the mark moved, so they are not even read"


# --- the high-water mark -------------------------------------------------------------------------


def test_the_mark_is_passed_to_the_tracker_and_advanced_to_what_was_read(
    session: Session,
) -> None:
    """Advanced to the newest activity **read**, never to now.

    An issue that becomes active a second after this pass must still be seen by the next one, and a
    mark set to `now()` would skip it for ever.
    """
    project = _project(session, swept_until=datetime(2026, 7, 1, tzinfo=UTC))
    newest = datetime(2026, 7, 29, 18, 9, tzinfo=UTC)
    inventory = _Inventory([_issue("12", last_seen=newest)])

    sweep_inventory(session, inventory)

    assert inventory.asked == [("hullwork", datetime(2026, 7, 1, tzinfo=UTC), 25)]
    session.refresh(project)
    assert project.tracker_swept_until == newest
    assert project.tracker_swept_until < datetime.now(UTC) - timedelta(hours=1), "not `now()`"


def test_nothing_read_leaves_the_mark_alone(session: Session) -> None:
    project = _project(session, swept_until=datetime(2026, 7, 1, tzinfo=UTC))

    results = sweep_inventory(session, _Inventory([]))

    assert [(r.created, r.swept_until) for r in results] == [(0, None)]
    session.refresh(project)
    assert project.tracker_swept_until == datetime(2026, 7, 1, tzinfo=UTC)


def test_a_never_swept_project_is_skipped_by_the_clock(session: Session) -> None:
    """**The adoption guard.** `None` means never swept, and the periodic pass must not decide that.

    A project with three hundred open issues would file three hundred forge issues on the first tick
    after an upgrade. It takes an explicit `first_pass`, which only the command passes.
    """
    _project(session, swept_until=None)
    inventory = _Inventory([_issue("12")])

    assert sweep_inventory(session, inventory) == []
    assert inventory.asked == [], "the clock does not even ask"

    # …and with the explicit flag it does.
    results = sweep_inventory(session, inventory, first_pass=True)
    assert [(r.created,) for r in results] == [(1,)]


def test_a_dry_run_writes_nothing(session: Session) -> None:
    """What the first pass shows an operator before they commit to it."""
    project = _project(session, swept_until=None)

    results = sweep_inventory(
        session, _Inventory([_issue("12"), _issue("13")]), first_pass=True, dry_run=True
    )

    assert [(r.created, r.deduplicated) for r in results] == [(2, 0)]
    assert session.query(Item).count() == 0
    session.refresh(project)
    assert project.tracker_swept_until is None, "and the mark is untouched"


def test_the_limit_is_passed_through(session: Session) -> None:
    _project(session)
    inventory = _Inventory([_issue(str(n)) for n in range(10)])

    sweep_inventory(session, inventory, limit=3)

    assert inventory.asked[0][2] == 3


def test_a_tracker_that_refuses_is_recorded_and_not_raised(session: Session) -> None:
    """One project's bad minute must not stop the sweep for the others — `drain_pending`'s rule."""
    _project(session)

    results = sweep_inventory(session, _Refusing())

    assert results[0].error is not None
    assert "typo" in results[0].error
    assert session.query(Item).count() == 0


# --- the command ---------------------------------------------------------------------------------


def test_the_first_sweep_needs_confirming(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It shows the count and writes nothing. **The adoption guard as an operator sees it.**"""
    _project(session, swept_until=None)
    monkeypatch.setenv("HULLWORK_TRACKER_URL", "http://tracker.example")
    monkeypatch.setenv("HULLWORK_TRACKER_TOKEN", "t")
    monkeypatch.setenv("HULLWORK_TRACKER_ORG", "easybyte-hub")
    get_settings.cache_clear()

    import hullwork.cli as cli

    monkeypatch.setattr(cli, "make_inventory", lambda _settings: _Inventory([_issue("12")]))

    out = io.StringIO()
    assert cli_main(["sweep", "hullwork"], out=out) == 0
    printed = out.getvalue()

    assert "would be filed" in printed
    assert "Nothing was written" in printed
    assert "--confirm" in printed
    assert session.query(Item).count() == 0


def test_from_now_adopts_the_present_without_filing_the_backlog(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The answer for a project with more history than anybody wants to look at."""
    project = _project(session, swept_until=None)
    monkeypatch.setenv("HULLWORK_TRACKER_URL", "http://tracker.example")
    monkeypatch.setenv("HULLWORK_TRACKER_TOKEN", "t")
    monkeypatch.setenv("HULLWORK_TRACKER_ORG", "easybyte-hub")
    get_settings.cache_clear()

    import hullwork.cli as cli

    monkeypatch.setattr(cli, "make_inventory", lambda _settings: _Inventory([_issue("12")]))

    out = io.StringIO()
    assert cli_main(["sweep", "hullwork", "--from-now"], out=out) == 0

    assert session.query(Item).count() == 0
    session.refresh(project)
    assert project.tracker_swept_until is not None
    assert "will not be filed" in out.getvalue()


def test_sweeping_without_an_organisation_says_what_is_missing(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HULLWORK_TRACKER_ORG", raising=False)
    get_settings.cache_clear()

    out = io.StringIO()
    assert cli_main(["sweep"], out=out) == 1


# --- the defect the first real sweep produced ----------------------------------------------------


def test_an_issue_nobody_resolved_in_the_tracker_does_not_reopen_a_closed_item(
    session: Session,
) -> None:
    """**Measured on the live instance, and it reopened four closed items.**

    A tracker issue stays `unresolved` until somebody marks it resolved *there*, and nobody does —
    items get closed in Hullwork and on the forge. So the first pass, which has no high-water mark
    by definition, sees every one of them, and `resolve` reads each as an occurrence against a
    closed item: a regression. Four items went from `done` back to `ready` — a dispatcher about to
    spend four attempts on probes.

    A delivery is an **event** and against a closed item genuinely is a regression. A list row is a
    **state** — it says the issue is open, not that anything happened.
    """
    project = _project(session, swept_until=None)
    closed = Item(
        project_id=project.id,
        fingerprint=adapter.fingerprint_for(issue_id="12", title="t", culprit=None),
        title="OperationalError: (sqlite3.OperationalError) database is locked",
        state=ItemState.DONE,
        occurrences=1,
    )
    session.add(closed)
    session.commit()
    settled_at = closed.updated_at

    # The issue is still `unresolved` in the tracker and was last seen *before* we closed the item.
    stale = _issue("12", title="t", culprit=None, last_seen=settled_at - timedelta(hours=1))
    results = sweep_inventory(session, _Inventory([stale]), first_pass=True)

    session.refresh(closed)
    assert closed.state is ItemState.DONE, "a closed item must stay closed"
    assert closed.occurrences == 1, "and its counter must not move"
    assert [(r.created, r.deduplicated) for r in results] == [(0, 1)]


def test_an_error_seen_since_the_item_was_closed_is_still_a_regression(session: Session) -> None:
    """The other half, and it is the half that must not be lost to the fix above.

    A bug that recurs **after** it was closed is exactly what `reopened` exists for: it is the fix
    that did not hold, which this product exists to catch.
    """
    project = _project(session, swept_until=None)
    closed = Item(
        project_id=project.id,
        fingerprint=adapter.fingerprint_for(issue_id="12", title="t", culprit=None),
        title="OperationalError",
        state=ItemState.DONE,
        occurrences=1,
    )
    session.add(closed)
    session.commit()

    recurred = _issue(
        "12", title="t", culprit=None, last_seen=closed.updated_at + timedelta(minutes=5)
    )
    results = sweep_inventory(session, _Inventory([recurred]), first_pass=True)

    session.refresh(closed)
    assert closed.state is not ItemState.DONE, "the fix did not hold, and that is news"
    assert sum(r.created for r in results) == 1


def test_an_issue_with_no_last_seen_never_reopens(session: Session) -> None:
    """Missing information must not reopen anything: that is the direction the defect went."""
    project = _project(session, swept_until=None)
    closed = Item(
        project_id=project.id,
        fingerprint=adapter.fingerprint_for(issue_id="12", title="t", culprit=None),
        title="OperationalError",
        state=ItemState.DONE,
    )
    session.add(closed)
    session.commit()

    blank = TrackerIssue(
        external_id="12", title="t", permalink="http://tracker/x/issues/12", status="unresolved"
    )
    sweep_inventory(session, _Inventory([blank]), first_pass=True)

    session.refresh(closed)
    assert closed.state is ItemState.DONE


def test_the_dry_run_and_the_real_pass_agree_about_the_count(session: Session) -> None:
    """They disagreed, and that is what let the defect through unnoticed.

    The rehearsal said "4 would be filed and 4 are already known"; the real pass said "filed 8,
    already knew 0" — because `resolve` returns `reopened` for a closed item and the counter added
    that to `created`. A rehearsal whose numbers do not predict the real pass is worse than none.
    """
    project = _project(session, swept_until=None)
    session.add(
        Item(
            project_id=project.id,
            fingerprint=adapter.fingerprint_for(issue_id="12", title="t", culprit=None),
            title="known and closed",
            state=ItemState.DONE,
        )
    )
    session.commit()
    issues = [
        _issue("12", title="t", culprit=None, last_seen=datetime(2026, 7, 1, tzinfo=UTC)),
        _issue("99"),
    ]

    rehearsed = sweep_inventory(
        session, _Inventory(issues), first_pass=True, dry_run=True
    )
    real = sweep_inventory(session, _Inventory(issues), first_pass=True)

    assert [(r.created, r.deduplicated) for r in rehearsed] == [
        (r.created, r.deduplicated) for r in real
    ]


# --- a swept item can be enriched. Item 086 -------------------------------------------------------


def test_a_swept_item_carries_the_permalink_enrichment_needs(session: Session) -> None:
    """**Why the first real dogfood attempt went out blind.**

    The permalink lived only on `events` rows, which the sweep does not write — so
    `_permalink_for` found nothing, enrichment silently never ran, and the agent's brief carried
    the issue title and nothing else. The frames that diagnosed the bug by hand were in the
    tracker the whole time, one request away.
    """
    from hullwork.ingest import _permalink_for

    _project(session)
    sweep_inventory(session, _Inventory([_issue("15")]))

    item = session.query(Item).one()
    assert item.permalink == "http://tracker/hullwork/issues/15"
    assert _permalink_for(session, item) == "http://tracker/hullwork/issues/15", (
        "enrichment must be able to find the reference with no events row behind it"
    )


def test_an_item_that_predates_the_column_is_backfilled_by_the_next_fact(
    session: Session,
) -> None:
    """Rows from before item 086 gain the reference the next time anything arrives for them."""
    project = _project(session)
    fingerprint = adapter.fingerprint_for(issue_id="15", title="t", culprit=None)
    session.add(
        Item(project_id=project.id, fingerprint=fingerprint, title="t", permalink=None)
    )
    session.commit()

    sweep_inventory(
        session,
        _Inventory([_issue("15", title="t", culprit=None)]),
    )

    item = session.query(Item).one()
    assert item.permalink == "http://tracker/hullwork/issues/15"
