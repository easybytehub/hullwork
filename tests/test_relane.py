"""Deciding a lane again once the code location arrives. Item 070, DR-0008 part 1.

The defect these cover was measured, not imagined. On 2026-07-29 the first real error from a project
that is not Hullwork arrived as a 471-character webhook with no frames, went red on an empty culprit
with the reason *"no lane rule matched"* — true, and misleading, because no rule could have
matched — and then was never enriched, because `human-only` counted as settled. The one decision
this system takes with the poorest evidence was the one decision it never revisited.

Every test here asserts by effect on the item, and the ones that matter assert both directions: a
test that only proves a lane can change would pass against a `relane` that changed every lane it
touched.
"""

from datetime import UTC, datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from hullwork.ingest import fetch_context
from hullwork.manifest import parse_manifest
from hullwork.models import (
    Attempt,
    AttemptOutcome,
    Base,
    Event,
    Item,
    ItemState,
    Lane,
    Project,
)
from hullwork.tracker import FetchedEvent as FetchedEventData
from hullwork.tracker import Frame

PERMALINK = "http://tracker.invalid/org/issues/6"

#: `divisionbyzero` is deliberately absent from every lane, which is the measured case: acme
#: declared the three exception types that dominate Python tracebacks and the first real failure was
#: none of them. `estimates` is in green so a culprit can earn leniency the title alone cannot.
MANIFEST = """
project: p
git: {provider: forgejo, repo: o/r}
tests: pytest
runtime: {base: python-3.12}
autofix:
  agent: claude-code
  lanes:
    green: [typeerror, estimates]
    amber: [migration]
    red: [payment, billing]
"""

TRIAGE_ONLY = MANIFEST.replace("agent: claude-code", "agent: none")



def _setup(
    session: Session,
    *,
    manifest: str = MANIFEST,
    title: str = "DivisionByZero: [<class 'decimal.DivisionByZero'>]",
    lane: Lane = Lane.RED,
    state: ItemState = ItemState.HUMAN_ONLY,
    saw: bool = False,
    reason: str = "no lane rule matched; defaulting to red so a human decides",
) -> Item:
    """An item as the measured delivery left it: red, in `human-only`, decided on no culprit."""
    project = Project(
        slug="p", forge="forgejo", repo="o/r",
        webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
        manifest=parse_manifest(manifest).model_dump(mode="json"),
    )
    session.add(project)
    session.flush()
    item = Item(
        project_id=project.id, fingerprint="fp", title=title,
        lane=lane, state=state, lane_reason=reason, lane_saw_code_location=saw,
    )
    session.add(item)
    session.flush()
    session.add(
        Event(
            project_id=project.id, delivery_id=1, fingerprint="fp",
            title=title, permalink=PERMALINK, raw={},
        )
    )
    session.flush()
    return item


class _Tracker:
    """Answers with one occurrence, and remembers being asked."""

    def __init__(
        self,
        culprit: str | None = "services.estimates.projection in monthly_total",
        paths: tuple[str, ...] = ("/app/src/acme_api/services/estimates/projection.py",),
    ) -> None:
        self.culprit = culprit
        self.paths = paths
        self.calls: list[str] = []

    def fetch_latest(self, permalink: str) -> FetchedEventData:
        self.calls.append(permalink)
        return FetchedEventData(
            provider_event_id="evt-1",
            exception_type="DivisionByZero",
            message="[<class 'decimal.DivisionByZero'>]",
            culprit=self.culprit,
            frames=tuple(
                Frame(
                    abs_path=path, lineno=49, function="monthly_total",
                    context_line="bac / (cpi_v * spi_v)",
                )
                for path in self.paths
            ),
            release="554eb46",
        )

    def fetch_samples(self, permalink: str, limit: int = 2) -> list[FetchedEventData]:
        return []


def test_the_measured_case_is_enriched_and_decided_again(session: Session) -> None:
    """The falsifiable gate. Red for want of evidence, then decided a second time on the culprit.

    Both halves matter. Enrichment happening at all is what `human-only` leaving `_SETTLED` bought;
    the lane moving is what proves the fetched evidence reached the rule rather than only the brief.
    """
    item = _setup(session)
    tracker = _Tracker()

    assert fetch_context(session, tracker) == 1, "a human-only item must now be enriched"
    assert tracker.calls == [PERMALINK]

    assert item.lane is Lane.GREEN
    assert item.lane_saw_code_location is True
    assert item.state is ItemState.READY, "the state has to follow the lane out of human-only"


def test_both_decisions_are_recorded_and_the_current_one_comes_first(session: Session) -> None:
    """An operator who saw it go to a human must be able to read why it is now queued."""
    item = _setup(session)

    fetch_context(session, _Tracker())

    reason = item.lane_reason or ""
    assert reason.startswith("matched 'estimates' in the green lane"), reason
    assert "no lane rule matched" in reason, "the first decision must survive, not be overwritten"
    assert "decided again once the code location arrived" in reason


def test_an_item_whose_first_decision_saw_the_culprit_is_left_alone(session: Session) -> None:
    """The other direction of the gate. Enrichment still happens; the lane does not move.

    Without this, a `relane` that ignored `lane_saw_code_location` and re-decided everything on
    every pass would pass every other test in this file.
    """
    item = _setup(session, saw=True, reason="matched 'payment' in the red lane")

    assert fetch_context(session, _Tracker()) == 1, "enrichment is not what is being suppressed"

    assert item.lane is Lane.RED
    assert item.state is ItemState.HUMAN_ONLY
    assert item.lane_reason == "matched 'payment' in the red lane"


def test_a_spent_attempt_freezes_the_lane(session: Session) -> None:
    """Item 042 sends a non-consuming outcome back to `ready`, so the state does not reveal this.

    Changing the lane after an agent has had its one try is changing the terms after the work.
    """
    item = _setup(session, state=ItemState.READY, lane=Lane.GREEN)
    session.add(
        Attempt(
            item_id=item.id, outcome=AttemptOutcome.ABANDONED,
            started_at=datetime.now(UTC), finished_at=datetime.now(UTC),
        )
    )
    session.flush()

    assert fetch_context(session, _Tracker(culprit="billing.charge in run")) == 1

    assert item.lane is Lane.GREEN, "a spent attempt freezes the lane even when red would be safer"
    assert item.lane_saw_code_location is False


def test_an_item_a_human_has_moved_is_left_alone(session: Session) -> None:
    """`not-reproducible` is not a state `route` produces. Something happened here."""
    item = _setup(session, state=ItemState.NOT_REPRODUCIBLE)

    assert fetch_context(session, _Tracker()) == 1

    assert item.lane is Lane.RED
    assert item.state is ItemState.NOT_REPRODUCIBLE


def test_the_lane_can_tighten_as_well_as_loosen(session: Session) -> None:
    """A culprit is evidence, not leniency. It has to be able to make things worse."""
    item = _setup(
        session, title="TypeError: bad", lane=Lane.GREEN, state=ItemState.READY,
        reason="matched 'typeerror' in the green lane",
    )

    fetch_context(session, _Tracker(culprit="app.billing.invoices in charge"))

    assert item.lane is Lane.RED
    assert item.state is ItemState.HUMAN_ONLY


def test_a_message_only_match_still_earns_nothing(session: Session) -> None:
    """The asymmetry `_trustworthy` exists for, unaffected by evidence arriving late.

    An anonymous user of the watched application writes exception *messages*. If a late culprit
    let a green word in the message start counting, the authorisation boundary would have moved.

    The frames deliberately land nowhere near `estimates`: this test is about the word being in
    text a stranger wrote, and it said so while an `estimates` path in the default fixture was
    quietly making it pass for the other reason. Item 071 exposed that by putting frame paths in
    `_trustworthy` — where an `estimates` path *should* earn green, which is the point of territory.
    """
    item = _setup(
        session,
        title="RuntimeError: could not render the projection for this account",
        reason="'estimates' matched only the error message, which the reporter controls; kept red",
    )

    fetch_context(
        session,
        _Tracker(culprit="app.reports.render in build", paths=("/app/src/reports/render.py",)),
    )

    assert item.lane is Lane.RED, "a green word in the message must not become leniency"
    assert item.state is ItemState.HUMAN_ONLY


def test_an_occurrence_with_neither_culprit_nor_frames_decides_nothing(session: Session) -> None:
    """Some events genuinely carry no code location at all. That is not evidence to act on."""
    item = _setup(session)

    assert fetch_context(session, _Tracker(culprit=None, paths=())) == 1

    assert item.lane is Lane.RED
    assert item.lane_saw_code_location is False, "nothing arrived, so nothing was seen"
    assert item.lane_reason == "no lane rule matched; defaulting to red so a human decides"


def test_frames_alone_are_enough_to_decide(session: Session) -> None:
    """A culprit is the SDK's summary of a stack; the frames are the stack. Either will do.

    Item 071. Without this, a tracker that reports frames and no culprit — and they exist — would
    leave the lane on the evidence-free decision for ever.
    """
    item = _setup(session)

    fetch_context(session, _Tracker(culprit=None))

    assert item.lane is Lane.GREEN
    assert item.lane_saw_code_location is True
    assert "matched 'estimates' in the green lane" in (item.lane_reason or "")


def test_triage_only_projects_keep_their_lane_and_their_state(session: Session) -> None:
    """`agent: none` is the default and most projects' whole configuration (DR-0002).

    The lane is still re-decided — it is what the digest and the labels show — but nothing moves,
    because with no agent there is nowhere for it to move to.
    """
    item = _setup(session, manifest=TRIAGE_ONLY, state=ItemState.TRIAGED)

    fetch_context(session, _Tracker())

    assert item.lane is Lane.GREEN
    assert item.state is ItemState.TRIAGED


def test_a_done_item_is_still_settled(session: Session) -> None:
    """`done` did not leave `_SETTLED` and must not. An item that is finished is finished."""
    item = _setup(session, state=ItemState.DONE)
    tracker = _Tracker()

    assert fetch_context(session, tracker) == 0
    assert tracker.calls == []
    assert item.lane is Lane.RED


def test_without_a_tracker_nothing_changes_at_all(session: Session) -> None:
    """DR-0002: a missing tracker costs context, never correctness."""
    item = _setup(session)

    assert fetch_context(session, None) == 0

    assert item.lane is Lane.RED
    assert item.state is ItemState.HUMAN_ONLY
    assert item.lane_reason == "no lane rule matched; defaulting to red so a human decides"


def test_a_sample_stored_before_item_070_still_gets_its_lane_decided(session: Session) -> None:
    """The measured gap: item 8 on the live instance sat green with `saw=0`, holding the evidence.

    A sample fetched before item 070 existed was stored and the lane was never revisited, and
    `fetch_context` skipped the item for ever because it only asked whether *a* sample existed. The
    evidence was on disk the whole time.

    **No tracker call**: the fixture answers with a culprit that would send this red, and the
    assertion is that the lane moved anyway — from what was already stored, not from a fetch.
    """
    from hullwork.models import FetchedEvent

    item = _setup(session)
    session.add(
        FetchedEvent(
            item_id=item.id,
            provider_event_id="stored-before-070",
            exception_type="DivisionByZero",
            message="[<class 'decimal.DivisionByZero'>]",
            culprit="services.estimates.projection in monthly_total",
            frames=[{"abs_path": "/app/src/acme_api/services/estimates/projection.py"}],
        )
    )
    session.flush()
    tracker = _Tracker(culprit="app.billing.charge in run", paths=("/app/billing/charge.py",))

    assert fetch_context(session, tracker) == 0, "nothing new was fetched"
    assert tracker.calls == [], "and the tracker was never asked"

    assert item.lane is Lane.GREEN, "the stored sample decided it"
    assert item.lane_saw_code_location is True
    assert "matched 'estimates' in the green lane" in (item.lane_reason or "")


def test_an_item_with_a_sample_and_a_decided_lane_is_left_entirely_alone(session: Session) -> None:
    """The negative twin. Otherwise every item with a sample is re-decided on every single pass."""
    from hullwork.models import FetchedEvent

    item = _setup(session, saw=True, reason="matched 'payment' in the red lane")
    session.add(
        FetchedEvent(
            item_id=item.id, provider_event_id="s", exception_type="X", message="m",
            culprit="services.estimates.projection in monthly_total", frames=[],
        )
    )
    session.flush()

    assert fetch_context(session, _Tracker()) == 0

    assert item.lane is Lane.RED
    assert item.lane_reason == "matched 'payment' in the red lane"


def test_a_lane_decided_from_a_stored_sample_survives_the_session(tmp_path: object) -> None:
    """The one test that catches a missing commit, and none of the others could.

    Every test above shares one session, so a change that was flushed and never committed is
    indistinguishable from one that was persisted — and that is exactly the defect this file
    shipped for one deploy: `fetch_context` commits only when it *fetched* something, and a lane
    re-decided from disk fetches nothing. It passed the suite, changed nothing in production, and
    was found by reading the item on the live instance.

    So this one uses a real file, closes the session, and opens a new one. Anything less asserts
    that the code ran, not that it had an effect.
    """
    from pathlib import Path

    from hullwork.models import FetchedEvent

    assert isinstance(tmp_path, Path)
    engine = create_engine(f"sqlite:///{tmp_path / 'persist.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)

    with factory() as first:
        item = _setup(first)
        first.add(
            FetchedEvent(
                item_id=item.id,
                provider_event_id="stored-before-070",
                exception_type="DivisionByZero",
                message="m",
                culprit="services.estimates.projection in monthly_total",
                frames=[{"abs_path": "/app/services/estimates/projection.py"}],
            )
        )
        first.commit()
        item_id = item.id

        fetch_context(first, _Tracker())

    with factory() as second:
        reloaded = second.get(Item, item_id)
        assert reloaded is not None
        assert reloaded.lane_saw_code_location is True, "flushed is not committed"
        assert reloaded.lane is Lane.GREEN
        assert "decided again once the code location arrived" in (reloaded.lane_reason or "")
