"""What happens to a delivery after the receiver has already said 200.

Deliberately separate from the HTTP layer, because the two have different failure modes: the
receiver must answer fast and never lose anything, while this can be slow, can fail, and can be
run again.

**The drain is resumable.** A delivery accepted but not yet processed survives the process dying:
on start-up the pending ones are picked up and finished. Without that, telling a sender "200, I
have it" and then evaporating is the worst thing the front door can do — nobody ever finds out.
"""

import json
import logging
import threading
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import Any, NamedTuple

from pydantic import ValidationError
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from hullwork import recurrence
from hullwork.dedup import Outcome, Resolution, resolve
from hullwork.forge import Forge, ForgeError, marker_for
from hullwork.manifest import MANIFEST_FILENAME, GitConfig, Manifest
from hullwork.models import (
    Attempt,
    Delivery,
    Event,
    FetchedEvent,
    Item,
    ItemState,
    Lane,
    Project,
)
from hullwork.normalise import ErrorFact, NormalisationError
from hullwork.normalise import glitchtip as glitchtip_adapter
from hullwork.normalise import sentry as sentry_adapter
from hullwork.notify import build_digest
from hullwork.notify.adapters import UnsupportedChannelError, make_notifier, notify_safely
from hullwork.readiness import forge_unchecked_for, record_forge
from hullwork.states import CLOSED, IllegalTransitionError, transition
from hullwork.tracker import FetchedEvent as FetchedEventData
from hullwork.tracker import (
    PermanentTrackerError,
    RetryableTrackerError,
    Tracker,
    TrackerError,
    TrackerInventory,
    TrackerIssue,
)
from hullwork.triage import relane

log = logging.getLogger(__name__)

LANE_LABELS = {
    Lane.GREEN: ("hullwork:green", "#1a7f37"),
    Lane.AMBER: ("hullwork:amber", "#d4a72c"),
    Lane.RED: ("hullwork:red", "#cf222e"),
}

_ADAPTERS = {"glitchtip": glitchtip_adapter.parse, "sentry": sentry_adapter.parse}

#: Failures that mean the payload itself cannot be understood. Trying again changes nothing, so
#: these seal the delivery. **Everything else is assumed transient** — a database that was locked,
#: a disk that was full, a bug we have not met yet — because the cost of guessing wrong in that
#: direction is a destroyed error report, and in this one it is a retry.
PERMANENT_FAILURES = (NormalisationError, ValidationError, json.JSONDecodeError, ValueError)

#: After this many tries a delivery is sealed anyway. Unbounded retries of something failing for a
#: reason nobody anticipated would spin the sweep; a row that has failed five times needs a human.
MAX_DELIVERY_ATTEMPTS = 5


def normalise(provider: str, payload: dict[str, object], received_at: datetime) -> list[ErrorFact]:
    """Route a payload to its provider adapter. One delivery may yield several facts."""
    adapter = _ADAPTERS.get(provider)
    if adapter is None:
        msg = f"no adapter for provider {provider!r}"
        raise ValueError(msg)
    return adapter(payload, received_at)


def process_delivery(
    session: Session, delivery: Delivery, project: Project, forge: Forge | None = None
) -> list[Resolution]:
    """Turn one stored delivery into items, and mark it done.

    Failure is recorded against the delivery rather than raised at the caller: one malformed payload
    must not stop the queue behind it.
    """
    payload = json.loads(delivery.payload_json)
    provider = delivery.provider
    manifest = _manifest_for(project)

    facts = normalise(provider, payload, delivery.received_at)
    resolutions = []
    for fact in facts:
        session.add(
            Event(
                project_id=project.id,
                delivery_id=delivery.id,
                fingerprint=fact.fingerprint,
                fingerprint_derived=fact.fingerprint_derived,
                title=fact.title,
                culprit=fact.culprit,
                level=fact.level,
                permalink=fact.permalink,
                timestamps_are_receipt_time=fact.timestamps_are_receipt_time,
                raw=payload,
            )
        )
        resolutions.append(resolve(session, project.id, fact, manifest))

    # The intent to file is written in the same transaction that marks the delivery done. If it
    # were recorded only after a successful forge call, a failure would leave no trace that the
    # item was ever owed an issue — which is exactly how two items went missing on 2026-07-27.
    for resolution in resolutions:
        if resolution.needs_attention:
            resolution.item.forge_sync_pending = True
    delivery.processed_at = datetime.now(UTC)
    session.commit()

    if forge is not None:
        for resolution in resolutions:
            _materialise(session, forge, project, resolution)

    return resolutions


def drain_pending(session: Session, forge: Forge | None = None, limit: int = 100) -> int:
    """Finish deliveries accepted earlier but never processed. Returns how many were handled.

    Called on start-up and after each accepted delivery. A delivery that fails is marked with its
    error and left behind; the ones after it still run.

    One digest per run, not per delivery — and grouped by the channel each project declares, so two
    projects sharing a channel share a message. Sending per event is how a tool teaches its user to
    mute it.
    """
    pending = session.scalars(
        select(Delivery)
        .where(Delivery.processed_at.is_(None), Delivery.attempts < MAX_DELIVERY_ATTEMPTS)
        .order_by(Delivery.id)
        .limit(limit)
    ).all()

    handled = 0
    by_channel: dict[str, list[Resolution]] = defaultdict(list)

    for delivery in pending:
        project = session.get(Project, delivery.project_id)
        if project is None:  # pragma: no cover - foreign key makes this unreachable
            continue
        try:
            resolutions = process_delivery(session, delivery, project, forge)
            handled += 1
            by_channel[_channel_for(project)].extend(resolutions)
        except Exception as exc:  # one bad payload must not stop the queue behind it
            session.rollback()
            _record_failure(session, delivery, project, exc)

    _notify(by_channel)
    return handled


def _record_failure(
    session: Session, delivery: Delivery, project: Project, exc: Exception
) -> None:
    """Decide whether this delivery is finished or merely unlucky.

    The distinction is the whole point. Sealing a delivery sets `processed_at`, and nothing ever
    selects a processed delivery again — while the tracker, having notified once, will never resend
    it (item 013). So calling a transient database error "permanent" does not delay an error
    report, it destroys one. Observed: two drains overlapping produced `database is locked`, and
    the payload sat intact and unreachable for ever.
    """
    permanent = isinstance(exc, PERMANENT_FAILURES)
    delivery.attempts += 1
    delivery.error = f"{type(exc).__name__}: {exc}"[:1000]
    if permanent or delivery.attempts >= MAX_DELIVERY_ATTEMPTS:
        # Either it can never be understood, or it has had its chances. Sealing a repeatedly
        # failing row is what keeps it from jamming the queue in front of everything else.
        delivery.processed_at = datetime.now(UTC)
    session.commit()
    log.warning(
        "delivery failed to process",
        extra={
            "delivery_id": delivery.id,
            "project": project.slug,
            "attempts": delivery.attempts,
            "retryable": not permanent and delivery.attempts < MAX_DELIVERY_ATTEMPTS,
        },
    )


def drain_unmaterialised(session: Session, forge: Forge | None = None, limit: int = 50) -> int:
    """File the issues that earlier attempts could not. Returns how many landed.

    Deliberately **not** driven by deliveries. A delivery is processed exactly once, and the
    tracker will not send it again: GlitchTip excludes an issue from an alert permanently once it
    has been notified (`apps/alerts/tasks.py`, verified 2026-07-27). So if this database forgets
    that an item is owed an issue, nothing anywhere remembers — the item is not delayed, it is
    lost.

    Oldest first, capped per pass. The cap is what bounds the cost of an item that can never be
    filed, since such an item stays queued rather than being abandoned.
    """
    if forge is None:
        return 0

    # Fewest attempts first, so a fresh item always outranks one that is known to be failing.
    # Ordered by id alone, `limit` permanently unfilable items at low ids meant nothing newer was
    # ever *attempted once* — one project whose repository was renamed made every other project's
    # errors invisible, while burning a hundred doomed API calls a minute.
    # **Closed items are excluded, and that took 38 attempts each to notice.** Item 084.
    #
    # `forge_sync_pending` is the intent to file, and an item can be closed while still carrying it
    # —
    # by a human, by `reconcile_closed`, or by an operator settling one by hand. Filing an issue for
    # a
    # bug that is already settled is work with no reader, and when the issue it points at is gone
    # the
    # attempt can never succeed: measured on the live instance as four `PATCH … 404` every sixty
    # seconds, for ever, with `forge_attempts` at 38 and climbing.
    #
    # The cap above bounds the cost of *one* pass. It does not bound the cost of an item that can
    # never be filed, because nothing retires it — so the state has to be part of the question.
    stranded = session.scalars(
        select(Item)
        .where(Item.forge_sync_pending.is_(True), Item.state.not_in(tuple(CLOSED)))
        .order_by(Item.forge_attempts, Item.id)
        .limit(limit)
    ).all()

    filed = 0
    for item in stranded:
        project = session.get(Project, item.project_id)
        if project is None:  # pragma: no cover - foreign key makes this unreachable
            continue
        if _file(session, forge, project, item):
            filed += 1

    if filed:
        log.info("filed items that were waiting for the forge", extra={"count": filed})
    return filed


def reconcile_closed(
    session: Session, forge: Forge | None = None, limit: int = 20, recheck_after: int = 600
) -> int:
    """Notice that a human resolved something. Returns how many items moved to `done`.

    An issue filed and never looked at again means our idea of what is outstanding drifts away from
    the one the team is actually working from — quietly, and for as long as the instance lives.

    Bounded twice on purpose: `limit` items per pass, and no item asked about again until
    `recheck_after` seconds have gone by. Without both, this would be one API call per open item
    per sweep, forever, to learn something that changes once.
    """
    if forge is None:
        return 0

    cutoff = datetime.now(UTC) - timedelta(seconds=recheck_after)
    candidates = session.scalars(
        select(Item)
        .where(
            Item.forge_issue_ref.is_not(None),
            Item.state.not_in(tuple(CLOSED)),
            or_(Item.forge_checked_at.is_(None), Item.forge_checked_at < cutoff),
        )
        .order_by(Item.forge_checked_at.is_not(None), Item.forge_checked_at, Item.id)
        .limit(limit)
    ).all()

    resolved = 0
    for item in candidates:
        project = session.get(Project, item.project_id)
        if project is None:  # pragma: no cover - foreign key makes this unreachable
            continue
        try:
            issue = forge.get_issue(project.repo, int(str(item.forge_issue_ref).lstrip("#")))
        except ForgeError as exc:
            # Unreachable forge is not news about the issue. Leave the timestamp alone so this item
            # is first in line next time rather than being skipped for the whole window.
            record_forge(f"unreachable:{exc.status or type(exc).__name__}")
            log.warning("could not read issue state", extra={"item_id": item.id, "why": str(exc)})
            continue

        # Stamped and committed BEFORE the transition. If anything below raises, the timestamp
        # survives — otherwise the same row sorts first for ever and every future pass dies on it.
        item.forge_checked_at = datetime.now(UTC)
        session.commit()

        if issue is not None and issue.state == "closed":
            try:
                transition(item, ItemState.DONE)
            except IllegalTransitionError:
                # One unexpected row must not decapitate the pass for every other project.
                session.rollback()
                log.exception("item could not be closed", extra={"item_id": item.id})
                continue
            session.commit()
            resolved += 1

    if resolved:
        log.info("items closed by a human in the forge", extra={"count": resolved})
    return resolved


def forge_answers(session: Session, forge: Forge | None) -> str | None:
    """`"ok"`, `"unreachable:<status>"`, or `None` when there is nothing to ask about.

    **Measures and returns; it does not remember.** Item 129 split this out because two callers want
    the same question and only one of them should write it down: the sweep records the answer for
    `/ready` to serve, while `hullwork status` runs in its own process, wants a fresh answer, and
    has no business mutating state that outlives its report — which is also how it started leaking
    between tests the moment it did.
    """
    if forge is None:
        return None
    project = session.scalars(
        select(Project).where(Project.active.is_(True)).order_by(Project.id).limit(1)
    ).one_or_none()
    if project is None:
        return None
    try:
        # **`read_file` and not `read_manifest`** (DR-0012, item 128): a project whose manifest this
        # instance holds has no `hullwork.yml`, and `read_manifest` raises on a missing file — which
        # made the health check call a perfectly reachable forge `unreachable:404`. `read_file`
        # answers `None` for a missing file and raises only when the forge or the credential is the
        # problem, which is the question being asked.
        forge.read_file(project.repo, MANIFEST_FILENAME)
    except ForgeError as exc:
        log.warning("the forge did not answer a health check", extra={"why": str(exc)})
        return f"unreachable:{exc.status or type(exc).__name__}"
    return "ok"


def confirm_forge(session: Session, forge: Forge | None, stale_after: int = 0) -> None:
    """One cheap call when the caller had no other reason to touch the forge.

    Otherwise a quiet instance reports `forge: unknown` indefinitely and a revoked credential
    is discovered on the day something finally needs filing. Rate-limited to the same window as
    the issue recheck, so this is a handful of requests a day, not one a minute.

    **Public since item 129**, because `hullwork status` runs in its own process and therefore has
    its own module state: it reported `forge: unknown` while `/ready`, served by the receiver, said
    `ok` about the same forge and the same credential. Two answers about one thing. Now both ask
    through here, so there is one definition of what "the forge is answering" means, and
    `stale_after=0` is a caller saying *I have no cached answer at all* rather than a second policy.
    """
    if forge is None or not forge_unchecked_for(stale_after):
        return
    answered = forge_answers(session, forge)
    if answered is not None:
        record_forge(answered)


def fetch_context(
    session: Session,
    tracker: Tracker | None = None,
    limit: int = 20,
    recheck_after: int = 600,
) -> int:
    """Ask the tracker for the full error behind each item that has not got one yet (item 036).

    On a clock rather than on delivery, and that is not a preference. The tracker notifies once per
    issue for the issue's whole life, so a fetch that fails while a webhook is being handled would
    never be prompted again — the same reason this system already keeps its own retry clock.

    Skipped entirely when no tracker is configured, which is the default. What a missing tracker
    costs is the context an agent needs to reproduce; the rest of the pipeline is unaffected.
    """
    if tracker is None:
        return 0

    cutoff = datetime.now(UTC) - timedelta(seconds=recheck_after)
    candidates = (
        session.query(Item)
        .filter(
            Item.state.notin_(_SETTLED),
            or_(Item.context_checked_at.is_(None), Item.context_checked_at < cutoff),
        )
        .order_by(Item.context_checked_at.is_(None).desc(), Item.id)
        .limit(limit)
        .all()
    )

    fetched = 0
    for item in candidates:
        # **Committed per item, in one place.** Item 083. `context_checked_at` is a fact — the
        # tracker
        # was asked about this item at this time — not a provisional value, and every branch below
        # sets it. Leaving the commit to the end of the pass lost all of them whenever the pass
        # fetched nothing, and left each write pending long enough for the *next* item's `SELECT` to
        # emit it through autoflush: which is why the live failure was reported inside a query on
        # `fetched_events` when the statement that failed was an `UPDATE` on `items`, one item back.
        #
        # `finally`, so a tracker that raises mid-pass does not cost the earlier items their
        # backoff.
        try:
            if _fetch_one(session, tracker, item):
                fetched += 1
        finally:
            session.commit()
    return fetched


def _fetch_one(session: Session, tracker: Tracker, item: Item) -> bool:
    """Bring one item's context up to date. Returns whether anything was fetched.

    Extracted from the loop by item 083 so there is **one** place that commits. Five `continue`
    branches each having to remember it is how the previous defect survived a fix to one of them.
    """
    has_sample = bool(
        session.query(FetchedEvent).filter(FetchedEvent.item_id == item.id).count()
    )
    if has_sample and item.lane_saw_code_location:
        # Already have a sample **and** the lane was decided with a code location in hand. A second
        # sample is worth having, but not at the cost of asking about every item on every pass for
        # the rest of its life.
        item.context_checked_at = datetime.now(UTC)
        return False
    if has_sample:
        # A sample arrived before item 070 existed, so it was stored and the lane was never
        # revisited. Measured: item 8 on the live instance sat green with `saw=0`, holding the
        # evidence that would have decided it, unreachable because this check only asked whether a
        # sample existed. Re-decide from what is already on disk — no fetch, no tracker call,
        # because
        # the tracker has nothing new to say.
        #
        # The explicit commit that used to be here is gone: the caller commits every branch now, and
        # a second one inside would only be a second thing to keep in step.
        _relane_from_stored_sample(session, item)
        item.context_checked_at = datetime.now(UTC)
        return False
    permalink = _permalink_for(session, item)
    item.context_checked_at = datetime.now(UTC)
    if not permalink:
        item.context_error = "no permalink stored for this item"
        return False
    try:
        event = tracker.fetch_latest(permalink)
    except RetryableTrackerError as exc:
        # `context_checked_at` is already set, so this backs off — and now it is committed, so the
        # backoff survives the pass. Before item 083 a retryable failure repeated every minute.
        item.context_error = f"retryable: {exc}"
        log.warning("could not fetch context", extra={"item": item.id, "error": str(exc)})
        return False
    except PermanentTrackerError as exc:
        item.context_error = f"permanent: {exc}"
        log.error("cannot fetch context for this item", extra={"item": item.id})
        return False
    if event is None:
        item.context_error = "the tracker no longer has this issue"
        return False
    _store_context(session, item, event)
    item.context_error = None
    _relane_now_that_we_know_where(session, item, event)
    return True


def _relane_from_stored_sample(session: Session, item: Item) -> bool:
    """Re-decide a lane using a sample fetched before item 070 existed.

    No network call: the evidence is already in `fetched_events`, it was simply never read by a
    rule. That is this function's whole reason to exist — the alternative was asking the tracker
    again for something it already told us, which costs a request and answers nothing new.
    """
    stored = (
        session.query(FetchedEvent)
        .filter(FetchedEvent.item_id == item.id)
        .order_by(FetchedEvent.id.desc())
        .first()
    )
    if stored is None:  # pragma: no cover - the caller has just counted one
        return False
    paths = [
        frame.get("abs_path")
        for frame in (stored.frames or [])
        if isinstance(frame, dict) and frame.get("abs_path")
    ]
    before = item.lane_saw_code_location
    _relane(session, item, culprit=stored.culprit, paths=[p for p in paths if p])
    return item.lane_saw_code_location != before


def _relane_now_that_we_know_where(
    session: Session, item: Item, event: FetchedEventData
) -> None:
    """Give the lane a second chance on the evidence that just arrived. Item 070.

    Guarded twice, and both guards are load-bearing. `relane` refuses an item that has left the
    states `route` puts it in; **this** refuses one that has spent an attempt, which the state alone
    does not reveal — item 042 sends a non-consuming outcome back to `ready`, so a `ready` item may
    already have had its one try. Changing the lane under that is changing the terms after the work.

    Failures here are logged and swallowed. A lane that could not be revisited leaves the item as
    enrichment found it, which is where it would have been anyway; letting it propagate would lose
    the fetched context for every remaining item on the sweep, and that context is the point.
    """
    # Item 071: the frame paths, not only the culprit. They are the half a project can write a rule
    # about — `services/billing/**` is a fact about a codebase, while a list of exception types is a
    # prediction about which bugs it will have. An occurrence often has one and not the other.
    paths = [frame.abs_path for frame in event.frames if frame.abs_path]
    _relane(session, item, culprit=event.culprit, paths=paths)


def _relane(session: Session, item: Item, *, culprit: str | None, paths: list[str]) -> None:
    """Decide the lane again from evidence, wherever the evidence came from.

    Shared by the two callers deliberately: one has just fetched an occurrence, the other found one
    on disk that predates item 070. The guards below must hold identically for both, and a second
    copy of them is a second place for one of them to be forgotten.
    """
    if culprit is None and not paths:
        return
    if session.query(Attempt).filter(Attempt.item_id == item.id).count():
        return
    project = session.get(Project, item.project_id)
    if project is None:
        return
    try:
        decision = relane(item, _manifest_for(project), culprit=culprit, paths=paths)
    except (IllegalTransitionError, ValidationError, ValueError) as exc:
        log.warning(
            "could not decide the lane again", extra={"item": item.id, "error": str(exc)}
        )
        return
    if decision is not None:
        log.info(
            "decided the lane again once the code location arrived",
            extra={"item": item.id, "lane": decision.lane.value, "state": item.state.value},
        )


def _permalink_for(session: Session, item: Item) -> str | None:
    """The tracker URL for an item: its own, then its most recent event's.

    The item carries one since item 086. The join on `(project_id, fingerprint)` stays as the
    fallback for rows that predate the column — it was the only route for as long as the webhook
    was the only way in, and it is exactly what the inventory sweep's items never had: the sweep
    writes no events, so enrichment silently never ran for them and the first real dogfood attempt
    went out with a brief that carried the issue title and nothing else.
    """
    if item.permalink:
        return item.permalink
    event = (
        session.query(Event)
        .filter(Event.project_id == item.project_id, Event.fingerprint == item.fingerprint)
        .order_by(Event.received_at.desc())
        .first()
    )
    return event.permalink if event else None


def _store_context(session: Session, item: Item, event: FetchedEventData) -> None:
    """Persist one fetched occurrence. Already scrubbed by the adapter, on the way in."""
    session.add(
        FetchedEvent(
            item_id=item.id,
            provider_event_id=event.provider_event_id,
            exception_type=event.exception_type,
            message=event.message,
            culprit=event.culprit,
            handled=event.handled,
            level=event.level,
            frames=[asdict(frame) for frame in event.frames],
            packages=dict(event.packages),
            extra=dict(event.extra),
            runtime=event.runtime,
            environment=event.environment,
            release=event.release,
            server_name=event.server_name,
            occurred_at=event.occurred_at,
            grouping_hash=event.grouping_hashes[0] if event.grouping_hashes else None,
        )
    )
    log.info(
        "fetched the full error",
        extra={
            "item": item.id,
            "frames": len(event.frames),
            "usable": event.is_useful_for_reproduction,
        },
    )


class SweepResult(NamedTuple):
    """What one pass finished off. `skipped` when another pass already held the lock."""

    deliveries: int
    filed: int
    resolved: int
    #: Items that gained the full error from the tracker this pass (item 036).
    fetched: int = 0
    #: Items the inventory found that no webhook had reported (DR-0011, item 080).
    swept: int = 0
    skipped: bool = False


#: One pass at a time, in this process. Every production path into the pipeline goes through
#: `sweep` — start-up, the background task after an accepted delivery, and the periodic ticker —
#: and the first two can overlap the third at any moment.
#:
#: Without it, two passes select the same rows because selecting is not claiming, and the window
#: between "file this issue" and "record that it is filed" is a whole HTTP round trip. Reproduced:
#: two issues for one item, the first orphaned and left open in the user's repository for ever,
#: and one delivery processed twice with its occurrence counter doubled.
#:
#: A second *process* is not covered by this — that would need an advisory lock in Postgres or a
#: lockfile beside the SQLite file. What protects the important half there is `find_issue_by_marker`
#: in `_file`, which makes creating an issue idempotent no matter who else is running.
#: States where more context would change nothing: the work is over, one way or another.
#:
#: **`human-only` was in here and came out (item 070).** The reasoning was that a human needs no
#: brief, and that is true — but a red lane is often red *because* the frames had not arrived, and
#: excluding those items from enrichment made the poorest decision this system takes the one it
#: never revisited. Measured: the first real error from a project that is not Hullwork went red on
#: an empty culprit and was then never enriched, so the evidence that would have re-decided it was
#: never fetched.
#:
#: `done` stays. An item that is finished is finished.
_SETTLED = frozenset({ItemState.DONE})

_SWEEP_LOCK = threading.Lock()


#: How many issues one inventory pass takes per project. Bounded so nothing is unbounded even when
#: the high-water mark is wrong, and small enough that a pass costs one request and a handful of
#: filings rather than an afternoon of them.
INVENTORY_PAGE = 25


class InventoryResult(NamedTuple):
    """What one inventory pass did, per project it looked at. DR-0011, item 080."""

    project: str
    created: int
    deduplicated: int
    #: How far the mark moved to. `None` when nothing was read, so the mark is left alone.
    swept_until: datetime | None
    error: str | None = None


def sweep_inventory(
    session: Session,
    inventory: "TrackerInventory | None" = None,
    limit: int = INVENTORY_PAGE,
    *,
    slug: str | None = None,
    first_pass: bool = False,
    dry_run: bool = False,
) -> list[InventoryResult]:
    """Read the tracker's unresolved list and fold each issue through the pipeline. DR-0011.

    **The webhook stops being the source of truth here.** It fires when an issue is created and
    never
    again for the issue's whole life, so only the first appearance of a new signature ever arrives.
    Measured on the live instance: six of fifteen unresolved issues had never entered Hullwork, and
    the one with the most events by a factor of nineteen was a defect in Hullwork's own write path.

    Nothing downstream changes. Each issue becomes an `ErrorFact` and goes through `resolve` — the
    same deduplication and triage a webhook delivery gets — so an issue Hullwork already knows about
    comes back `deduplicated` and costs nothing. That is safe because identity is shared between the
    two routes (`normalise.glitchtip.fingerprint_for`), not because the two happen to agree.

    **A project with no mark is skipped.** `tracker_swept_until is None` means never swept, and the
    first pass of a project with a real backlog would file one forge issue per open issue — three
    hundred on somebody's first afternoon is DR-0006's adoption failure from the other direction. It
    takes `first_pass=True`, which only the CLI passes, after showing the operator the count.
    """
    if inventory is None:
        return []

    projects = session.scalars(
        select(Project)
        .where(Project.active.is_(True), Project.tracker_project.is_not(None))
        .order_by(Project.slug)
    ).all()

    results: list[InventoryResult] = []
    for project in projects:
        if slug is not None and project.slug != slug:
            continue
        if project.tracker_swept_until is None and not first_pass:
            continue
        results.append(
            _sweep_one(session, inventory, project, limit=limit, dry_run=dry_run)
        )
    return results


def _sweep_one(
    session: Session,
    inventory: "TrackerInventory",
    project: Project,
    *,
    limit: int,
    dry_run: bool,
) -> InventoryResult:
    """One project's pass. Failures are recorded and returned, never raised at the caller.

    The same rule `drain_pending` follows for one bad payload: a tracker having a bad minute for one
    project must not stop the sweep for the others.
    """
    tracker_project = str(project.tracker_project)
    try:
        issues = inventory.list_unresolved(
            tracker_project, since=project.tracker_swept_until, limit=limit
        )
    except TrackerError as exc:
        log.warning(
            "could not read the tracker inventory",
            extra={"project": project.slug, "error": str(exc)},
        )
        return InventoryResult(project.slug, 0, 0, None, f"{type(exc).__name__}: {exc}")

    if not issues:
        return InventoryResult(project.slug, 0, 0, None)

    manifest = _manifest_for(project)
    created = deduplicated = 0
    for issue in issues:
        fact = glitchtip_adapter.from_issue(issue, project_ref=tracker_project)
        known = session.scalars(
            select(Item).where(
                Item.project_id == project.id, Item.fingerprint == fact.fingerprint
            )
        ).one_or_none()
        if _already_settled(known, issue):
            deduplicated += 1
            continue
        if dry_run:
            # Counted by asking the database rather than by resolving: a dry run writes nothing at
            # all, and `resolve` creates items as a matter of course.
            deduplicated += 1 if known is not None else 0
            created += 0 if known is not None else 1
            continue
        resolution = resolve(session, project.id, fact, manifest)
        if resolution.outcome is Outcome.DEDUPLICATED:
            deduplicated += 1
        else:
            created += 1
            # Same as a delivery: the intent to file is recorded now, so a forge that is down leaves
            # a trace rather than losing the item (the failure that lost two items on 2026-07-27).
            resolution.item.forge_sync_pending = True

    # The mark moves to the newest activity actually read, not to now: an issue that becomes active
    # a second after this pass must still be seen by the next one.
    furthest = max((issue.last_seen for issue in issues if issue.last_seen), default=None)
    if not dry_run:
        if furthest is not None:
            project.tracker_swept_until = furthest
        elif project.tracker_swept_until is None:
            # Nothing carried a timestamp, and the project had never been swept. Mark it as swept
            # anyway, or `first_pass` would be required for ever on a project that is simply quiet.
            project.tracker_swept_until = datetime.now(UTC)
        session.commit()
        log.info(
            "swept the tracker inventory",
            # `filed` and not `created`: `LogRecord` reserves `created` for its own timestamp and
            # `logging` raises `KeyError: Attempt to overwrite 'created' in LogRecord` on the
            # collision. It would have thrown on every pass that found anything — the one path a
            # quiet instance never exercises. Caught by the tests, which is the only reason it is
            # not a production traceback.
            extra={
                "project": project.slug,
                "filed": created,
                "deduplicated": deduplicated,
                "swept_until": str(furthest),
            },
        )
    return InventoryResult(project.slug, created, deduplicated, furthest)



def _already_settled(item: "Item | None", issue: "TrackerIssue") -> bool:
    """Whether this issue is one somebody already closed and nothing has happened to since.

    **The defect the first real sweep produced, and it reopened four closed items.** DR-0011 says
    resolved issues are not swept and that "a closed item that recurs is already handled — `dedup`
    calls that a regression". Both sentences are true and together they miss a case, because they
    assume the sweep only ever sees new activity.

    It does not. A tracker issue stays `unresolved` until a human marks it resolved *there*, and
    nobody does — the items were closed in Hullwork and on the forge. So the first pass, which has
    no
    high-water mark by definition, sees every one of them and `resolve` reads each as an occurrence
    against a closed item: a **regression**. Measured on the live instance: four items back from
    `done` to `ready`, which is a dispatcher about to spend four attempts on probes.

    The distinction the sweep needs and a delivery does not:

    * **a delivery is an event.** It arrived because the error happened again, so against a closed
      item it genuinely is a regression, and `dedup` is right about it.
    * **a list row is a state.** It says the issue is open, not that anything has happened.

    So a closed item is only reopened when the issue has been *active since the item was settled*.
    `updated_at` is when the item last changed, which for a closed one is when it was closed;
    `last_seen` is when the tracker last saw the error. If the error has not been seen since,
    nothing
    has recurred.

    An issue with no `last_seen` is treated as settled — the safe direction, because reopening on
    missing information is what this exists to prevent.
    """
    if item is None or item.state not in CLOSED:
        return False
    if issue.last_seen is None:
        return True
    return bool(issue.last_seen <= item.updated_at)


def sweep(
    session: Session,
    forge: Forge | None = None,
    limit: int = 100,
    recheck_after: int = 600,
    tracker: Tracker | None = None,
    inventory: TrackerInventory | None = None,
) -> SweepResult:
    """Finish everything outstanding: deliveries, then items owed an issue, then the way back.

    In that order, because a delivery processed in this pass may itself leave an item stranded if
    the forge is having a bad minute, and there is no reason to make it wait for the next one.

    **Returns immediately if another pass is running.** Skipping is the right answer rather than
    queueing: the work is idempotent and the next tick is sixty seconds away, so waiting would only
    pile up threads behind a pass that is already doing exactly what they came to do.
    """
    if not _SWEEP_LOCK.acquire(blocking=False):
        log.debug("sweep already running, skipping this pass")
        return SweepResult(deliveries=0, filed=0, resolved=0, fetched=0, swept=0, skipped=True)
    try:
        deliveries = drain_pending(session, forge, limit)
        filed = drain_unmaterialised(session, forge, limit)
        resolved = reconcile_closed(session, forge, recheck_after=recheck_after)
        # Last: it is the only step that is pure enrichment. An item is filed and reconciled
        # whether or not the tracker answers, and a tracker having a bad minute must not delay
        # the work that has a human waiting on it.
        fetched = fetch_context(session, tracker, recheck_after=recheck_after)
        # After enrichment, and last of all: DR-0011. The inventory is how an issue that never got a
        # webhook — because the tracker speaks once per issue for its whole life — arrives at all.
        # It goes here rather than in the dispatcher because it needs the ingest credential and
        # nothing else, and because `fetch_context` already runs on this clock for the same reason.
        #
        # A project that has never been swept is skipped: the first pass of a real backlog is an
        # explicit act (`hullwork sweep <slug> --confirm`), never a side effect of a tick.
        swept = sweep_inventory(session, inventory)
        # **Last of all, and on this clock for the same reason as the two above** (M9). A recurrence
        # cannot arrive by webhook: the tracker notifies once per issue for that issue's whole life,
        # so a returning error belongs to an issue that has already spent its notification. It needs
        # the ingest credential and nothing else — a pull request's merge state is a read — which is
        # why it lives here and not in the dispatcher.
        recurrence.watch(session, forge, tracker)
        for outcome in swept:
            if outcome.created:
                # Filed on the next pass through `drain_unmaterialised`, which already exists for
                # exactly this: an item owed an issue, whoever created it.
                log.info(
                    "the inventory found errors no webhook reported",
                    # `filed`, never `created` — see `_sweep_one`.
                    extra={"project": outcome.project, "filed": outcome.created},
                )
        confirm_forge(session, forge, recheck_after)
    finally:
        _SWEEP_LOCK.release()
    return SweepResult(
        deliveries=deliveries,
        filed=filed,
        resolved=resolved,
        fetched=fetched,
        swept=sum(outcome.created for outcome in swept),
    )


def _channel_for(project: Project) -> str:
    manifest = project.manifest or {}
    return str((manifest.get("notify") or {}).get("channel", "none"))


def _notify(by_channel: dict[str, list[Resolution]]) -> None:
    """One message per channel, and none at all when there is nothing to say."""
    for channel, resolutions in by_channel.items():
        try:
            notifier = make_notifier(channel)
        except UnsupportedChannelError:
            # Configured for a channel this build cannot deliver to. Loud in the log, harmless to
            # the pipeline: the items are filed either way.
            log.warning("digest not delivered, unsupported channel", extra={"channel": channel})
            continue
        notify_safely(notifier, build_digest(resolutions))


def _manifest_for(project: Project) -> Manifest:
    """The manifest cached at registration. Re-fetching here would put the forge in the hot path.

    **A cached copy that no longer validates degrades instead of failing.** The snapshot is
    re-validated against whatever code is running, so the day a field is renamed every already
    registered project would start raising here — and a `ValidationError` is permanent, so every
    delivery for that project would be sealed on arrival while the instance looked healthy.

    Falling back to a manifest with no lanes means everything lands red, which is the safe
    direction: a human looks at it. Loudly, because a project whose rules have quietly stopped
    applying is not a state to sit in.
    """
    if not project.manifest:
        msg = f"project {project.slug} has no cached manifest"
        raise ValueError(msg)
    try:
        return Manifest.model_validate(project.manifest)
    except ValidationError:
        log.error(
            "cached manifest no longer validates; treating everything as red until it is "
            "refreshed with `hullwork projects refresh`",
            extra={"project": project.slug},
        )
        cached: dict[str, Any] = project.manifest or {}
        raw_git = cached.get("git")
        git: dict[str, Any] = raw_git if isinstance(raw_git, dict) else {}
        # The row is the fallback for both, because it is the thing registration verified.
        return Manifest(
            project=str(cached.get("project") or project.slug),
            git=GitConfig(
                provider=str(git.get("provider") or project.forge),  # type: ignore[arg-type]
                repo=str(git.get("repo") or project.repo),
            ),
        )


def _materialise(
    session: Session, forge: Forge, project: Project, resolution: Resolution
) -> bool:
    """Give the item a home in the forge, if it deserves one.

    Deduplicated occurrences never reach here: no issue, no comment, no noise. That silence is the
    single most valuable behaviour in the product.
    """
    if not resolution.needs_attention:
        return False
    return _file(session, forge, project, resolution.item)


def _file(session: Session, forge: Forge, project: Project, item: Item) -> bool:
    """One attempt at making the forge agree with the database. Returns whether it landed.

    **Which operation this is comes from the item, not from the caller.** An item that already has
    a reference needs that issue reopened; one without needs an issue created. That is what lets
    the retry pass — which has no resolution in hand, only a row — do exactly what the original
    attempt would have done.

    A failure of any kind leaves `forge_sync_pending` set. Even a permanent one: an item nobody can
    file is a bug nobody will see, and one wasted API call per pass is the cheaper mistake.
    """
    try:
        if item.forge_issue_ref:
            number = int(item.forge_issue_ref.lstrip("#"))
            forge.set_issue_state(project.repo, number, "open")
            forge.comment(project.repo, number, _regression_comment(item))
        else:
            # Look before creating. The marker is already in every body we write, and adopting an
            # existing issue is the difference between recovering and filing a duplicate — which
            # is this product's cardinal sin. It covers three real cases: a database restored from
            # an older backup than the forge, a second process racing this one, and an issue that
            # was created just before the commit recording it failed.
            existing = forge.find_issue_by_marker(project.repo, item.fingerprint)
            if existing is not None:
                log.info(
                    "adopted an issue that was already filed",
                    extra={"item_id": item.id, "issue": existing.ref},
                )
                item.forge_issue_ref = existing.ref
            else:
                name, colour = LANE_LABELS[item.lane]
                label_ids = forge.ensure_labels(project.repo, {name: colour})
                issue = forge.create_issue(
                    project.repo, item.title, _issue_body(item), label_ids=[label_ids[name]]
                )
                item.forge_issue_ref = issue.ref
        item.forge_sync_pending = False
        item.forge_error = None
        item.forge_attempts += 1
        session.commit()
        record_forge("ok")
    except ForgeError as exc:
        # The item keeps its fingerprint and its place in the queue, so the next sweep tries again.
        # Losing the issue is recoverable; losing the item would not be.
        session.rollback()
        item.forge_attempts += 1
        item.forge_error = f"{type(exc).__name__}: {exc}"[:500]
        session.commit()
        record_forge(f"unreachable:{exc.status or type(exc).__name__}")
        log.warning(
            "forge did not accept the item, still queued",
            extra={"item_id": item.id, "attempts": item.forge_attempts},
        )
        return False
    else:
        return True


def _issue_body(item: Item) -> str:
    lines = [
        "Reported by Hullwork from a production error.",
        "",
        "| | |",
        "|---|---|",
        f"| Lane | {item.lane.value} |",
        f"| Occurrences | {item.occurrences} |",
        f"| First seen | {item.first_seen.isoformat()} |",
    ]
    if item.lane_reason:
        lines.append(f"| Why this lane | {item.lane_reason} |")
    if item.lane is Lane.RED:
        # **Where to reclassify it depends on where the manifest lives** (DR-0012). Telling a
        # reader to edit `hullwork.yml` in a repository that has none is a sentence this decision
        # created on the day it shipped: measured on the first project connected that way, in the
        # first issue it filed.
        held = getattr(item.project, "manifest_origin", None) == "operator"
        where = (
            "the manifest this instance holds — `hullwork projects refresh "
            f"{item.project.slug} --manifest FILE`, since this repository declares none"
            if held
            else "`hullwork.yml`"
        )
        lines += [
            "",
            f"Red lane: an agent will never touch this. Reclassify it in {where} if that is wrong.",
        ]
    lines += ["", marker_for(item.fingerprint), ""]
    return "\n".join(lines)


def _regression_comment(item: Item) -> str:
    return (
        f"**This came back.** Seen again after the issue was closed "
        f"({item.occurrences} occurrences in total).\n\n"
        "Reopened as a regression rather than filed as a new problem, so the fix that did not hold "
        "stays visible.\n"
    )


def adapters_available() -> Sequence[str]:
    """Providers this build can normalise. Used by the receiver to reject unknown ones early."""
    return tuple(_ADAPTERS)
