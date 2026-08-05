"""Did the fix hold? M9, and DR-0005's role 6.
**The only claim this product makes that converts somebody who does not believe it.** Everything
else Hullwork says about itself is about process — a test failed, then it passed, a human merged.
This is about outcome: the error stopped happening, or it did not, counted by each instance about
its own repository.

Three facts shape the whole module, and each one removes an easier design:

**A recurrence cannot arrive by webhook.** GlitchTip's alert query carries
`.exclude(notification__project_alert=alert)`: an issue notified once is excluded from that alert
*permanently* — not a cooldown, a window, or a rate limit. So the returning error belongs to an
issue that has already used up its one notification, and nothing will ever be delivered for it
again. This has to poll, which is why `Tracker.fetch_samples` exists and had no caller until now.

**Hullwork does not merge, so it cannot know at publish time whether a merge happened.** The
merge commit is read from the forge afterwards, and until it is read, `Attempt.merge_commit is
None` means either "not merged" or "not asked yet" — `Item.merge_checked_at` is what tells those
apart.

**A recurrence is not the same as an error arriving from old code.** A release that predates the
merge can still be deployed and still be reporting: that says nothing about the fix. Item 039 is
the same confusion caught from the other direction — an error that reproduces at the deployed
commit and not at the tip is *already fixed*, not unreproducible. Here the question is inverted
and the answer needs the same care: **only a recurrence from code that contains the merge counts
against the fix.**

And when containment cannot be decided — the tracker reports `0.4.2` rather than a commit, which
is most instances — this says so instead of guessing. `Verdict.UNDECIDABLE` is not a failure of
the watch; it is the honest answer to a question the available data cannot settle, and an
operator who reads it knows to record commits in their release string if they want the number.

"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.orm import Session

from hullwork.forge import SHA, ForgeError
from hullwork.models import Attempt, AttemptOutcome, Item, ItemState, Project
from hullwork.outcomes import rejection_reason
from hullwork.states import IllegalTransitionError, transition
from hullwork.tracker import RetryableTrackerError, TrackerError

if TYPE_CHECKING:  # pragma: no cover - imports for types only
    from hullwork.forge import Forge
    from hullwork.tracker import Tracker

log = logging.getLogger(__name__)

#: How long between asking about the same item. Generous on purpose: a merged fix that holds is
#: the common case, the question is not urgent, and every ask costs a tracker request plus a
#: forge request per item. A daily answer to "did it come back" is as useful as an hourly one.
RECHECK_SECONDS = 6 * 60 * 60

#: How long an item is watched after its merge before it is called held. A fix that has not recurred
#: in two weeks of production is a fix that held, and watching for ever would mean every merged item
#: this instance has ever seen costs two requests a day for the life of the deployment.
WATCH_DAYS = 14

#: Items looked at per pass. The watch shares its clock with ingest, and a backlog of merged
#: items must not push the work with a human waiting on it out of the tick (the shape item 080
#: used for the inventory, for the same reason).
WATCH_LIMIT = 20


class Verdict(StrEnum):
    """What one pass concluded about one merged fix."""

    #: No occurrence after the merge. Not proof of anything yet — see `HELD`.
    QUIET = "quiet"
    #: Quiet for the whole watch window. This is the number worth publishing.
    HELD = "held"
    #: An occurrence from code that contains the merge. The fix did not hold.
    RECURRED = "recurred"
    #: An occurrence arrived, and whether the code it came from contains the merge cannot be
    #: established — a version string rather than a commit, or refs the forge does not know.
    UNDECIDABLE = "undecidable"
    #: Nothing was asked: not merged, or nothing to ask with.
    SKIPPED = "skipped"


@dataclass(frozen=True)
class Watched:
    """One item the watch looked at, and what it concluded."""

    item_id: int
    verdict: Verdict
    note: str
    release: str | None = None


def _as_utc(moment: datetime) -> str:
    """A moment as an operator can compare it against their tracker.

    A separate function because the alternative was writing `%Y-%m-%d %H:%M` three times and
    labelling the result UTC three times, which is how a value carrying `+02:00` got printed as
    though it were UTC on the live instance. Converting is the whole job; naming it stops the next
    call site from forgetting.
    """
    return f"{moment.astimezone(UTC):%Y-%m-%d %H:%M} UTC"


def _merged_attempt(session: Session, item: Item) -> Attempt | None:
    """The attempt that opened the pull request for this item, if there is one.

    Newest first, because an item can have several attempts and only the last one published.
    """
    return session.scalars(
        select(Attempt)
        .where(
            Attempt.item_id == item.id,
            Attempt.pull_request_ref.is_not(None),
            Attempt.outcome.in_(
                (AttemptOutcome.PR_OPEN, AttemptOutcome.PR_OPEN_LINT_FAILED),
            ),
        )
        .order_by(Attempt.id.desc())
        .limit(1)
    ).first()


def _pull_request_number(ref: str) -> int | None:
    """The number out of whatever the publisher stored — `#12`, `12`, or a URL ending in it."""
    tail = ref.rstrip("/").rsplit("/", 1)[-1].lstrip("#")
    return int(tail) if tail.isdigit() else None


def due(session: Session, *, now: datetime | None = None) -> list[Item]:
    """Items whose merged fix is worth asking about on this pass.

    An item is due when it published a pull request, is in a state that means the work is over, and
    has either never been checked or was last checked longer ago than `RECHECK_SECONDS`.

    The window is applied here rather than at the verdict, so an item that held stops costing
    requests the day it ages out instead of being asked about for ever.
    """
    moment = now or datetime.now(UTC)
    cutoff = moment - timedelta(seconds=RECHECK_SECONDS)
    return list(
        session.scalars(
            select(Item)
            .join(Attempt, Attempt.item_id == Item.id)
            .where(
                Attempt.pull_request_ref.is_not(None),
                Item.state.in_((ItemState.PR_OPEN, ItemState.DONE, ItemState.REOPENED)),
                # A settled verdict means done being asked about — this is where the watch stops
                # costing requests. A verdict rather than a clock, because `HELD` is what the window
                # produces: filtering by the window here would exclude the very items ready to be
                # called held.
                # `SKIPPED` joins them (item 121): it is only ever written for a skip that can
                # never resolve, and asking again costs a request to learn the same thing.
                Item.recurrence_verdict.notin_(
                    (Verdict.HELD.value, Verdict.RECURRED.value, Verdict.SKIPPED.value)
                )
                | Item.recurrence_verdict.is_(None),
                (Item.merge_checked_at.is_(None)) | (Item.merge_checked_at < cutoff),
            )
            # Never-asked first, then oldest answer: a new merge is more interesting than re-asking
            # about one that was quiet an hour ago.
            .order_by(Item.merge_checked_at.is_not(None), Item.id)
            .limit(WATCH_LIMIT)
        ).unique()
    )


def _decide(
    attempt: Attempt,
    project: Project,
    samples: list[tuple[str | None, datetime | None]],
    forge: Forge,
) -> tuple[Verdict, str, str | None]:
    """Read the samples against the merge and say what they mean.

    Split out so the decision is testable without a tracker or a forge: what it takes is a list of
    `(release, occurred_at)` pairs, which is all `fetch_samples` contributes.
    """
    commit = attempt.merge_commit
    merged_at = attempt.merged_at
    if commit is None:
        return (
            Verdict.SKIPPED,
            "the forge reports the pull request as merged and gives no merge commit, so whether a "
            "recurrence carries the fix cannot be decided",
            None,
        )

    after = [
        (release, when)
        for release, when in samples
        if when is not None and merged_at is not None and when > merged_at
    ]
    if not after:
        return (
            Verdict.QUIET,
            f"no occurrence since the fix was merged at {_as_utc(merged_at)}"
            if merged_at
            else "no occurrence since the fix was merged",
            None,
        )

    # Newest first, because the freshest occurrence is the one that decides.
    after.sort(key=lambda pair: pair[1] or datetime.min.replace(tzinfo=UTC), reverse=True)
    undecided: list[str] = []
    for release, when in after:
        if not release:
            undecided.append("an occurrence with no release recorded")
            continue
        if not SHA.fullmatch(release):
            # **Checked here, not inferred from the forge's answer.** `release_contains` returns
            # `None` for this *and* for a ref the forge cannot resolve, and this module used to
            # report both with the same sentence — so an unresolvable commit was announced to the
            # operator as "the tracker records a version rather than a sha", about a 40-character
            # sha. A note that asserts a reason it did not establish is worse than a vague one.
            undecided.append(
                f"release {release} is a version string rather than a commit, so whether it "
                f"carries the fix cannot be established"
            )
            continue
        try:
            contains = forge.release_contains(project.repo, release, commit)
        except ForgeError as exc:
            # A forge that cannot answer is not evidence either way, and the watch runs again.
            return (
                Verdict.UNDECIDABLE,
                f"the forge could not compare release {release} with the merge commit: {exc}",
                release,
            )
        if contains is True:
            return (
                Verdict.RECURRED,
                f"the error occurred at {_as_utc(when)} from release {release}, which "
                f"contains the merge commit {commit[:12]} — the fix did not hold",
                release,
            )
        if contains is False:
            # Old code still deployed and still reporting. Says nothing about the fix, and saying so
            # is the whole reason this is three answers rather than two.
            continue
        undecided.append(
            f"the forge could not resolve release {release} against the merge commit — one of the "
            f"two refs is unknown to it"
        )

    if undecided:
        return (Verdict.UNDECIDABLE, "; ".join(dict.fromkeys(undecided)), after[0][0])
    return (
        Verdict.QUIET,
        f"{len(after)} occurrence(s) since the merge, all from releases that predate it — old code "
        f"still deployed, which says nothing about the fix",
        after[0][0],
    )


def watch(
    session: Session,
    forge: Forge | None = None,
    tracker: Tracker | None = None,
    *,
    now: datetime | None = None,
) -> list[Watched]:
    """One pass of the recurrence watch. M9.

    For each due item: ask the forge whether its pull request was merged, and if so ask the tracker
    whether the error has occurred since — then decide what that means against the merge commit.

    A `RECURRED` verdict reopens the item as a regression, which is the state `dedup.resolve`
    already uses when a closed item comes back, so nothing downstream needs to learn a new one.

    Every path writes `merge_checked_at`, including the ones that conclude nothing. A pass that asks
    and does not record having asked is a pass that asks again in sixty seconds, for ever — measured
    on `fetch_context` (item 083), where the same omission cost twenty requests a minute.
    """
    if forge is None or tracker is None:
        return []

    moment = now or datetime.now(UTC)
    watched: list[Watched] = []
    for item in due(session, now=moment):
        result = _watch_one(session, item, forge, tracker, moment)
        if result is not None:
            watched.append(result)
        # Committed per item rather than per pass: one item's tracker timing out must not throw away
        # the timestamps the items before it earned (item 083's second half).
        session.commit()
    if watched:
        log.info(
            "recurrence watch",
            extra={"looked_at": len(watched), "recurred": sum(
                1 for w in watched if w.verdict is Verdict.RECURRED
            )},
        )
    return watched


def _settled(item: Item, note: str) -> Watched:
    """Record a skip that can never resolve, so the watch stops asking. Item 121.

    **Two of the five skip paths are permanent** — an item with no tracker permalink, and a stored
    pull request reference with no number in it — and three are transient: the forge could not be
    asked, the tracker could not be read, the pull request is still open. Only the permanent ones
    are written, because a verdict recorded for a transient failure abandons an item over one bad
    afternoon.

    Measured on the live instance: item 9's fix was merged on 2026-07-29 and cannot be decided,
    and with no verdict stored `due` selected it every six hours for ever — four forge requests a
    day on a question whose answer cannot change, against that function's own promise that a
    settled item *"stops costing requests"*.
    """
    item.recurrence_note = note
    item.recurrence_verdict = Verdict.SKIPPED.value
    return Watched(item.id, Verdict.SKIPPED, note)


def _watch_one(
    session: Session, item: Item, forge: Forge, tracker: Tracker, moment: datetime
) -> Watched | None:
    """One item, and never raising: the pass has to survive one bad answer."""
    item.merge_checked_at = moment
    attempt = _merged_attempt(session, item)
    if attempt is None or not attempt.pull_request_ref:  # pragma: no cover - `due` filters these
        return None
    number = _pull_request_number(attempt.pull_request_ref)
    if number is None:
        return _settled(
            item,
            f"the stored pull request reference {attempt.pull_request_ref!r} has no number in it, "
            f"so the forge cannot be asked whether it was merged",
        )

    try:
        state = forge.merge_state(item.project.repo, number)
    except ForgeError as exc:
        item.recurrence_note = f"the forge could not be asked about the pull request: {exc}"
        return Watched(item.id, Verdict.SKIPPED, item.recurrence_note)

    if not state.merged:
        # **"Not merged" was two facts wearing one answer** (item 138). A pull request nobody has
        # opened and one a reviewer closed without merging both landed here, so an item stayed
        # `pr-open` for ever in both cases — and review debt, which is the count of the first kind,
        # could not be told from refusals, which are the second.
        if state.state == "closed":
            # Through `transition`, never by assignment: item 042 made that a rule and a test
            # asserts it, which is how this line was caught the first time it was written.
            transition(item, ItemState.REJECTED)
            item.rejected_reason = rejection_reason(state.labels)
            item.recurrence_note = (
                "a human closed the pull request without merging"
                + (f" — {item.rejected_reason}" if item.rejected_reason else ", and said no reason")
            )
            # Terminal, so the watch stops: a question whose answer cannot change was costing four
            # forge requests a day (item 121's lesson, one state later).
            return Watched(item.id, Verdict.SKIPPED, item.recurrence_note)
        item.recurrence_note = "the pull request is open; nothing to watch yet"
        return Watched(item.id, Verdict.SKIPPED, item.recurrence_note)

    # Recorded on the attempt the moment it is known, so the number in `status` does not depend on
    # the tracker answering.
    attempt.merge_commit = state.commit
    # **Normalised here, not at the point it is printed.** A forge answers in its own offset —
    # `2026-07-30T19:03:17+02:00` from ours — and `UtcDateTime` converts on the way to the database,
    # so before the round trip the value in memory disagreed with the value on disk. Measured on the
    # live instance: the column read 17:03 and the note this pass wrote said "19:03 UTC", which is
    # two hours of an operator's time spent finding out that both were the same moment.
    attempt.merged_at = state.merged_at.astimezone(UTC) if state.merged_at else None

    permalink = item.permalink
    if not permalink:
        return _settled(
            item,
            "the item has no tracker permalink, so its occurrences cannot be read — this is what "
            "item 086 fixed for enrichment and it applies here for the same reason",
        )

    try:
        samples = tracker.fetch_samples(permalink, limit=5)
    except RetryableTrackerError as exc:
        item.recurrence_note = f"the tracker could not be read this pass: {exc}"
        return Watched(item.id, Verdict.SKIPPED, item.recurrence_note)
    except TrackerError as exc:
        item.recurrence_note = f"the tracker refused: {exc}"
        return Watched(item.id, Verdict.SKIPPED, item.recurrence_note)

    verdict, note, release = _decide(
        attempt, item.project,
        [(sample.release, sample.occurred_at) for sample in samples],
        forge,
    )

    # **Quiet becomes held when the window closes**, and only then. `QUIET` says "nothing yet",
    # which is not a claim worth publishing — a fix quiet for ten minutes has demonstrated nothing.
    # `HELD` is the one this instance counts, and it costs two weeks of not recurring.
    if (
        verdict is Verdict.QUIET
        and attempt.merged_at is not None
        and moment - attempt.merged_at >= timedelta(days=WATCH_DAYS)
    ):
        verdict = Verdict.HELD
        note = (
            f"no occurrence in the {WATCH_DAYS} days since the fix was merged at "
            f"{_as_utc(attempt.merged_at)} — this one held"
        )

    item.recurrence_note = note
    item.recurrence_verdict = verdict.value

    if verdict is Verdict.RECURRED and item.state is not ItemState.REOPENED:
        try:
            transition(item, ItemState.REOPENED)
        except IllegalTransitionError:
            # A state machine refusal is the state machine's business, and it is right whatever this
            # module wants. The verdict and its reason are recorded either way, so an operator sees
            # what happened even when the item could not move.
            log.warning(
                "a recurrence was found and the item could not be reopened",
                extra={"item": item.id, "state": item.state.value},
            )
    return Watched(item.id, verdict, note, release)


def counted(session: Session) -> tuple[int, int, int]:
    """`(merged, holding, recurred)` — what DR-0005 asks each instance to compute about itself.

    Read from what the watch has already written rather than recomputed from the tracker: this is
    what `status` prints, and a status command that spends two network requests per merged item is a
    status command nobody runs.

    "Holding" is deliberately *not* "merged minus recurred". An item nobody has asked about yet is
    neither holding nor recurred, and folding it into the good number is how a figure like this
    starts flattering itself.
    """
    from sqlalchemy import distinct, func

    merged = session.scalar(
        select(func.count(distinct(Attempt.item_id))).where(Attempt.merge_commit.is_not(None))
    )
    holding = session.scalar(
        select(func.count()).select_from(Item).where(
            Item.recurrence_verdict == Verdict.HELD.value
        )
    )
    recurred = session.scalar(
        select(func.count()).select_from(Item).where(
            Item.recurrence_verdict == Verdict.RECURRED.value
        )
    )
    return int(merged or 0), int(holding or 0), int(recurred or 0)


def undecided(session: Session) -> int:
    """Merged fixes whose verdict can never arrive. Item 121.

    **Its own function rather than a fourth element of `counted`**: that tuple is what M9 defined
    and what its tests assert, and widening it would have rewritten assertions that were never
    wrong. This is a different question — not *what did the watch conclude* but *how many merges it
    will never conclude anything about* — and a reader of `status` needs both.

    Measured on 2026-08-02: four merged fixes, three that can still hold, and one whose item has no
    tracker permalink. Printing the first number alone invited the reader to expect four when the
    window closed.
    """
    from sqlalchemy import distinct, func

    return int(
        session.scalar(
            select(func.count(distinct(Item.id)))
            .select_from(Item)
            .join(Attempt, Attempt.item_id == Item.id)
            .where(
                Attempt.merge_commit.is_not(None),
                Item.recurrence_verdict == Verdict.SKIPPED.value,
            )
        )
        or 0
    )
