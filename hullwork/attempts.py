"""Recording what an attempt did, so a human can check the claim rather than take it.

DR-0003's most useful sentence is "this test failed at commit X and passes at commit Y", and it is
two rows of `attempt_steps`. Nothing else this product can hand a reviewer is worth as much, and it
costs nothing to produce because the dispatcher ran both commands anyway.

The accounting rule lives here too, because it is easy to state and easy to get wrong: an item gets
**one** attempt, and only a run that reached the model and produced a verdict spends it. Anything
that went wrong with the infrastructure — the endpoint unreachable, the sandbox refusing to start,
the base branch moving, the forge down — leaves the item exactly as it was. "The network was bad"
and "the agent could not fix this" must never look the same.
"""

import json
import logging
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from hullwork import scrub
from hullwork.models import Attempt, AttemptOutcome, AttemptPhase, AttemptStep, Item

log = logging.getLogger(__name__)

#: How much of a command's output to keep. Generous, because a traceback is the evidence, and
#: bounded, because a runaway suite can print for as long as you let it.
MAX_OUTPUT_CHARS = 20_000

#: DR-0003 and M1 decision 4: one attempt, then a human.
MAX_ATTEMPTS = 1

#: Outcomes that leave the item exactly as it was, and the default reason each one gives.
#: An item that will be tried again has to say so rather than merely go quiet.
_DOES_NOT_CONSUME: dict[AttemptOutcome, str] = {
    AttemptOutcome.ABANDONED: "the run did not reach a verdict",
    AttemptOutcome.ALREADY_FIXED: (
        "the bug reproduces at the deployed commit and not at the default branch — it appears to "
        "be fixed already and not yet deployed, so the agent was never given a fair attempt"
    ),
    AttemptOutcome.BASELINE_RED: (
        "the project's own test suite was already failing on an untouched checkout, so the attempt "
        "stopped at step 0 before any model was called — nothing was learned about the bug and the "
        "agent was never asked (item 043)"
    ),
}

#: Why a rehearsal does not count, in the words a reader of the issue or the terminal needs.
_REHEARSED = (
    "this was a rehearsal (`hullwork work --no-publish`): every gate ran and nothing was "
    "published, so the item keeps its attempt"
)

_ELLIPSIS = "\n\n… [{dropped} characters removed from the middle] …\n\n"


def bound(output: str, limit: int = MAX_OUTPUT_CHARS) -> tuple[str, bool]:
    """Trim long output from the **middle**, keeping both ends.

    The head carries what ran and the tail carries the summary and the failure; the middle is
    usually the part nobody reads. Cutting the tail — the obvious implementation — throws away the
    line that says which test failed, which is the whole reason the output was kept.
    """
    if len(output) <= limit:
        return output, False
    half = limit // 2
    dropped = len(output) - (half * 2)
    return output[:half] + _ELLIPSIS.format(dropped=dropped) + output[-half:], True


def start(session: Session, item: Item, *, image_tag: str | None = None,
          base_sha: str | None = None, production_ref: str | None = None) -> Attempt:
    """Open an attempt record. Written before anything runs, so a crash still leaves a trace."""
    attempt = Attempt(
        item_id=item.id,
        image_tag=image_tag,
        base_sha=base_sha,
        production_ref=production_ref,
        phase_reached=AttemptPhase.BASELINE,
    )
    session.add(attempt)
    session.flush()
    return attempt


def _environment(given: dict[str, str] | None) -> str | None:
    """A phase's added environment as JSON, scrubbed by name. `None` when it was not recorded.

    **Scrubbed through `scrub.is_secret_name`, the same rule the log filter uses**, rather than a
    second copy of it. Nothing Hullwork passes to a phase is a credential today — DR-0004 puts the
    model credential in the gateway and the engine recipe carries a deliberate placeholder — but
    this column is written from a dict somebody will add to, and the point of a shared rule is that
    the sixth variable is covered by the same sentence as the first five. Item 099 became a defect
    for the mirror-image reason: a list of five names that nobody updated.
    """
    if given is None:
        return None
    return json.dumps(
        {
            name: (scrub.REDACTED if scrub.is_secret_name(name, value) else value)
            for name, value in sorted(given.items())
        },
        ensure_ascii=False,
    )


def record(
    session: Session,
    attempt: Attempt,
    phase: AttemptPhase,
    command: str,
    *,
    exit_code: int | None = None,
    duration_ms: int | None = None,
    output: str = "",
    environment: dict[str, str] | None = None,
) -> AttemptStep:
    """Add one command to the trail and move the attempt's high-water mark.

    **`environment` is what Hullwork added to this command's environment** (item 106, part 6).
    Pass `{}` for a command that got nothing added — a gate — because that is an answer, and the
    answer item 099's defect turned on: the gates ran clean while the agent's phases carried five
    variables the watched project's settings loader rejected. Omitting it leaves the column `NULL`,
    which means *not recorded* and is what every row written before this existed says.

    **Committed, not flushed, and that is item 081.** A flush emits the insert inside the
    transaction, and pysqlite opens its `BEGIN` immediately before it — so the first recorded step
    of
    an attempt took SQLite's write lock and **held it until the attempt ended**. Between two
    steps sits a model phase or a whole test suite, so the lock was held for most of a run:
    measured at 12m56s against a real project.

    Everything else writing to that database then failed. On the live instance, in one day: 58
    `database is locked` on the receiver's sweep (`UPDATE items SET forge_checked_at`) and two on
    **`INSERT INTO deliveries`** — an inbound webhook, which loses an error for ever, because a
    tracker notifies once per issue and never retries. `busy_timeout` is already 5s (pysqlite's
    default, inherited by SQLAlchemy) and 5s against a 13-minute hold is not a wait, it is a
    formality.

    A step is also not provisional: it is a command that has already run and the output it already
    produced. `start`'s docstring promises the record is "written before anything runs, so a crash
    still leaves a trace" — and with a flush that promise was false for every step, since a killed
    dispatcher rolled the whole uncommitted transaction back.
    """
    text, truncated = bound(output)
    ordinal = (
        session.execute(
            select(func.coalesce(func.max(AttemptStep.ordinal), -1)).where(
                AttemptStep.attempt_id == attempt.id
            )
        ).scalar_one()
        + 1
    )
    step = AttemptStep(
        attempt_id=attempt.id,
        ordinal=ordinal,
        phase=phase,
        command=command,
        exit_code=exit_code,
        duration_ms=duration_ms,
        output=text,
        output_truncated=truncated,
        environment=_environment(environment),
    )
    session.add(step)
    attempt.phase_reached = phase
    session.commit()
    return step


def finish(
    session: Session,
    attempt: Attempt,
    outcome: AttemptOutcome,
    *,
    not_consumed_reason: str | None = None,
    seal: dict[str, object] | None = None,
    error: str | None = None,
    rehearsal: bool = False,
) -> Attempt:
    """Close an attempt, deciding in one place whether it spent the item's one shot.

    Two outcomes never consume: `abandoned`, and `already-fixed` (item 039). The second is easy to
    get wrong — it looks like a result and it is one, but it is a result about the *deployment*
    rather than about the bug, and the agent never got a chance to be right or wrong about it.

    Passing a reason with a consuming outcome is a caller confusing "why it failed" with "why it
    does not count", so it is dropped
    rather than stored — a stored contradiction is worse than a missing note.
    """
    attempt.outcome = outcome
    attempt.finished_at = datetime.now(UTC)
    # A rehearsal never consumes, whatever the verdict was (item 049). Decided here rather than by
    # the caller for the same reason the rest of it is: this function's docstring says it owns the
    # question, and item 042 was spent removing the second place that answered it.
    attempt.rehearsal = rehearsal
    attempt.consumed = (not rehearsal) and outcome not in _DOES_NOT_CONSUME
    attempt.not_consumed_reason = None if attempt.consumed else (
        not_consumed_reason or (_REHEARSED if rehearsal else _DOES_NOT_CONSUME[outcome])
    )
    if seal is not None:
        attempt.seal = dict(seal)
    if error is not None:
        attempt.error = error
    session.flush()
    log.info(
        "attempt finished",
        extra={
            "item": attempt.item_id,
            "outcome": outcome.value,
            "consumed": attempt.consumed,
            "phase": attempt.phase_reached.value,
        },
    )
    return attempt


def consumed_count(session: Session, item: Item) -> int:
    """How many of this item's attempts actually counted."""
    return int(
        session.execute(
            select(func.count())
            .select_from(Attempt)
            .where(Attempt.item_id == item.id, Attempt.consumed.is_(True))
        ).scalar_one()
    )


def has_attempt_left(session: Session, item: Item) -> bool:
    """Whether the dispatcher may try this item at all (DR-0003: one attempt, then a human)."""
    return consumed_count(session, item) < MAX_ATTEMPTS
