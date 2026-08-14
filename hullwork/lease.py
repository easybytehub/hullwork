"""The dispatcher's claim on being the dispatcher. Item 075, DR-0009.

One row, held by whichever loop is running, renewed every turn. It answers three questions that were
separate problems and turn out to be the same one:

* **May I dispatch?** — `_SWEEP_LOCK` is in-process and its own comment admits a second *process* is
  not covered. Two loops against one database would both claim items. A row is visible to both.
* **Is the dispatcher alive?** — the renewal *is* the heartbeat. Nothing extra to write, and nothing
  that can disagree with the lock about who is running.
* **Did the previous one die?** — an expired lease is the evidence, and it is what lets the next
  start release items claimed by a corpse without an operator running `--release-stale` by hand.

**A lease and not a lock**, because a lock has to be released to be correct and a process that is
killed releases nothing. This expires on its own, which is the only kind of mutual exclusion that
survives `docker kill`.

The holder is opaque and self-chosen: it identifies *a run*, never a machine or a user, and it is
written to the database and to logs. Anything that could name an operator has no business here.
"""

import logging
import os
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from hullwork.models import DispatcherLease

log = logging.getLogger(__name__)

#: How long a lease outlives its last renewal. Generous on purpose: a turn of the loop includes a
#: whole attempt, measured at 12m56s against a real project on 2026-07-29 — and an attempt that
#: takes longer than expected must not have its lease stolen mid-flight by a second process that
#: concluded it was dead. Renewal happens far more often than this, so the only thing this bounds is
#: how long a *genuinely* dead dispatcher blocks the next one.
LEASE_SECONDS = 3600

#: Beyond this, `status` reports the dispatcher as not having run rather than as alive. Deliberately
#: shorter than `LEASE_SECONDS`: "the lease is still valid" and "somebody is working right now" are
#: different claims, and an operator asking whether the thing is running wants the second.
ALIVE_SECONDS = 300

#: What `release` writes to say "given up on purpose", and what `state` reads to tell that apart
#: from a lease whose holder died. Item 078.
#:
#: A named constant because two functions have to agree about it, and they did not: `release` wrote
#: the epoch and `state` had no branch for it, so an orderly shutdown was reported as `stale` — with
#: the sentinel rendered as a date, which is where `no dispatcher has run since 1970-01-01` came
#: from. Same reason `PUBLICATION_FAILED` became one constant in item 077.
RELEASED = datetime.fromtimestamp(0, tz=UTC)


def _now() -> datetime:
    return datetime.now(UTC)


def new_holder() -> str:
    """An identifier for one run of the loop.

    Random, plus the pid for the operator who is looking at two log lines and wants to know whether
    they came from the same process. Nothing derived from the host or the user: this string goes
    into the database and into logs, and a lease is not a place to leak who is running Hullwork.
    """
    return f"{uuid.uuid4().hex[:12]}-{os.getpid()}"


def holder_of(session: Session) -> str | None:
    """Who holds the lease right now, or `None` when nobody ever has. Item 097.

    Read *before* `acquire`, because `acquire` overwrites it — and what the caller needs to know is
    whether the lease changed hands, which is the only available proof that a previous dispatcher is
    gone rather than merely quiet.
    """
    lease = session.get(DispatcherLease, 1)
    return lease.holder if lease is not None else None


def acquire(session: Session, holder: str, *, error_reporting: bool | None = None) -> bool:
    """Take the lease, or return `False` because somebody living has it.

    Committed before returning, so a second process sees the answer rather than racing on it. Two
    loops starting in the same second is the case this exists for, and SQLite serialises the write —
    the loser reads a fresh row and declines.

    `error_reporting` is written beside the holder because this row is the only thing the two
    programs share (item 110). It describes **this** run, so it is set here and nowhere else: a
    dispatcher that took the lease with reporting off does not become a reporting one because the
    next process would have been.
    """
    now = _now()
    lease = session.get(DispatcherLease, 1)
    if lease is None:
        session.add(
            DispatcherLease(
                id=1, holder=holder, acquired_at=now, renewed_at=now,
                error_reporting=error_reporting,
            )
        )
        session.commit()
        log.info("dispatcher lease taken", extra={"holder": holder, "previous": None})
        return True

    if lease.holder != holder and lease.renewed_at > now - timedelta(seconds=LEASE_SECONDS):
        log.warning(
            "another dispatcher holds the lease; this one will not claim anything",
            extra={"holder": holder, "held_by": lease.holder, "renewed_at": str(lease.renewed_at)},
        )
        return False

    previous = lease.holder
    lease.holder = holder
    lease.acquired_at = now
    lease.renewed_at = now
    lease.error_reporting = error_reporting
    session.commit()
    log.info("dispatcher lease taken", extra={"holder": holder, "previous": previous})
    return True


def reporting_of(session: Session) -> bool | None:
    """Whether the dispatcher holding this lease reports its own errors, or `None` if unrecorded.

    Read by `status`, which runs in the other program and has no other way to find out (item 110).
    `None` covers both "no dispatcher has ever run here" and "the one that did predates the column",
    and both must read as *not recorded* rather than as *off*.
    """
    lease = session.get(DispatcherLease, 1)
    return lease.error_reporting if lease is not None else None


def renew(session: Session, holder: str) -> bool:
    """Keep the lease, and with it the heartbeat. `False` means it was taken away.

    Losing a lease mid-run is not impossible — a long attempt, a clock that moved, an operator who
    forced a second dispatcher — and the loop has to stop rather than carry on writing next to
    somebody else. Reported honestly rather than reacquired silently: two processes both convinced
    they hold it is the state this whole module exists to prevent.
    """
    lease = session.get(DispatcherLease, 1)
    if lease is None or lease.holder != holder:
        log.error(
            "this dispatcher no longer holds the lease",
            extra={"holder": holder, "held_by": None if lease is None else lease.holder},
        )
        return False
    lease.renewed_at = _now()
    session.commit()
    return True


def doing(session: Session, holder: str, what: str | None) -> None:
    """Record what this dispatcher is doing, or `None` for idle. Item 242. Never raises.

    **Best effort, and deliberately so.** This is a page's trace, not the work: a database that
    refuses this write must not take down a verification that is already running. It is also why
    the timestamp moves only when the sentence changes — a step that has been going for nine
    minutes should read as nine minutes, not reset every turn of the loop.
    """
    try:
        lease = session.get(DispatcherLease, 1)
        if lease is None or lease.holder != holder:
            return
        if lease.doing != what:
            lease.doing = what
            lease.doing_since = _now() if what else None
            session.commit()
    except Exception:  # a trace for a page is never worth a rollback of the work
        log.warning("could not record what this dispatcher is doing", extra={"holder": holder})
        session.rollback()


def release(session: Session, holder: str) -> None:
    """Give the lease up on the way out, so the next start does not wait for it to expire.

    Best-effort by nature: a process that is killed does not reach here, which is exactly why the
    lease expires as well. This is the courtesy path, never the guarantee.
    """
    lease = session.get(DispatcherLease, 1)
    if lease is not None and lease.holder == holder:
        lease.renewed_at = RELEASED
        # A stopped dispatcher is not still doing the last thing it was doing (item 242).
        lease.doing = None
        lease.doing_since = None
        session.commit()
        log.info("dispatcher lease released", extra={"holder": holder})


def state(session: Session) -> tuple[str, datetime | None]:
    """What to tell a human: `("alive" | "released" | "stale" | "never", when)`.

    Four states, and the two in the middle are the ones worth having. Before item 075 an operator
    could see that items were waiting and had no way to tell a dispatcher that was busy from one
    dead four days ago — and those need opposite reactions.

    `released` is the fourth, added by item 078 after `status` reported an orderly shutdown as
    *"no dispatcher has run since 1970-01-01"*. The difference is not cosmetic: a holder that
    **died** may have left items claimed mid-attempt, so `stale` sends an operator to
    `--release-stale`, while a lease somebody gave up means nothing is stuck and there is simply
    nothing running. Sending somebody to look for damage after a clean stop is the same mistake this
    docstring already warns about, one state further along.

    No date for `released`: the sentinel is not a time, and rendering it as one is what made the
    report look like a data bug.
    """
    lease = session.get(DispatcherLease, 1)
    if lease is None:
        return "never", None
    if lease.renewed_at == RELEASED:
        return "released", None
    if lease.renewed_at > _now() - timedelta(seconds=ALIVE_SECONDS):
        return "alive", lease.renewed_at
    return "stale", lease.renewed_at
