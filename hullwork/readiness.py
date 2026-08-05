"""Whether this instance is actually working, as opposed to merely running.

`/health` is a liveness probe and deliberately depends on nothing — that is correct for what it is,
and it was the only signal the product had. So an inert error-reporting SDK, an unreachable forge, a
full disk, a disabled retry clock and a backlog of unfiled items all looked exactly like a healthy
service. In one day of real deployment this system failed silently three times and each was found
by luck, because luck was the only detector installed.

Everything here is read from state the pipeline already keeps. **Nothing in this module calls the
forge**: a probe that makes network calls fails for reasons unrelated to the thing it is probing,
and can be pointed at somebody else's server by whoever can reach it. The forge's health is
recorded by the sweep, which talks to it anyway.
"""

import os
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from hullwork import __version__
from hullwork.config import Settings
from hullwork.models import Delivery, Item, ItemState

#: Below this, the next write is a coin toss. Chosen to leave room to notice and act, not to be
#: the last possible moment.
MIN_FREE_BYTES = 50 * 1024 * 1024

#: An item owed an issue for longer than this is not "in flight", it is stuck.
BACKLOG_PATIENCE_SECONDS = 900

#: How many sweeps may be missed before the clock counts as stopped.
MISSED_SWEEPS_ALLOWED = 3

# --- what the pipeline tells us as it goes ----------------------------------------------------
#
# Process-global and deliberately not persisted: after a restart the honest answer is "unknown",
# and a value restored from disk would assert something about a process that no longer exists.

_last_sweep_ok: float | None = None
_forge_state: str = "unknown"
_forge_checked: float | None = None


def record_sweep_ok() -> None:
    """Called at the end of a sweep that completed. The heartbeat of the retry clock."""
    global _last_sweep_ok
    _last_sweep_ok = time.monotonic()


def record_forge(state: str) -> None:
    """`ok`, or `unreachable:<status>`. Recorded by whoever last talked to the forge."""
    global _forge_state, _forge_checked
    _forge_state = state
    _forge_checked = time.monotonic()


def forge_unchecked_for(seconds: float) -> bool:
    """Whether nobody has spoken to the forge lately.

    A healthy idle instance has no reason to call it — no deliveries, nothing to file, nothing
    due for reconciliation — so its state would sit at `unknown` for ever and a revoked token
    would only surface on the day something needed filing, which is the worst possible day.
    """
    return _forge_checked is None or (time.monotonic() - _forge_checked) > seconds


def _sweep_age() -> float | None:
    return None if _last_sweep_ok is None else time.monotonic() - _last_sweep_ok


@dataclass(frozen=True)
class Readiness:
    """The answer, and the numbers behind it, so a human can act without opening the database."""

    ready: bool
    version: str
    problems: list[str] = field(default_factory=list)

    #: Settings never supplied, as opposed to things that broke. **Reported by both callers and
    #: fatal to only one**: an operator asking `hullwork status` whether this instance can do its
    #: job gets no, and a probe asking `/ready` whether this process can serve gets yes, because a
    #: receiver with no forge accepts webhooks and stores them. `ready` ignores these — the
    #: image's healthcheck probes `/ready`, and a documented first look that leaves a container
    #: permanently unhealthy is worse than the silence this replaced.
    gaps: list[str] = field(default_factory=list)

    error_reporting: bool = False
    forge: str = "unknown"
    db_writable: bool = False
    db_free_bytes: int | None = None
    sweep_interval_s: int = 0
    last_sweep_ok_age_s: float | None = None
    backlog: int = 0
    backlog_oldest_age_s: float | None = None
    failed_deliveries: int = 0
    last_delivery_age_s: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def check(
    session: Session,
    settings: Settings,
    *,
    error_reporting: bool,
    forge_state: str | None = None,
) -> Readiness:
    """Assemble the answer. Cheap enough to serve on every probe.

    `forge_state` is for a caller that has **just asked** and is not the process that remembers
    (item 129): `hullwork status` runs in its own interpreter, where the module-level state is the
    import-time default, and reporting `unknown` there described the asker rather than the forge.
    Passing the answer keeps it out of global state that would outlive one report.
    """
    problems: list[str] = []

    writable, free_bytes = _database_state(session, settings)
    if not writable:
        problems.append("the database is not writable")
    if free_bytes is not None and free_bytes < MIN_FREE_BYTES:
        problems.append(f"only {free_bytes // (1024 * 1024)} MB of disk left")

    # The one that would have caught the healthy container with the inert SDK: a DSN set and
    # nothing listening to it is a configuration the operator believes is working.
    if settings.error_dsn is not None and not error_reporting:
        problems.append("HULLWORK_ERROR_DSN is set but error reporting is not running")

    # **Never configured is a gap, and a gap is not a runtime failure.** Both of those halves were
    # found by strangers evaluating the product on 2026-08-04, an hour apart, and the second found
    # the first one's fix overshooting.
    #
    # The finding: this caught a forge gone *unreachable* and said nothing about one never set, so
    # an instance that could file nothing anywhere reported READY, exit 0 — and the
    # `hullwork status || mail me` the README sells as the whole monitoring story could never fire
    # on the likeliest misconfiguration.
    #
    # The overshoot: putting it in `problems` made `/ready` answer 503, and the image's healthcheck
    # probes `/ready`, so the documented first look — start the stack with no forge — produced a
    # permanently **unhealthy** container ninety seconds in. A worse first impression than the
    # defect it fixed.
    #
    # So: one list of facts, two thresholds. `/ready` is a probe about whether this process can
    # serve, and a receiver with no forge serves webhooks and stores them perfectly well; `status`
    # is an operator asking whether this instance can do its job, and there the answer is no. Item
    # 129 required one definition of *the facts*, which this keeps — what it forbade was two
    # components computing one fact differently, not two callers weighing it for different ends.
    gaps: list[str] = []
    if not (settings.forge_url and settings.forge_token):
        gaps.append(
            "no forge is configured (HULLWORK_FORGE_URL, HULLWORK_FORGE_TOKEN), so no item can "
            "ever become an issue"
        )

    known = forge_state or _forge_state
    if known.startswith("unreachable"):
        problems.append(f"the forge is {known.split(':', 1)[1]}")

    age = _sweep_age()
    if settings.sweep_interval_seconds == 0:
        problems.append("the retry clock is disabled (HULLWORK_SWEEP_INTERVAL_SECONDS=0)")
    elif age is not None and age > MISSED_SWEEPS_ALLOWED * settings.sweep_interval_seconds:
        problems.append(f"no sweep has completed for {int(age)}s")

    try:
        backlog, oldest_age = _backlog(session)
        failed_deliveries = _failed_deliveries(session)
        last_delivery_age = _last_delivery_age(session)
    except Exception:  # a database with no tables is exactly `writable` above, not this (item 1)
        session.rollback()
        problems.append("the database has no schema (migrations not applied)")
        backlog, oldest_age, failed_deliveries, last_delivery_age = 0, None, 0, None
    else:
        if oldest_age is not None and oldest_age > BACKLOG_PATIENCE_SECONDS:
            problems.append(f"{backlog} item(s) still owed an issue, oldest {int(oldest_age)}s")

    return Readiness(
        ready=not problems,
        version=__version__,
        problems=problems,
        gaps=gaps,
        error_reporting=error_reporting,
        forge=known,
        db_writable=writable,
        db_free_bytes=free_bytes,
        sweep_interval_s=settings.sweep_interval_seconds,
        last_sweep_ok_age_s=None if age is None else round(age, 1),
        backlog=backlog,
        backlog_oldest_age_s=None if oldest_age is None else round(oldest_age, 1),
        failed_deliveries=failed_deliveries,
        last_delivery_age_s=last_delivery_age,
    )


def sqlite_path(url: str) -> str:
    """The file behind a SQLite URL, absolute or relative.

    `sqlite:///x.db` is relative and `sqlite:////x.db` is absolute — one slash apart, and
    stripping them all turns the production path `/data/hullwork.db` into `data/hullwork.db`,
    which does not exist. The disk-space gate then silently measured nothing at all, which is
    the exact species of failure this module was written to end.
    """
    return url.split("sqlite:///", 1)[-1]


def _database_state(session: Session, settings: Settings) -> tuple[bool, int | None]:
    """Can it be written to, and is there room? Not the same question as "does it answer"."""
    sqlite = settings.database_url.startswith("sqlite")
    try:
        if sqlite:
            # Takes the write lock and gives it straight back: proves the file is not read-only
            # and not held by somebody else. `SELECT 1` would prove neither.
            session.execute(text("BEGIN IMMEDIATE"))
            session.rollback()
        else:
            session.execute(text("SELECT 1"))
        writable = True
    except Exception:  # any failure here is the answer, whatever its class
        session.rollback()
        writable = False

    free = None
    if sqlite:
        directory = os.path.dirname(sqlite_path(settings.database_url)) or "."
        try:
            stat = os.statvfs(directory)
            free = stat.f_bavail * stat.f_frsize
        except OSError:
            free = None
    return writable, free


def _backlog(session: Session) -> tuple[int, float | None]:
    # Closed items are excluded for the reason `drain_unmaterialised` excludes them (item 084): a
    # settled item is owed nothing, and a count that includes what the drain will never touch is a
    # backlog that can never reach zero — an alarm nobody can clear, which is the shape item 073
    # was spent removing.
    row = session.execute(
        select(func.count(Item.id), func.min(Item.updated_at)).where(
            Item.forge_sync_pending.is_(True), Item.state != ItemState.DONE
        )
    ).one()
    count = int(row[0] or 0)
    oldest: datetime | None = row[1]
    if not count or oldest is None:
        return count, None
    return count, (datetime.now(UTC) - oldest).total_seconds()


def _failed_deliveries(session: Session) -> int:
    """Deliveries carrying an error. Written faithfully since M1 and read by nothing until now."""
    return int(
        session.execute(
            select(func.count(Delivery.id)).where(Delivery.error.is_not(None))
        ).scalar_one()
    )


def _last_delivery_age(session: Session) -> float | None:
    """Reported, never a failure condition.

    Tempting as a silence alarm and wrong for this product: an error tracker notifies once per
    issue for the issue's whole life, so deliveries are rare and irregular by design. Days apart is
    normal. Any threshold on it would either cry wolf constantly or never fire at all — it belongs
    in a report a human reads, not in a pass/fail gate.
    """
    latest = session.execute(select(func.max(Delivery.received_at))).scalar_one_or_none()
    if latest is None:
        return None
    return (datetime.now(UTC) - latest).total_seconds()
