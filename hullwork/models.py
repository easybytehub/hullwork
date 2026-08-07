"""The persistence layer.

Everything ingested lives here; only what deserves a human's attention becomes a forge issue.
That split is the point (spec M1 §5): the ~80% of traffic that is a repeat never leaves this
database, and the user's git history stays clean.

Portability rule: nothing here may be Postgres-only. The 30-minute quickstart runs on SQLite, so
enums are stored as strings with a check constraint rather than as native database types.
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Dialect,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _now() -> datetime:
    return datetime.now(UTC)


class UtcDateTime(TypeDecorator[datetime]):
    """A timestamp that comes back timezone-aware on every backend.

    SQLite has no timezone type, so a plain `DateTime(timezone=True)` column returns a naive value
    there and an aware one on Postgres: identical code, different behaviour, and the difference
    only shows up once you are in production. Both are normalised to UTC-aware here.

    Naive values are refused on the way in rather than assumed to be UTC. Guessing a timezone is
    how a system ends up reporting events an hour in the future.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            msg = "refusing to store a naive datetime; attach a timezone at the source"
            raise ValueError(msg)
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class Base(DeclarativeBase):
    """Declarative base for every table."""


class Lane(StrEnum):
    """What an agent may attempt. Anything unclassified is red."""

    GREEN = "green"
    AMBER = "amber"
    RED = "red"


class ItemKind(StrEnum):
    """Whether the red-green gate (DR-0003) applies: it does to bugs, not to chores."""

    BUG = "bug"
    OTHER = "other"


class AttemptPhase(StrEnum):
    """How far an attempt got. The six steps of spec M2 §3, in order.

    Stored rather than inferred, because "it stopped at the red gate" and "it never started" are
    different things to a human and identical to a null outcome.
    """

    BASELINE = "baseline"
    REPRODUCE = "reproduce"
    RED_GATE = "red-gate"
    FIX = "fix"
    GREEN_GATE = "green-gate"
    #: Item 046. The green gate run again after test infrastructure the fix had modified was put
    #: back. Recorded as its own phase rather than as a second `green-gate` row, because a reader
    #: has to be able to tell which of the two runs the published claim rests on — and it is always
    #: this one.
    GREEN_GATE_RESTORED = "green-gate-restored"
    LINT_GATE = "lint-gate"
    PUBLISH = "publish"


class AttemptOutcome(StrEnum):
    """How an attempt ended.

    The first three are DR-0003's verdicts and they consume the item's one attempt. `abandoned` is
    the fourth and it does **not**: the endpoint was unreachable, the sandbox would not start, the
    base branch moved, the forge was down. "The network was bad" and "the agent could not fix this"
    are different facts, and only the second is terminal — the same line `RetryableForgeError`
    already draws one layer down.
    """

    PR_OPEN = "pr-open"
    FAILED = "failed"
    NOT_REPRODUCIBLE = "not-reproducible"
    ABANDONED = "abandoned"
    #: Reproduces at the commit production was running and not at the tip: **already fixed
    #: upstream, not yet deployed** (item 039). A verdict about the deployment, not about the bug
    #: and not about the agent, so it does not consume the attempt.
    #:
    #: Without it this outcome is indistinguishable from `not-reproducible`, and it is the most
    #: likely single cause of a wrong verdict: it hits every project that merges more often than
    #: it deploys, which is all of them. Folding it into `not-reproducible` would burn the item's
    #: one attempt *and* fill the bucket DR-0003 calls the honest headline outcome with something
    #: else entirely, which costs the operator the ability to read the signal at all.
    ALREADY_FIXED = "already-fixed"
    #: The gates proved the claim and the project's own lint gate did not pass (item 067). It
    #: **publishes**, because *a test that failed against unmodified code passes with this change
    #: applied* was verified by two commands this system ran, and the lint gate does not contest
    #: that claim — it contests the style of the file that proves it. A reviewer fixes an
    #: unreachable statement in seconds; throwing the verdict away costs the item its one attempt
    #: for something that is not about the bug. Measured here: 67 model calls and ~25,000 output
    #: tokens discarded twice for `Statement is unreachable` in a test the agent wrote.
    #:
    #: Its own value rather than `pr-open`, because publishing under that name would make the trail
    #: say everything passed. It consumes the attempt: there is an artefact for a human to read, so
    #: the item has been dealt with, and requeueing it would be the retry loop DR-0003 forbids.
    PR_OPEN_LINT_FAILED = "pr-open-lint-failed"
    #: The project's own suite was already failing on an untouched checkout, so step 0 stopped the
    #: attempt before any model was called (item 043). Named for what was observed rather than for
    #: what it means, because what it means is a judgement and what it says is a measurement.
    #:
    #: It does not consume the attempt: nothing about the bug was learned and the agent was never
    #: asked. But unlike `abandoned` it does **not** go back in the queue either — the suite will
    #: still be red on the next pass, and an item cycling through a dispatcher for ever is worse
    #: than one waiting for a human. DR-0003 already decided this class: work needing what the
    #: sandbox cannot provide is out of the agent's reach by definition, and goes to a person.
    BASELINE_RED = "baseline-red"


class ItemState(StrEnum):
    """The item lifecycle.

    `duplicate` is deliberately absent: a duplicate does not become an item, it increments the
    occurrence counter of the one that already exists. Making it a state would leave the database
    full of rows representing "nothing happened".

    `failed` and `not_reproducible` are separate on purpose (DR-0003). "I made it happen and could
    not fix it" and "I could not make it happen" need different things from a human.
    """

    NEW = "new"
    TRIAGED = "triaged"
    WAITING_APPROVAL = "waiting-approval"
    READY = "ready"
    IN_PROGRESS = "in-progress"
    PR_OPEN = "pr-open"
    DONE = "done"
    FAILED = "failed"
    NOT_REPRODUCIBLE = "not-reproducible"
    HUMAN_ONLY = "human-only"
    REOPENED = "reopened"
    #: A human read the pull request and closed it without merging. Item 138.
    #:
    #: **The state that did not exist**, and its absence is what made review debt uncountable: a
    #: refused pull request left its item in `pr-open` for ever, indistinguishable from one nobody
    #: had looked at yet. Waiting and refused are opposite facts about the same artefact.
    #:
    #: Terminal. The decision has been made, so the recurrence watch stops asking — a question whose
    #: answer cannot change is four forge requests a day for nothing (item 121's lesson).
    REJECTED = "rejected"


def _enum(enum_type: type[StrEnum], name: str) -> Enum:
    """A string column with a real CHECK constraint.

    Never a native database enum: `CREATE TYPE` does not exist on SQLite and makes Postgres
    migrations painful for no benefit at this size. `create_constraint` is not the default and
    without it the column accepts any string at all — the type would be documentation, not a rule.
    """
    return Enum(
        enum_type,
        native_enum=False,
        create_constraint=True,
        validate_strings=True,
        length=32,
        name=name,
        values_callable=lambda e: [m.value for m in e],
    )


class Project(Base):
    """A connected repository. Registered explicitly; never auto-discovered."""

    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    slug: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    forge: Mapped[str] = mapped_column(String(20))
    repo: Mapped[str] = mapped_column(String(200))

    #: Hashed, never stored in the clear. Shown once at registration and rotated if lost.
    webhook_secret_hash: Mapped[str] = mapped_column(String(128))

    manifest: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)

    #: Where this copy came from: `"repository"`, `"operator"`, or `None`. DR-0012.
    #:
    #: **Three states, and the third is not laziness.** Every project registered before this column
    #: existed came from a repository, and saying so would be inferring it; `None` says *not
    #: recorded*, which is the rule item 105 was closed for and the one that keeps being worth
    #: keeping. `refresh` reads this to decide whether it has anything to re-read.
    manifest_origin: Mapped[str | None] = mapped_column(String(20), default=None)
    manifest_fetched_at: Mapped[datetime | None] = mapped_column(
        UtcDateTime(), default=None
    )

    #: Deactivated rather than deleted: unregistering a project must not destroy its history.
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)

    #: What this project is called **in the error tracker**. DR-0011, item 080.
    #:
    #: Instance configuration rather than manifest, and that is a decision: a repository naming
    #: somebody else's tracker project would be a repository reading errors it does not own. It also
    #: cannot be discovered — the least-privilege tracker token is refused `/api/0/organizations/`
    #: and `/api/0/projects/` (measured, 403), which is correct and means an operator says it.
    #:
    #: `None` means this project is not swept. Ingest, dedup, triage and filing all work exactly as
    #: before; what is missing is the inventory, which is the additive half of DR-0011.
    tracker_project: Mapped[str | None] = mapped_column(String(200), default=None)

    #: How far the inventory sweep has read, by the tracker's own `lastSeen`. DR-0011, item 080.
    #:
    #: **`None` means "never swept", and that is deliberately not the same as "swept and found
    #: nothing".** The first sweep of a project with a real backlog would file one forge issue per
    #: open issue — three hundred of them on somebody's first afternoon is DR-0006's adoption
    #: failure arriving from the other direction — so it has to be an explicit act with its count
    #: shown first, never a side effect of an upgrade.
    #:
    #: A mark on last activity rather than a page cursor, because the provider's `Link` header is
    #: unusable: it arrives wrapped in Python set syntax on every list response.
    tracker_swept_until: Mapped[datetime | None] = mapped_column(UtcDateTime(), default=None)

    items: Mapped[list["Item"]] = relationship(back_populates="project")


class Delivery(Base):
    """One inbound webhook call. This table is also the queue — no broker, by design.

    The unique constraint is what makes a redelivery a no-op. Error trackers retry deliveries by
    design, so this is the ordinary case, not an edge case.
    """

    __tablename__ = "deliveries"
    __table_args__ = (
        UniqueConstraint("project_id", "provider_delivery_id", "payload_hash", name="uq_delivery"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)

    #: Which error tracker sent it. Explicit, because the two payloads cannot be told apart by
    #: sniffing and guessing on a security boundary is not acceptable.
    provider: Mapped[str] = mapped_column(String(20), default="glitchtip")

    #: Empty string when the provider sends no delivery id — NOT NULL, because in SQL two NULLs are
    #: never equal and the unique constraint would silently stop protecting us.
    provider_delivery_id: Mapped[str] = mapped_column(String(200), default="")
    payload_hash: Mapped[str] = mapped_column(String(64))

    #: The body as received. Kept so a delivery accepted before a restart can still be processed
    #: after one: without it, "200, I have it" becomes a lie the moment the process dies.
    payload_json: Mapped[str] = mapped_column(Text, default="{}")

    received_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now, index=True)
    processed_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), default=None)
    error: Mapped[str | None] = mapped_column(Text, default=None)

    #: How many times processing has been tried. Only a transient failure increments it and leaves
    #: `processed_at` null; a payload that cannot be understood is sealed on the first attempt.
    #: The counter is what stops a row failing for an unforeseen reason from jamming the queue.
    attempts: Mapped[int] = mapped_column(Integer, default=0)


class Event(Base):
    """A normalised fact, kept immutable.

    The raw payload is retained verbatim: the day a provider changes its shape, re-normalising the
    history is only possible if the original was kept.
    """

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    delivery_id: Mapped[int] = mapped_column(ForeignKey("deliveries.id"), index=True)

    fingerprint: Mapped[str] = mapped_column(String(128), index=True)
    #: True when we derived the fingerprint ourselves because the provider sent none usable.
    fingerprint_derived: Mapped[bool] = mapped_column(Boolean, default=False)

    title: Mapped[str] = mapped_column(Text)
    culprit: Mapped[str | None] = mapped_column(Text, default=None)
    level: Mapped[str | None] = mapped_column(String(20), default=None)
    permalink: Mapped[str | None] = mapped_column(Text, default=None)

    #: True when the times on this event are when **we** received it, not when it happened.
    #: `ErrorFact` has always carried this and the `Event` boundary dropped it, so every
    #: `first_seen` in the live database is an HTTP receipt time with nothing saying so — and the
    #: field exists precisely to stop a receipt time being read as an event time.
    timestamps_are_receipt_time: Mapped[bool] = mapped_column(Boolean, default=True)

    raw: Mapped[dict[str, Any]] = mapped_column(JSON)

    received_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)


class Item(Base):
    """A unit of work: one distinct problem in one project, however many times it has occurred."""

    __tablename__ = "items"
    __table_args__ = (
        UniqueConstraint("project_id", "fingerprint", name="uq_item_fingerprint"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(128))

    state: Mapped[ItemState] = mapped_column(_enum(ItemState, "item_state"), default=ItemState.NEW)
    lane: Mapped[Lane] = mapped_column(_enum(Lane, "lane"), default=Lane.RED)
    kind: Mapped[ItemKind] = mapped_column(_enum(ItemKind, "item_kind"), default=ItemKind.BUG)

    #: Why this lane was chosen. A lane a human cannot explain is a lane a human will not trust.
    lane_reason: Mapped[str | None] = mapped_column(Text, default=None)

    #: Whether the lane above was chosen by rules that could see **where in the code** the error
    #: happened. Item 070.
    #:
    #: False is the honest default for every row that predates this column: a tracker's webhook
    #: carries no frames, enrichment ran afterwards, and until item 070 a red item was never
    #: enriched at all — so nobody can say those decisions saw a culprit, and claiming they did
    #: would put them permanently beyond a second look. False also costs nothing, because `relane`
    #: only revisits an item once frames arrive and only while nothing has happened to it.
    #: The `server_default` is kept rather than dropped after the migration, unlike its neighbours:
    #: `items` has incoming foreign keys, so it cannot be recreated by `batch_alter_table` without
    #: the drop step failing. See migration `a91f5c0d2e84`.
    lane_saw_code_location: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("0"), nullable=False
    )

    title: Mapped[str] = mapped_column(Text)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    last_seen: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)

    #: The tracker URL for this problem, kept on the item itself. Item 086.
    #:
    #: It used to live only on `events` rows, joined back by `(project_id, fingerprint)` — which was
    #: fine while the webhook was the only way in, because processing a delivery always wrote an
    #: event. The inventory sweep (item 080) writes no events, so its items had no permalink
    #: anywhere `_permalink_for` could see: enrichment never ran for them, and the first real
    #: dogfood attempt was dispatched with a brief that carried the issue title and nothing else.
    permalink: Mapped[str | None] = mapped_column(String(500), default=None)

    #: Set once the item is materialised in the forge. Null while it is still only ours.
    forge_issue_ref: Mapped[str | None] = mapped_column(String(100), default=None)

    #: True while the forge still owes this item something: the issue it never got, or the reopen
    #: that did not land. Stored rather than derived from `forge_issue_ref`, because a failed
    #: reopen already has a reference and still needs the forge — and because the intent has to
    #: survive the attempt that failed to carry it out. Nothing upstream remembers for us: an error
    #: tracker notifies once per issue and never again.
    forge_sync_pending: Mapped[bool] = mapped_column(Boolean, default=False)

    #: How many times filing has been attempted, and why the last one failed. An item that can
    #: never be filed stays queued on purpose; these make it visible rather than merely quiet.
    forge_attempts: Mapped[int] = mapped_column(Integer, default=0)
    forge_error: Mapped[str | None] = mapped_column(Text, default=None)

    #: When the forge was last asked what state this item's issue is in. Null means never. It is
    #: what keeps the reconciliation from asking about every open item on every pass.
    forge_checked_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), default=None)

    #: When the tracker was last asked for this item's full event, and why it failed if it did.
    #: Mirrors the `forge_checked_at`/`forge_error` pair above, for the same reason: without a
    #: timestamp the sweep either asks on every pass or never asks again, and both are wrong.
    context_checked_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), default=None)
    #: When the recurrence watch last asked about this item, and what it concluded (M9). Separate
    #: from `context_checked_at` because they ask different questions of the same tracker: one
    #: wants the evidence for a bug nobody has fixed, the other wants to know whether a merged fix
    #: held.
    #:
    #: `None` and a merged attempt means the watch has not reached it yet, which is why the
    #: backoff is a timestamp rather than a boolean — a poll that cannot say "already asked,
    #: nothing new" asks every minute for the life of the instance.
    merge_checked_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), default=None)
    #: The last recurrence verdict for this item, as a sentence for a person. Kept rather than
    #: derived because the reason a recurrence was *not* counted — "the release predates the
    #: merge", "the tracker reports a version rather than a commit, so containment cannot be
    #: decided" — is the part an operator disagrees with, and it cannot be recomputed once the
    #: tracker has moved on.
    #: Why a human refused it, from the closed set in `outcomes.REJECTION_REASONS`. `None` on a
    #: rejected item means **not given**, which is a different fact from any of the reasons and is
    #: counted separately (item 110's rule, one more time).
    rejected_reason: Mapped[str | None] = mapped_column(String(40), default=None)
    recurrence_note: Mapped[str | None] = mapped_column(Text, default=None)
    #: The watch's verdict, as a value rather than prose (M9). The note above is for a person;
    #: this is what `status` counts, and deriving it from the note or from the item's state would
    #: be guessing: `reopened` is also what a returning error produces through `dedup.resolve`,
    #: and those two are different facts about the same row.
    recurrence_verdict: Mapped[str | None] = mapped_column(String(20), default=None)
    context_error: Mapped[str | None] = mapped_column(Text, default=None)

    #: True when this item came back after being closed. A regression is not a new bug.
    regression: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime(), default=_now, onupdate=_now
    )
    #: When this item entered the state it is in. Item 141, and the signal the board is made of.
    #:
    #: **Not `updated_at`**, which moves on any change at all — an occurrence counter, a permalink,
    #: a context fetch — so an item six days into `waiting-approval` reads as fresh the morning its
    #: count is bumped. A column that says *3 items* is a photograph; *3 items, oldest 6 days* is
    #: the sentence somebody acts on, and it is what makes item 138's review debt visible.
    #:
    #: Written by `states.transition` and nowhere else, the same single door item 042's guard
    #: already watches.
    #:
    #: **Nullable, and not backfilled.** `NULL` means *this item predates the column*. Filling it
    #: from `updated_at` would put a number that is not a transition time into the one column whose
    #: purpose is to be trusted — the shape item 133 already settled when seals written before the
    #: cache fields reported *not recorded* rather than zero.
    state_since: Mapped[datetime | None] = mapped_column(UtcDateTime(), default=_now)

    project: Mapped[Project] = relationship(back_populates="items")


class FetchedEvent(Base):
    """The full error, read from the tracker rather than received from it (item 036).

    A separate table on purpose. `Event.raw` taught the lesson: it stores the whole delivery once
    per error inside it, and 2,000 attachments in one request became a 322 MB database. This is the
    largest object in the system — frames with source context, and 33 to 71 dependency versions —
    so it lives where `prune` can reach it and where the hot tables stay small.

    Several rows per item are allowed. Two samples of one bug are worth more than one: what differs
    between them is usually the input that triggers it, and the tracker keeps every occurrence in
    full. It is also the only route to occurrences 2..N, because the tracker notifies once per
    issue and never again.

    **Everything here is scrubbed before it arrives.** The adapter does it on the way in, not on
    the way out: this is the one table that holds frame locals and `sys.argv`, and an audit found a
    live DSN in one and Hullwork's own webhook token in the other, on real events.
    """

    __tablename__ = "fetched_events"
    __table_args__ = (
        UniqueConstraint("item_id", "provider_event_id", name="uq_fetched_event"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    item_id: Mapped[int] = mapped_column(ForeignKey("items.id"), index=True)

    #: The tracker's own id for this occurrence. The unique constraint above makes re-fetching the
    #: same occurrence a no-op rather than a duplicate.
    provider_event_id: Mapped[str] = mapped_column(String(64))

    exception_type: Mapped[str | None] = mapped_column(String(200), default=None)
    #: Untruncated. The provider's webhook cuts the title at 100 characters, and for a `KeyError`
    #: or a `ValueError` the half it cuts is often the input that reproduces the bug.
    message: Mapped[str | None] = mapped_column(Text, default=None)
    culprit: Mapped[str | None] = mapped_column(Text, default=None)
    handled: Mapped[bool | None] = mapped_column(Boolean, default=None)
    level: Mapped[str | None] = mapped_column(String(20), default=None)

    #: Ordered, innermost last. Each frame carries its path, line, function, the failing source
    #: line and the lines around it — the material a reproducing test is written from.
    frames: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    #: What the failing process had installed. Worth more than a version string.
    packages: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    runtime: Mapped[str | None] = mapped_column(String(100), default=None)
    environment: Mapped[str | None] = mapped_column(String(100), default=None)
    #: Whatever the SDK called the deployed version — a commit sha if the operator was disciplined,
    #: a package version if not. Telling those apart is item 039's job, not this table's.
    release: Mapped[str | None] = mapped_column(String(200), default=None)
    server_name: Mapped[str | None] = mapped_column(String(200), default=None)

    #: When the error actually happened, as the tracker recorded it. Distinct from anything on
    #: `Item`, whose `first_seen` is an HTTP receipt time on the provider we recommend.
    occurred_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), default=None)

    #: The provider's own grouping hash, stored and **not** used as the identity.
    #:
    #: It is the better dedup key — stable across occurrences, verified — and adopting it now would
    #: retroactively split every item already in the database: the same error would hash
    #: differently, become a new item, and be filed a second time in somebody's repository. That is
    #: a migration with a decision behind it, not a side effect of this one. Stored so the decision
    #: can be taken later with the data already in hand.
    grouping_hash: Mapped[str | None] = mapped_column(String(128), default=None)

    fetched_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)


class Attempt(Base):
    """One run of the dispatcher against one item (spec M2 §8).

    There was nowhere to put this. Four tables existed, none of them could hold an attempt, and
    items 025, 027 and 028 all assumed otherwise — spec §8 even claimed the counter was visible in
    `hullwork status`, which it could not be. The third guardrail this milestone found existing
    only in prose, after the gate that ran nothing and the reserved subjects nobody enforced.
    """

    __tablename__ = "attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    item_id: Mapped[int] = mapped_column(ForeignKey("items.id"), index=True)

    started_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), default=None)

    phase_reached: Mapped[AttemptPhase] = mapped_column(
        _enum(AttemptPhase, "attempt_phase"), default=AttemptPhase.BASELINE
    )
    outcome: Mapped[AttemptOutcome | None] = mapped_column(
        _enum(AttemptOutcome, "attempt_outcome"), default=None
    )

    #: Whether this used up the item's one attempt (DR-0003). Stored rather than derived from the
    #: outcome, because the rule is about what happened and not about what it is called: a run
    #: that never reached the model must not spend the attempt whatever went wrong afterwards.
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)
    #: This attempt was a rehearsal — `hullwork work --no-publish` (item 049). Every gate ran and
    #: nothing was published, so it never consumes.
    #:
    #: A flag rather than a new outcome, deliberately: an `AttemptOutcome.REHEARSED` would throw
    #: away the interesting fact, which is that this *would have been* a pull request. A boolean
    #: keeps the real verdict and adds what happened to it.
    rehearsal: Mapped[bool] = mapped_column(Boolean, default=False)
    #: Why not, when not. An item that will be tried again should say so rather than go quiet.
    not_consumed_reason: Mapped[str | None] = mapped_column(Text, default=None)

    #: The commit the gates actually ran against. Everything the evidence trail claims is claimed
    #: about this sha, so it is stored rather than looked up later — the default branch moves.
    base_sha: Mapped[str | None] = mapped_column(String(64), default=None)
    #: The commit production was running, when it is known (item 039). Different question from the
    #: one above, and conflating them is what makes a fixed-upstream bug look unreproducible.
    production_ref: Mapped[str | None] = mapped_column(String(200), default=None)

    branch: Mapped[str | None] = mapped_column(String(200), default=None)
    pull_request_ref: Mapped[str | None] = mapped_column(String(100), default=None)
    #: The commit the merge produced, and when. Written by the recurrence watch (M9) after asking
    #: the forge, never by publishing — Hullwork does not merge, so it cannot know at publish time
    #: and must not guess. `None` means either "not merged" or "not asked yet", which
    #: `merge_checked_at` on the item tells apart.
    #:
    #: **This is what makes "does the fix hold?" answerable.** Without the commit there is no way
    #: to distinguish an error returning from a release that carries the fix — a genuine
    #: regression — from one arriving from a release that predates it, which says nothing about
    #: the fix and is the same confusion item 039 fixed from the other direction.
    merge_commit: Mapped[str | None] = mapped_column(String(64), default=None)
    merged_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), default=None)
    #: The sandbox image the gates ran in. A reproduction against different dependency versions
    #: than production is not wrong, but it is the first thing to suspect when one will not repeat.
    image_tag: Mapped[str | None] = mapped_column(String(200), default=None)

    #: The provenance seal (DR-0002 §4), read off the wire rather than copied from configuration.
    seal: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    error: Mapped[str | None] = mapped_column(Text, default=None)

    steps: Mapped[list["AttemptStep"]] = relationship(
        back_populates="attempt", cascade="all, delete-orphan", order_by="AttemptStep.ordinal"
    )


class AttemptStep(Base):
    """One command the dispatcher ran, and what it printed.

    This is the evidence a reviewer actually reads: "this test failed at commit X and passes at
    commit Y" is two rows of this table. Output is bounded, and when it is cut the row says so —
    a truncation nobody is told about turns evidence into a suggestion.
    """

    __tablename__ = "attempt_steps"
    __table_args__ = (UniqueConstraint("attempt_id", "ordinal", name="uq_attempt_step"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    attempt_id: Mapped[int] = mapped_column(ForeignKey("attempts.id"), index=True)

    #: Position in the run. The phase is not enough: a phase can run more than one command.
    ordinal: Mapped[int] = mapped_column(Integer)
    phase: Mapped[AttemptPhase] = mapped_column(_enum(AttemptPhase, "step_phase"))

    command: Mapped[str] = mapped_column(Text)
    exit_code: Mapped[int | None] = mapped_column(Integer, default=None)
    duration_ms: Mapped[int | None] = mapped_column(Integer, default=None)

    output: Mapped[str] = mapped_column(Text, default="")
    #: True when `output` is not all of it. Said out loud so nobody reads a cut log as a whole one.
    output_truncated: Mapped[bool] = mapped_column(Boolean, default=False)

    #: What Hullwork added to this command's environment, as a JSON object. Item 106, part 6.
    #:
    #: `{}` is a real answer and means *nothing was added* — true of every gate, and the fact worth
    #: seeing beside a phase where it is not. Item 099 was exactly that asymmetry: the gates ran
    #: clean and the agent's phases carried five variables inside the namespace the watched project
    #: validates, which broke the project's own suite. Nothing in the trail could show it.
    #:
    #: `None` means *not recorded*, which is every row written before this column existed. Values
    #: are scrubbed by name through the rule the logger uses, so a variable somebody adds later
    #: called `…_TOKEN` cannot arrive here in the clear.
    environment: Mapped[str | None] = mapped_column(Text, default=None)

    started_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)

    attempt: Mapped[Attempt] = relationship(back_populates="steps")


class PageAccess(Base):
    """The one credential that reads. Item 122. One row, id 1, or none at all.

    **None at all is the default and it means the page does not exist.** The receiver is the half
    of Hullwork that has to be reachable by an error tracker — with hosted GlitchTip that means a
    public address — so a read-only view of every item, attempt and captured output must not appear
    there because somebody upgraded.

    The hash, never the token: it is printed once by `hullwork page-token` and stored the way the
    webhook secret is, for the same reason and with the same helpers. Rotating is overwriting this
    row, which is why there is exactly one.
    """

    __tablename__ = "page_access"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    #: SHA-256, compared in constant time. See `security.hash_token` for why a KDF buys nothing
    #: against 32 random bytes.
    token_hash: Mapped[str] = mapped_column(String(64))

    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)


class OperatorKey(Base):
    """The credential that **acts**. Item 166. One row, id 1, or none at all.

    **Separate from `PageAccess` on purpose, and that separation is the whole security model.** The
    page token is a bearer credential that lives in a URL — a saved page, a screenshot of the
    address bar, a link mailed to a colleague — so it reads everything and may never spend money.
    This one never appears in a URL: it is pasted into a form once, exchanged for a session, and
    after that only the session cookie travels.

    **None at all is the default, and it means the buttons do not exist.** An instance that upgrades
    into this item is byte-identical to the one before it until somebody runs
    `hullwork operator-key`.

    Generated, never chosen. 32 random bytes hashed with SHA-256, for the reason already written
    beside the page token: against 32 random bytes a KDF buys nothing. A human-chosen password would
    need scrypt or argon2, a new dependency, and a guessing-rate story — three problems this does
    not have.
    """

    __tablename__ = "operator_key"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    #: SHA-256, compared in constant time. See `security.hash_token`.
    key_hash: Mapped[str] = mapped_column(String(64))

    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)


class OperatorSession(Base):
    """One browser that has proved it holds the operator key. Item 166.

    **Rows rather than a signed cookie, so that revoking is deleting.** A signed cookie cannot be
    withdrawn without rotating the signing key, which logs out everything at once and gives the
    operator no way to end one session — and the moment a laptop is lost, "everything at once" is
    the only option anybody has. Deleting a row is the whole of it, and
    `hullwork operator-key --rotate` deletes them all.

    The token is hashed like every other credential here. The **CSRF token is not**: it is not a
    credential, it is a value the server hands out and expects back on the same session, and it is
    compared in constant time for tidiness rather than for secrecy.
    """

    __tablename__ = "operator_session"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    #: SHA-256 of the value in the cookie.
    token_hash: Mapped[str] = mapped_column(String(64), index=True)

    #: Handed to the browser, returned in a hidden field, and never in a URL.
    csrf: Mapped[str] = mapped_column(String(64))

    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)

    #: When this stops being accepted. An absolute expiry rather than an idle timeout: an idle
    #: timeout has to be written on every request, which turns a read of the page into a write to
    #: the database — and the receiver's sweep already contends for that lock.
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime())


class DispatcherLease(Base):
    """Who is dispatching, and when they last said so. One row, id 1. Item 075, DR-0009.

    A **lease**, not a lock: it expires on its own. A lock has to be released to be correct, and a
    process that is killed releases nothing — so a lock would need a supervisor to clean up after
    it, which is the dependency DR-0009 exists to remove.

    One row rather than one per run, because the question is never "who has dispatched" — the
    attempts table answers that, with evidence. The question is "who is dispatching *now*", which
    has exactly one answer or none.
    """

    __tablename__ = "dispatcher_lease"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    #: Identifies a run. Opaque and self-chosen, never derived from the host or the user — it is
    #: written to the database and to logs, and a lease is no place to disclose who runs Hullwork.
    holder: Mapped[str] = mapped_column(String(64))

    acquired_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    #: Renewed every turn of the loop, which makes this the heartbeat as well. Deliberately the same
    #: field: a separate heartbeat could disagree with the lock about who is running, and then
    #: neither is trustworthy.
    renewed_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)

    #: Whether this dispatcher's own errors reach the tracker. Item 110, written at start-up.
    #:
    #: Here because this row is the **only** thing the two programs share. `/ready` can answer the
    #: same question for the receiver by asking itself; a process that listens on nothing cannot be
    #: asked, so the answer has to be left somewhere on the way past.
    #:
    #: Three states, not two. `None` is *"not recorded"* — a lease taken by a build older than the
    #: column — and it must not read as `off`, which is the defect item 105 was closed for.
    error_reporting: Mapped[bool | None] = mapped_column(Boolean, default=None)


class Installation(Base):
    """A name this deployment can be counted by. One row, id 1. Item 151.

    **Random, and generated here.** Not the hostname, not a MAC address, not a hash of either: a
    hash of a hostname is still the hostname to anybody holding a list of hostnames to try. Sixteen
    random bytes are a name that means nothing anywhere except beside the other events carrying it.

    **What it buys, and it is the only thing it buys.** Forty crashes from one installation and one
    crash from forty installations are the same forty events without it, and those two situations
    call for opposite work. Nothing else upstream is allowed to identify anybody, which is what
    makes this the field that has to be honest about being an identifier.

    Written on first use rather than at migration time, so a deployment that never reports anything
    never acquires one — and `hullwork init` is not the moment somebody is asked to accept being
    counted.
    """

    __tablename__ = "installation"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    #: 32 hexadecimal characters from `secrets.token_hex(16)`. Stored, never derived, never rotated:
    #: rotating would double-count one installation, which is the one measurement this exists for.
    identifier: Mapped[str] = mapped_column(String(32))

    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
