"""The read side of the error tracker: what the webhook could never tell us.

Constitution §3 — core sees this protocol and never a provider. The same rule that keeps the forge
swappable keeps the tracker swappable, and here it earns its keep twice over, because the *only*
lawful place to parse provider-shaped JSON is behind this boundary.

**Why this exists at all.** An audit on 2026-07-27 measured what Hullwork knew about a real
production error: 437 bytes. A title GlitchTip truncates at 100 characters, a colour, a permalink
and three Slack fields, with `culprit` null in every real delivery. No stack trace, no file, no
line, no local variable — not because the code dropped them but because the outbound webhook never
carried them. DR-0003 requires the agent to write a test that reproduces the bug before it may
attempt a fix, and nobody can do that from a truncated sentence. M2 would have run correctly and
returned `not-reproducible` for almost everything.

The data was there the whole time, one call away, behind a scope we were not using.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable


class TrackerError(Exception):
    """Something went wrong talking to the error tracker."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class RetryableTrackerError(TrackerError):
    """Worth trying again: a 5xx, a timeout, a rate limit.

    Kept distinct for the same reason the forge draws this line (DR-0003): an item gets one
    attempt, and "the tracker was briefly down" must never be allowed to spend it.
    """


class PermanentTrackerError(TrackerError):
    """Trying again will not help: bad credentials, a malformed reference, a deleted issue."""


@dataclass(frozen=True)
class Frame:
    """One stack frame, which is the unit an agent actually needs to locate a bug.

    `context_line` plus its neighbours matters as much as the line number: a reproduction is
    written against what the code *says*, and a line number alone sends the agent to whatever now
    happens to sit at that offset.
    """

    filename: str | None = None
    abs_path: str | None = None
    module: str | None = None
    function: str | None = None
    lineno: int | None = None
    context_line: str | None = None
    #: Source either side of the failing line, in order, as `(lineno, text)`.
    context: tuple[tuple[int, str], ...] = ()
    #: Local variables, **already scrubbed**. `None` means the SDK did not send any, which is a
    #: different fact from "it sent an empty scope" and the agent should be able to tell them apart.
    variables: Mapping[str, Any] | None = None

    @property
    def location(self) -> str:
        """A one-line human reference, for the evidence trail and the prompt."""
        where = self.abs_path or self.filename or self.module or "<unknown>"
        line = f":{self.lineno}" if self.lineno is not None else ""
        func = f" in {self.function}" if self.function else ""
        return f"{where}{line}{func}"


@dataclass(frozen=True)
class FetchedEvent:
    """One full sample of an error, as the tracker recorded it.

    Everything here is scrubbed before it is constructed. A fetched event is the most sensitive
    object this system handles — it carries frame locals, `sys.argv` and request data out of
    somebody else's process — and the audit found a **live DSN** inside `sys.argv` on one of our
    own real events, plus Hullwork's own webhook token in the locals of another. Scrubbing on the
    way in, rather than on the way out, is the difference between a leak that is contained and a
    leak that is stored.
    """

    provider_event_id: str
    exception_type: str | None = None
    #: The full message. The webhook's copy is truncated at 100 characters by the provider, and
    #: for a `KeyError` or a `ValueError` the truncated half is often the reproducing input.
    message: str | None = None
    culprit: str | None = None
    handled: bool | None = None
    level: str | None = None
    #: Innermost frame last, the order every provider sends and every human reads.
    frames: tuple[Frame, ...] = ()
    #: Dependency versions as the failing process had them — 33 to 71 entries in practice. Worth
    #: more than a version string: it says what the code was actually running against.
    packages: Mapping[str, str] = field(default_factory=dict)
    runtime: str | None = None
    environment: str | None = None
    #: Whatever the SDK called the deployed version. A commit sha if you were disciplined, a
    #: package version if you were not — item 039 is about telling those apart.
    release: str | None = None
    server_name: str | None = None
    occurred_at: datetime | None = None
    #: The provider's own grouping hash, when it exposes one.
    grouping_hashes: tuple[str, ...] = ()
    #: Scrubbed. `sys.argv` arrives here, which is why it is scrubbed.
    extra: Mapping[str, Any] = field(default_factory=dict)

    @property
    def is_useful_for_reproduction(self) -> bool:
        """Whether this carries enough to be worth handing an agent at all.

        A frame with a line number is the floor. Below it we are back to the 437 bytes the audit
        measured, and the honest thing is to say so rather than dispatch and blame the agent.
        """
        return any(f.lineno is not None and (f.abs_path or f.filename) for f in self.frames)


@dataclass(frozen=True)
class TrackerIssue:
    """One row of the tracker's unresolved list. DR-0011, item 080.

    **Not a `FetchedEvent`.** That is one occurrence in full — frames, locals, pinned versions —
    read
    from a detail route to write a reproduction with. This is the tracker's own summary of an issue,
    and it exists so Hullwork can learn that the issue *exists at all*: the outbound webhook fires
    once per issue for the issue's whole life, so anything that predates the installation, or whose
    single notification was lost, is invisible without this list.

    Deliberately flat and small. Everything here is present on the list route of the provider this
    was measured against, and nothing here needs a second request.
    """

    #: The provider's own issue id, as a string. The identity everything else hangs off.
    external_id: str
    title: str
    permalink: str
    #: `unresolved`, `resolved`, `ignored`. Only the first is ever swept, but it is carried so a
    #: caller cannot silently sweep the wrong thing.
    status: str
    level: str | None = None
    #: What the tracker calls the failing location. On the measured provider the list route fills
    #: `metadata.filename` and `metadata.function` where the webhook sent `culprit: null` — which is
    #: why this route improves triage as well as coverage (items 070, 071).
    culprit: str | None = None
    #: How many times the provider has seen it. The webhook never says.
    occurrences: int | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None


@runtime_checkable
class Tracker(Protocol):
    """What the pipeline needs to read about **one** issue it already knows about.

    Two verbs, and enumerating issues is deliberately not one of them — see `TrackerInventory` below
    for why that is a separate protocol rather than a third method here.
    """

    def fetch_latest(self, permalink: str) -> FetchedEvent | None:
        """The most recent sample of the error behind this permalink, or `None` if it is gone.

        Takes the permalink rather than a provider id on purpose: the permalink is what Hullwork
        already stores, and turning it into whatever the provider calls an issue is exactly the
        provider-specific knowledge that belongs on this side of the boundary.
        """
        ...

    def fetch_samples(self, permalink: str, limit: int = 2) -> Sequence[FetchedEvent]:
        """Several occurrences of the same error, newest first.

        The provider stores every occurrence in full, and two samples of one bug are worth more
        than one: what differs between them is usually the input that triggers it. This is also
        the only route to occurrences 2..N, because the tracker notifies once per issue and never
        again — a fact that already forced Hullwork to keep a clock of its own.
        """
        ...

@runtime_checkable
class TrackerInventory(Protocol):
    """"Which issues are there?" — separate from `Tracker`, and separate on purpose.

    Reading one issue in full and enumerating a project's issues are different capabilities, and
    this codebase already narrows a credential to the question asked three times over
    (`PermissionReader`, `RepositoryReader`, `IssueReader`). Two reasons it matters here:

    * **`fetch_context` must not require it.** Enrichment needs `fetch_latest` and nothing else, and
      widening `Tracker` would have made every existing tracker double — and every future adapter —
      owe a method it never uses.
    * **A provider may refuse it.** The list route needs an organisation this instance cannot
      discover: the least-privilege token is refused `/api/0/organizations/` (measured, 403). An
      adapter that can read events and not enumerate them is a legitimate, working `Tracker`.
    """

    def list_unresolved(
        self, project: str, *, since: datetime | None = None, limit: int = 25
    ) -> Sequence[TrackerIssue]:
        """The project's unresolved issues, oldest activity first. DR-0011.

        **`since` is a high-water mark on last activity, not a page cursor**, and that is forced
        rather than chosen: the provider measured for this emits its `Link` header wrapped in Python
        set syntax — a real bug, on every list response — so no RFC 5988 parser can follow it.
        Paging
        by time is what is left, and an implementation must therefore return results ordered so that
        a caller advancing `since` makes progress.

        `limit` bounds one pass. A project with three hundred open issues must not become three
        hundred forge issues in one afternoon, which is DR-0006's adoption failure arriving from the
        other direction.

        Only unresolved. An issue somebody resolved is a decision, and re-ingesting it would make
        Hullwork argue with its user; a closed item that recurs is already handled — `dedup` calls
        that a regression, which is a better answer.
        """
        ...
