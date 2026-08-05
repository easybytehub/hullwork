"""Telling a human what happened, once per run.

The unit is the **digest**, never the event. A tool that sends a message per error trains its user
to mute it, and a muted tool is worse than no tool: it looks like coverage while providing none.

Ordered by what requires action, not by what happened first. Someone skimming this on a phone should
see the thing they have to deal with in the first line, and the volume statistics last — or not at
all, which is usually the honest answer.
"""

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from hullwork.dedup import Outcome, Resolution
from hullwork.models import Item, ItemState, Lane


@dataclass(frozen=True)
class Line:
    """One item, as it appears in a digest."""

    title: str
    lane: Lane
    reason: str | None = None
    issue_ref: str | None = None

    def render(self) -> str:
        where = f" ({self.issue_ref})" if self.issue_ref else ""
        why = f" — {self.reason}" if self.reason else ""
        return f"{self.title}{where}{why}"

    @classmethod
    def of(cls, item: Item) -> "Line":
        return cls(
            title=item.title,
            lane=item.lane,
            reason=item.lane_reason,
            issue_ref=item.forge_issue_ref,
        )


@dataclass(frozen=True)
class Digest:
    """What one run produced, arranged by urgency.

    `deduplicated` is a **count**, never a list. Those occurrences are most of the traffic, and the
    whole point of the product is that they do not demand attention.
    """

    #: Worst news first: something we considered fixed came back.
    regressions: list[Line] = field(default_factory=list)
    #: Red lane, or amber waiting for approval — a person has to decide something.
    needs_decision: list[Line] = field(default_factory=list)
    #: Newly filed, already triaged, nothing to decide right now.
    created: list[Line] = field(default_factory=list)
    deduplicated: int = 0

    @property
    def is_empty(self) -> bool:
        """Nothing worth a message.

        Deduplicated occurrences alone are emptiness: a digest saying "40 repeats, nothing new" is
        the message that teaches people to stop reading digests.
        """
        return not (self.regressions or self.needs_decision or self.created)

    def render(self) -> str:
        parts = []
        if self.regressions:
            parts.append(_section("Came back (regressions)", self.regressions))
        if self.needs_decision:
            parts.append(_section("Waiting on you", self.needs_decision))
        if self.created:
            parts.append(_section("New", self.created))
        if self.deduplicated:
            noun = "occurrence" if self.deduplicated == 1 else "occurrences"
            parts.append(f"({self.deduplicated} repeat {noun} deduplicated, nothing filed)")
        return "\n\n".join(parts)


def _section(heading: str, lines: list[Line]) -> str:
    body = "\n".join(f"  - {line.render()}" for line in lines)
    return f"{heading} ({len(lines)}):\n{body}"


def build_digest(resolutions: list[Resolution]) -> Digest:
    """Fold a run's resolutions into one digest."""
    regressions: list[Line] = []
    needs_decision: list[Line] = []
    created: list[Line] = []
    deduplicated = 0

    for resolution in resolutions:
        item = resolution.item
        if resolution.outcome is Outcome.DEDUPLICATED:
            deduplicated += 1
        elif resolution.outcome is Outcome.REOPENED:
            regressions.append(Line.of(item))
        elif item.lane is Lane.RED or item.state is ItemState.WAITING_APPROVAL:
            needs_decision.append(Line.of(item))
        else:
            created.append(Line.of(item))

    return Digest(
        regressions=regressions,
        needs_decision=needs_decision,
        created=created,
        deduplicated=deduplicated,
    )


@runtime_checkable
class Notifier(Protocol):
    """Where a digest goes. `none` is a supported answer."""

    def send(self, digest: Digest) -> None: ...
